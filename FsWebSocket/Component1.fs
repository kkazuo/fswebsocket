namespace FsWebSocket

open System

module WebSocket =
    let statusCode line =
        let regex = new Text.RegularExpressions.Regex(@"^(?:HTTP.1.1 +)([0-9]{3})(?: )")
        let m = regex.Match line
        if m.Success
        then m.Groups.[1].Value |> Int32.Parse
        else FormatException "HTTP Status Code Not Found" |> raise

    let decomposeHttpHeaders lines =
        let sts = Seq.head lines |> statusCode
        let toKV (line : string) =
            match line.IndexOf(':') with
            | -1 -> FormatException line |> raise
            | n  ->
                let k = line.Substring(0, n).ToLower()
                let v = line.Substring(n + 1, line.Length - (n + 1)).Trim()
                k, v
        let kvs =
            lines
            |> Seq.tail
            |> Seq.map toKV
            |> Map.ofSeq
        sts, kvs

    let validateHttpHeaders nonce (sts, headers : Map<string,string>) =
        if sts = 101
        then match (Map.tryFind "connection" headers,
                    Map.tryFind "upgrade" headers,
                    Map.tryFind "sec-websocket-accept" headers) with
             | Some c, Some u, Some a
                when c.ToLower() = "upgrade"
                  && u.ToLower() = "websocket"
                  && a = nonce
                 -> headers
             | _,_,_ -> FormatException "HTTP Headers" |> raise
        else FormatException "HTTP Status" |> raise

    let validateHeaderProtocols protocols (headers : Map<string,string>) =
        match Map.tryFind "sec-websocket-protocol" headers with
        | None -> None
        | Some x -> 
            if Seq.contains x protocols
            then Some x
            else FormatException "Sec-WebSocket-Protocol" |> raise

    let internal readHttpHeader (s : IO.Stream) =
        let mutable cr = 0
        let rec loop a =
            match s.ReadByte() with
            | -1 -> raise (FormatException "")
            | n  -> cr <- match cr, n with
                          | 0, 13 -> 1
                          | 1, 10 -> 2
                          | 2, 13 -> 3
                          | 3, 10 -> 4
                          | _,  _ -> 0
                    if cr = 4
                    then Array.take (Array.length a - 3) a
                    else Array.append a [| byte n |]
                         |> loop
        loop [||]
        |> Text.Encoding.UTF8.GetString
        |> (fun s -> s.Split([|"\r\n"|], StringSplitOptions.None))

    let internal handshake (uri : Uri) protocols extensions nonce =
        let values key vals =
            match (String.concat "," vals).Trim() with
            | "" -> None
            | xs -> Some <| key + xs
        [| Some <| sprintf "GET %s HTTP/1.1" uri.PathAndQuery;
           Some <| sprintf "Host: %s" uri.Host;
           Some <| "Connection: Upgrade";
           Some <| "Upgrade: websocket";
           Some <| "Sec-WebSocket-Version: 13";
           Some <| sprintf "Sec-WebSocket-Key: %s" nonce;
           values "Sec-WebSocket-Protocol: " protocols;
           values "Sec-WebSocket-Extensions: " extensions;
           Some <| "";
           Some <| "" |]
        |> Seq.choose id
        |> String.concat "\r\n"
        |> Text.Encoding.UTF8.GetBytes

    let genNonce numberOfBytes =
        use rng = Security.Cryptography.RNGCryptoServiceProvider.Create()
        let bytes = Array.zeroCreate numberOfBytes
        rng.GetBytes(bytes)
        Convert.ToBase64String(bytes)

    let hashedNonce nonce =
        use sha1 = new Security.Cryptography.SHA1Managed()
        nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        |> Text.Encoding.UTF8.GetBytes
        |> sha1.ComputeHash
        |> Convert.ToBase64String

    let readNumber (s : IO.Stream) len = async {
        let buf = Array.zeroCreate 8
        let! n = s.ReadAsync(buf, 0, len) |> Async.AwaitTask
        return match n with
               | 2 -> (uint64 buf.[0] <<< 8) + uint64 buf.[1]
               | 8 -> (uint64 buf.[0] <<< 8 * 7) +
                      (uint64 buf.[1] <<< 8 * 6) +
                      (uint64 buf.[2] <<< 8 * 5) +
                      (uint64 buf.[3] <<< 8 * 4) +
                      (uint64 buf.[4] <<< 8 * 3) +
                      (uint64 buf.[5] <<< 8 * 2) +
                      (uint64 buf.[6] <<< 8) +
                      (uint64 buf.[7])
               | _ -> FormatException "EOF" |> raise }

    let readWsPayload (s : IO.Stream) len = async {
        let buf = Array.zeroCreate len
        let! n = s.ReadAsync(buf, 0, len) |> Async.AwaitTask
        if n <> len then FormatException "EOF" |> raise
        return buf }

    let readWsHeader (s : IO.Stream) = async {
        let buf = Array.zeroCreate 8
        let! n = s.ReadAsync(buf, 0, 2) |> Async.AwaitTask
        if n <> 2 then FormatException "EOF" |> raise
        let fin    = (buf.[0] &&& 0b10000000uy) <> 0uy
        let op     = (buf.[0] &&& 0b00001111uy) |> int
        let masked = (buf.[1] &&& 0b10000000uy) <> 0uy
        let! len   =
            match  (buf.[1] &&& 0b01111111uy) |> int with
            | 126 -> readNumber s 2
            | 127 -> readNumber s 8
            | x   -> async { return uint64 x }
        return (fin, op, len) }

    let pongWs (s : IO.Stream) mask = async {
        let bytes = [| 0x8Auy; 0x80uy |]
        do! s.WriteAsync(bytes, 0, 2) |> Async.AwaitTask
        do! s.WriteAsync(mask, 0, 4) |> Async.AwaitTask
        do! s.FlushAsync() |> Async.AwaitTask }

    let closeWs (s : IO.Stream) mask = async {
        let bytes = [| 0x88uy; 0x80uy |]
        do! s.WriteAsync(bytes, 0, 2) |> Async.AwaitTask
        do! s.WriteAsync(mask, 0, 4) |> Async.AwaitTask
        do! s.FlushAsync() |> Async.AwaitTask }

    let masking (mask : byte[]) (xs : byte[]) =
        for i = 0 to xs.Length - 1 do
            xs.[i] <- xs.[i] ^^^ mask.[i % 4]
        xs

    let bytesOfLength (n : uint64) =
        if n < 126UL then
            let bytes = Array.zeroCreate 1
            bytes.[0] <- byte n ||| 0x80uy
            bytes
        else if n < 0x10000UL then
            let bytes = Array.zeroCreate 3
            bytes.[0] <- 126uy ||| 0x80uy
            bytes.[1] <- byte ((n &&& 0xFF00UL) >>> 8)
            bytes.[2] <- byte ((n &&& 0x00FFUL))
            bytes
        else
            let bytes = Array.zeroCreate 9
            bytes.[0] <- 127uy ||| 0x80uy
            bytes.[1] <- byte ((n &&& 0xFF00000000000000UL) >>> 8 * 7)
            bytes.[2] <- byte ((n &&& 0x00FF000000000000UL) >>> 8 * 6)
            bytes.[3] <- byte ((n &&& 0x0000FF0000000000UL) >>> 8 * 5)
            bytes.[4] <- byte ((n &&& 0x000000FF00000000UL) >>> 8 * 4)
            bytes.[5] <- byte ((n &&& 0x00000000FF000000UL) >>> 8 * 3)
            bytes.[6] <- byte ((n &&& 0x0000000000FF0000UL) >>> 8 * 2)
            bytes.[7] <- byte ((n &&& 0x000000000000FF00UL) >>> 8)
            bytes.[8] <- byte ((n &&& 0x00000000000000FFUL))
            bytes

    let sendWs (s : IO.Stream) head mask (bytes : byte[]) = async {
        let len = uint64 bytes.LongLength
        let blen = bytesOfLength len
        do! s.WriteAsync(head, 0, 1) |> Async.AwaitTask
        do! s.WriteAsync(blen, 0, blen.Length) |> Async.AwaitTask
        do! s.WriteAsync(mask, 0, mask.Length) |> Async.AwaitTask
        do! s.WriteAsync(bytes, 0, bytes.Length) |> Async.AwaitTask
        do! s.FlushAsync() |> Async.AwaitTask }
    
    let textWs s mask txt =
        Text.Encoding.UTF8.GetBytes(txt : string)
        |> masking mask
        |> sendWs s [| 0x81uy |] mask

    let binaryWs s mask bytes =
        bytes
        |> Array.copy
        |> masking mask
        |> sendWs s [| 0x82uy |] mask

    type Message =
        | Text of string
        | Binary of byte[]
        | Close

    type Msg =
        | Data of Message
        | Pong
        | Quit

    let outputLoop (s : IO.Stream) (canceller : Threading.CancellationTokenSource) =
        MailboxProcessor.Start <| fun inbox ->
            use random = Security.Cryptography.RNGCryptoServiceProvider.Create()
            let genMask () =
                let bytes = Array.zeroCreate 4
                random.GetBytes(bytes)
                bytes
            let rec loop () = async {
                let! msg = inbox.Receive()
                match msg with
                | Data (Text txt) ->
                    do! textWs s (genMask ()) txt
                    return! loop ()
                | Data (Binary bin) ->
                    do! binaryWs s (genMask ()) bin
                    return! loop ()
                | Data Close ->
                    do! closeWs s (genMask ())
                    canceller.Cancel()
                    return ()
                | Pong ->
                    do! pongWs s (genMask ())
                    return! loop ()
                | Quit ->
                    return () }
            loop ()

    let inputLoop (s : IO.Stream) (onMsg : (Message -> unit) -> Message -> Async<unit>)
            (output : MailboxProcessor<Msg>) =
        let ws msg = output.Post(Data msg)
        let rec loop () = async {
            //use! cancelHandler = Async.OnCancel(fun () -> printfn "Canceling operation.")
            let! (fin, op, llen) = readWsHeader s
            if uint64 Int32.MaxValue < llen then FormatException "too large payload" |> raise
            let len = int llen
            let! payload = if 0 < len then readWsPayload s len else async { return [||] }
            match op with
            | 1 ->
                let msg = Text.Encoding.UTF8.GetString(payload)
                do! onMsg ws <| Text msg
            | 2 ->
                do! onMsg ws <| Binary payload
            | 8 ->
                printfn "server close"
            | 9 ->
                output.Post(Pong)
                output.Post(Data (Text "hello"))
            | _ ->
                ()
            return! loop () }
        loop ()

    let makeSession name onMessage onOpen = async {
        let uri = new Uri(name)
        use net = new Net.Sockets.TcpClient()
        do! net.ConnectAsync(uri.Host, uri.Port) |> Async.AwaitTask
        use! ios =
            match uri.Scheme with
            | "https" | "wss" -> async {
                let ssl = new Net.Security.SslStream(net.GetStream())
                do! ssl.AuthenticateAsClientAsync(uri.Host) |> Async.AwaitTask
                return ssl :> IO.Stream }
            | _ -> async {
                return net.GetStream() :> IO.Stream }
        let nonce = genNonce 16
        let protocols = ["chat"; "superchat"]
        let extesions = ["test"]
        let hello = handshake uri protocols extesions nonce
        do! ios.WriteAsync(hello, 0, hello.Length) |> Async.AwaitTask
        do! ios.FlushAsync() |> Async.AwaitTask
        let h =
            ios
            |> readHttpHeader
            |> decomposeHttpHeaders
            |> validateHttpHeaders (hashedNonce nonce)
            |> validateHeaderProtocols protocols
        //printfn "hd=%A" h

        use canceller = new Threading.CancellationTokenSource()
        let token = canceller.Token
        let output = outputLoop ios canceller
        let input =
            inputLoop ios onMessage output
        let start =
            onOpen(fun msg -> output.Post(Data msg))
        Async.Start(input, token)
        Async.RunSynchronously(start, Threading.Timeout.Infinite, token)
        //Async.Start(start, canceller.Token)
        //output.Post(Data Close)
        return () }

    let connect name onMessage onOpen = async {
        try
            do! makeSession name onMessage onOpen
        with
        | _ -> printfn "canceled"; () }
