// Learn more about F# at http://fsharp.net. See the 'F# Tutorial' project
// for more guidance on F# programming.

#load "Component1.fs"
open FsWebSocket

let () =
    WebSocket.connect
      //"https://google.com"
      //"https://letsencrypt.org"
      "ws://echo.websocket.org"
      (fun ws msg -> async {
        printfn "message %A" msg
        if msg = WebSocket.Text "quit" then
            ws WebSocket.Close
        return () })
      (fun ws ->
           let rec loop () = async {
               //use! cancelHandler = Async.OnCancel(fun () -> printfn "User Canceling operation."; stdin.Close())
               let! line = stdin.ReadLineAsync() |> Async.AwaitTask
               ws <| WebSocket.Text line
               return! loop () }
           loop ())
    |> Async.Ignore
    |> Async.RunSynchronously