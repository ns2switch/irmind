# Guided demo screenshots use the isolated scripted model and synthetic episode.
Output "/out/preview.gif"
Output "/out/preview.ascii"

Set Shell "bash"
Set FontFamily "Source Code Pro"
Set FontSize 16
Set Width 1230
Set Height 660
Set Padding 0
Set Theme "Catppuccin Mocha"
Set Framerate 12
Set TypingSpeed 10 ms
Set CursorBlink false

Env HOME "/tmp/irmind-demo-guide"
Env USER "demo"
Env LOGNAME "demo"
Env HOSTNAME "demo"
Env PS1 "demo$ "
Env TERM "xterm-256color"

Hide
Type "mkdir -p /tmp/irmind-demo-guide && clear && env -i HOME=/tmp/irmind-demo-guide USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color /build/debug/irmind demo --scripted"
Enter
Sleep 8 s
Show
Sleep 700 ms
Screenshot "/out/welcome.png"
Sleep 700 ms

Type "/demo next"
Enter
Sleep 300 ms
Type "/scope"
Enter
Sleep 300 ms
Type "/demo next"
Enter
Sleep 500 ms
Screenshot "/out/evidence.png"
Sleep 700 ms

Type "/demo next"
Enter
Sleep 400 ms
Screenshot "/out/explore.png"
Sleep 700 ms

Type "/demo skip"
Enter
Sleep 200 ms
Type "What happened in this synthetic AWS IAM episode?"
Enter
Sleep 3 s
Type "/demo next"
Enter
Sleep 500 ms
Screenshot "/out/approval.png"
Sleep 700 ms

Type "/approve "
Tab
Enter
Sleep 1 s
Type "/demo next"
Enter
Sleep 500 ms
Type "/confirm "
Tab
Enter
Sleep 500 ms
Type "/demo next"
Enter
Sleep 300 ms
Type "/demo check"
Enter
Sleep 300 ms
Type "/demo next"
Enter
Sleep 300 ms
Type "/verify"
Enter
Sleep 1 s
Screenshot "/out/custody.png"
Sleep 700 ms
