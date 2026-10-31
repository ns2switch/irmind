# The public demo uses a temporary signed case, ephemeral keys and synthetic events.
# The VHS container has no network; no local model is offered in this recording.
Output docs/assets/demo.gif
Output docs/assets/demo.ascii

Set Shell "bash"
Set FontFamily "Source Code Pro"
Set FontSize 16
Set Width 1230
Set Height 660
Set Padding 0
Set Theme "Catppuccin Mocha"
Set Framerate 12
Set TypingSpeed 15 ms
Set CursorBlink false

Env HOME "/tmp/irmind-demo-home"
Env USER "demo"
Env LOGNAME "demo"
Env HOSTNAME "demo"
Env PS1 "demo$ "
Env TERM "xterm-256color"

Hide
Type "mkdir -p /tmp/irmind-demo-home && clear && env -i HOME=/tmp/irmind-demo-home USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color /vhs/target/debug/irmind demo --scripted"
Enter
Sleep 4 s
Show
Sleep 2 s
Type "What happened in this synthetic episode?"
Enter
Sleep 7 s
Type "/approve "
Tab
Enter
Sleep 6 s
Type "/confirm "
Tab
Enter
Sleep 2 s
Type "/demo check"
Enter
Sleep 4 s
Type "/quit"
Enter
Enter
Sleep 1 s
