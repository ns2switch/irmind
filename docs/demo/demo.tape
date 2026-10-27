# IRMind synthetic, offline walkthrough. Run from the repository root.
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
Type "mkdir -p /tmp/irmind-demo-home && clear && env -i HOME=/tmp/irmind-demo-home USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color /vhs/target/debug/examples/demo"
Enter
Sleep 2 s
Show

Sleep 1 s
Type "n"
Sleep 400 ms
Type "Demo CloudTrail alert"
Enter
Sleep 1 s

Type "/"
Sleep 500 ms
Screenshot docs/assets/command-menu.png
Sleep 300 ms
Type "ing"
Tab
Type " examples/cloudtrail-alert.json"
Enter
Sleep 2 s

Type "What does this synthetic role assumption show?"
Enter
Sleep 1500 ms
Screenshot docs/assets/conversation.png
Sleep 4 s
Screenshot docs/assets/approval-card.png
Sleep 300 ms

Type "/approve "
Tab
Enter
Sleep 3 s
Type "/ver"
Tab
Enter
Sleep 3 s
Sleep 5 s
