# Offline synthetic case; the signing key and case are ephemeral.
Output docs/ux/recent-case-and-forms/after/resumed.gif
Output docs/ux/recent-case-and-forms/after/resumed.ascii

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

Env HOME "/tmp/irmind-recent-resumed"
Env USER "demo"
Env LOGNAME "demo"
Env HOSTNAME "demo"
Env PS1 "demo$ "
Env TERM "xterm-256color"

Hide
Type "mkdir -p /tmp/irmind-recent-resumed && clear && env -i HOME=/tmp/irmind-recent-resumed USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color /vhs/target/debug/examples/demo --resume"
Enter
Sleep 7 s
Show
Sleep 700 ms
Screenshot docs/ux/recent-case-and-forms/after/case.png
Sleep 1 s
