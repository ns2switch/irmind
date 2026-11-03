# Real IRMind with an isolated synthetic case; no network or real user configuration.
Output preview.ascii
Set Shell "bash"
Set FontFamily "Source Code Pro"
Set FontSize 16
Set Width 1230
Set Height 840
Set Padding 0
Set Theme "Catppuccin Mocha"
Set Framerate 8
Set CursorBlink false
Env HOME "/tmp/irmind-demo-home"
Env USER "demo"
Env LOGNAME "demo"
Env HOSTNAME "demo"
Env PS1 "demo$ "
Env TERM "xterm-256color"
Hide
Type "mkdir -p /tmp/irmind-demo-home /tmp/irmind-demo-data && stty cols 120 rows 40 && clear && env -i HOME=/tmp/irmind-demo-home USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color TMPDIR=/tmp/irmind-demo-data /app/irmind demo --scripted"
Enter
Sleep 3 s
Show
Sleep 500 ms
Screenshot "01-welcome.png"
Sleep 500 ms
Enter
Sleep 2 s
Screenshot "02-case.png"
Sleep 500 ms
Enter
Sleep 3 s
Screenshot "03-evidence.png"
Sleep 500 ms
Escape
Sleep 500 ms
