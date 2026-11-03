# Real IRMind with an isolated synthetic case; no network or real user configuration.
Output frames/
Output demo.ascii
Set Shell "bash"
Set FontFamily "Source Code Pro"
Set FontSize 16
Set Width 1230
Set Height 840
Set Padding 0
Set Theme "Catppuccin Mocha"
Set Framerate 6
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
Wait+Screen@90s /Step 1 of 10/
Show
Sleep 2 s
Screenshot "welcome.png"
Sleep 500 ms
Wait+Screen@90s /Step 2 of 10/
Sleep 2 s
Screenshot "case.png"
Sleep 500 ms
Wait+Screen@90s /Step 3 of 10/
Wait+Screen@90s /Evidence ready:/
Sleep 1 s
Screenshot "evidence.png"
Sleep 500 ms
Wait+Screen@90s /Step 4 of 10/
Sleep 7 s
Screenshot "explore.png"
Sleep 500 ms
Wait+Screen@90s /Step 5 of 10/
Sleep 4 s
Screenshot "agent.png"
Sleep 500 ms
Wait+Screen@90s /Step 6 of 10/
Sleep 3 s
Screenshot "approval.png"
Sleep 500 ms
Wait+Screen@90s /Step 7 of 10/
Sleep 3 s
Screenshot "findings.png"
Sleep 500 ms
Wait+Screen@90s /Step 8 of 10/
Wait+Screen@90s /Local comparison/
Sleep 1 s
Screenshot "check.png"
Sleep 500 ms
Wait+Screen@90s /Step 9 of 10/
Wait+Screen@90s /Seal case/
Sleep 2 s
Screenshot "custody.png"
Sleep 500 ms
Wait+Screen@90s /Step 10 of 10/
Sleep 2 s
Screenshot "next.png"
Sleep 4 s
Escape
Wait+Screen@90s /Demo data deleted/
Hide
