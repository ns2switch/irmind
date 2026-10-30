# Synthetic, offline home screen and dialog captures.
Output docs/ux/home-refresh/after/preview.gif
Output docs/ux/home-refresh/after/preview.ascii

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

Env HOME "/tmp/irmind-home-refresh"
Env USER "demo"
Env LOGNAME "demo"
Env HOSTNAME "demo"
Env PS1 "demo$ "
Env TERM "xterm-256color"

Hide
Type "mkdir -p /tmp/irmind-home-refresh && clear && env -i HOME=/tmp/irmind-home-refresh USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color /vhs/target/debug/examples/demo"
Enter
Sleep 2 s
Show
Escape
Sleep 1 s
Screenshot docs/ux/home-refresh/after/home.png
Sleep 700 ms
Type "/"
Sleep 700 ms
Screenshot docs/ux/home-refresh/after/command-menu.png
Sleep 700 ms
Escape
Sleep 500 ms
Type "/new"
Enter
Sleep 1 s
Screenshot docs/ux/home-refresh/after/new.png
Sleep 700 ms
Escape
Sleep 500 ms
Type "/modules"
Enter
Sleep 1 s
Screenshot docs/ux/home-refresh/after/modules.png
Sleep 700 ms
Escape
Sleep 500 ms
Type "/keystore"
Enter
Sleep 1 s
Screenshot docs/ux/home-refresh/after/keystore.png
Sleep 700 ms
Escape
Sleep 500 ms
Type "/model"
Enter
Sleep 1 s
Screenshot docs/ux/home-refresh/after/model.png
Sleep 1 s
