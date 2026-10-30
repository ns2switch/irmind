# Offline synthetic fixture. The default product build includes all modules;
# this fixture intentionally lists two illustrative module statuses.
Output docs/ux/recent-case-and-forms/after/forms.gif
Output docs/ux/recent-case-and-forms/after/forms.ascii

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

Env HOME "/tmp/irmind-recent-forms"
Env USER "demo"
Env LOGNAME "demo"
Env HOSTNAME "demo"
Env PS1 "demo$ "
Env TERM "xterm-256color"

Hide
Type "mkdir -p /tmp/irmind-recent-forms && clear && env -i HOME=/tmp/irmind-recent-forms USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color /vhs/target/debug/examples/demo"
Enter
Sleep 2 s
Show
Escape
Sleep 500 ms
Type "/new"
Enter
Sleep 700 ms
Screenshot docs/ux/recent-case-and-forms/after/new.png
Sleep 2 s
Tab
Tab
Enter
Sleep 700 ms
Screenshot docs/ux/recent-case-and-forms/after/remote.png
Sleep 2 s
Escape
Escape
Sleep 300 ms
Type "/modules"
Enter
Sleep 700 ms
Screenshot docs/ux/recent-case-and-forms/after/modules.png
Sleep 2 s
Escape
Sleep 300 ms
Type "/config"
Enter
Sleep 700 ms
Screenshot docs/ux/recent-case-and-forms/after/config.png
Sleep 1 s
