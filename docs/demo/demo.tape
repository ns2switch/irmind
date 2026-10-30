# Offline synthetic walkthrough. The demo process creates an ephemeral signed
# case, file keystore and fake model. No provider or network is used.
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
Type "mkdir -p /tmp/irmind-demo-home && clear && env -i HOME=/tmp/irmind-demo-home USER=demo LOGNAME=demo HOSTNAME=demo PATH=/usr/local/bin:/usr/bin:/bin TERM=xterm-256color /vhs/target/debug/examples/demo --resume"
Enter
Sleep 6 s
Show
Screenshot docs/assets/resumed.png
Sleep 700 ms

Type "/home"
Enter
Sleep 500 ms
Screenshot docs/assets/home.png
Sleep 700 ms
Type "/settings"
Enter
Sleep 500 ms
Screenshot docs/assets/settings.png
Sleep 300 ms
Enter
Sleep 500 ms
Screenshot docs/assets/model.png
Sleep 700 ms
Escape
Sleep 300 ms
Down
Enter
Sleep 500 ms
Up
Sleep 250 ms
Screenshot docs/assets/modules.png
Sleep 700 ms
Escape
Sleep 300 ms
Down
Enter
Sleep 500 ms
Screenshot docs/assets/keystore.png
Sleep 300 ms
Escape
Down
Enter
Sleep 500 ms
Screenshot docs/assets/preferences.png
Sleep 300 ms
Escape
Escape
Sleep 300 ms
Type "/new"
Enter
Sleep 500 ms
Screenshot docs/assets/new.png
Sleep 700 ms
Type "Demo CloudTrail alert"
Enter
Sleep 1200 ms

Type "/"
Sleep 350 ms
Screenshot docs/assets/command-menu.png
Sleep 700 ms
Type "ing"
Tab
Type " examples/cloudtrail-alert.json"
Enter
Sleep 1400 ms

Type "What does this synthetic role assumption show?"
Enter
Sleep 1 s
Screenshot docs/assets/conversation.png
Sleep 1 s
Sleep 1700 ms
Screenshot docs/assets/approval-card.png
Sleep 700 ms

Type "/approve "
Tab
Enter
Sleep 2 s
Type "/ver"
Tab
Enter
Sleep 2200 ms
