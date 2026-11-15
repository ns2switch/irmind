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
Set PlaybackSpeed 1.0
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
Wait+Screen /Resumed · \/home to view all cases/
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
Wait+Screen /Ask about the case/
Sleep 500 ms

Type "/"
Sleep 350 ms
Screenshot docs/assets/command-menu.png
Sleep 700 ms
Type "ing"
Tab
Type " examples/cloudtrail-alert.json"
Enter
Wait+Screen /Ingest: Ingested 1 file/
Sleep 500 ms

Type "What does this synthetic role assumption show?"
Enter
Sleep 1 s
Screenshot docs/assets/conversation.png
Sleep 1 s
Wait+Screen /Approval required/
Screenshot docs/assets/approval-card.png
Sleep 700 ms

Type "/approve "
Tab
Enter
Wait+Screen /approval executed/
Sleep 500 ms
Type "/verify examples"
Enter
Sleep 200 ms
Enter
Wait+Screen /Verified 1 of 1 original sources/
Sleep 500 ms

Type "/help"
Enter
Wait+Screen /Help · PgUp/
Sleep 500 ms
Screenshot docs/assets/help.png
Escape
Sleep 300 ms
Type "/skills"
Enter
Wait+Screen /Forensic skills/
Sleep 500 ms
Screenshot docs/assets/skills.png
Escape
Sleep 300 ms
Type "/subagents"
Enter
Wait+Screen /No delegated tasks/
Sleep 500 ms
Screenshot docs/assets/subagents.png
Escape
Sleep 300 ms

Sleep 2 s
