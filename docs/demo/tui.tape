# Interactive mode. Render from the repo root with: vhs docs/demo/tui.tape
# Prereqs: docs/demo/fixtures.yaml applied to a kind cluster whose kubeconfig
# is /tmp/demo/kubeconfig (context renamed to "demo"), kupre in /tmp/demo/bin.

Output docs/demo/tui.gif

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 70ms

Hide
Type "cd /tmp/demo && export PATH=/tmp/demo/bin:$PATH KUBECONFIG=/tmp/demo/kubeconfig PS1='$ ' && clear"
Enter
Show

Type "kupre"
Sleep 400ms
Enter
Sleep 2.5s

# Intro -> missions: upgrade preflight is first
Enter
Sleep 1.5s
Enter
Sleep 1.2s

# Kubeconfig picker -> the demo cluster
Enter
Sleep 1.2s

# Target version
Type "1.37.0"
Sleep 600ms
Enter
Sleep 6s

# Walk the worklist
Down
Sleep 700ms
Down
Sleep 700ms
Up
Sleep 500ms
Up
Sleep 500ms

# Open the blocker: affected resources, fix, exact command
Enter
Sleep 4.5s
Down
Sleep 3.5s
Escape
Sleep 1.5s

# Passing checks, each with what it verified
Type "p"
Sleep 2.5s
Type "q"
Sleep 500ms
