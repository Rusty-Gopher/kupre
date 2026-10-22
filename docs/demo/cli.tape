# Scripted mode: the CI story. Render from the repo root with:
#   vhs docs/demo/cli.tape
# Same prereqs as tui.tape.

Output docs/demo/cli.gif

Set Shell bash
Set FontSize 15
Set Width 1200
Set Height 800
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

Hide
Type "cd /tmp/demo && rm -f report.json && export PATH=/tmp/demo/bin:$PATH KUBECONFIG=/tmp/demo/kubeconfig PS1='$ ' && clear"
Enter
Show

# 1. A machine-readable verdict and a meaningful exit code
Type "kupre check --target-version 1.37.0 -o json > report.json; echo exit=$?"
Sleep 300ms
Enter
Sleep 4s
Type "jq '{verdict, exitCode, blocking: .summary.blocking, warnings: .summary.warnings}' report.json"
Sleep 300ms
Enter
Sleep 3s

# 2. Accept today's warnings; from now on, only new problems fail CI
Type "clear; kupre check --target-version 1.37.0 -q --baseline report.json"
Sleep 300ms
Enter
Sleep 9s
