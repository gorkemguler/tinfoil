# tinfoil — the CI story: JSON out, exit code in.
#
#   vhs assets/ci.tape        # run from the repository root
#
# Terminal area: (900 - 32 - 40) = 828px wide -> ~98 cols
#                (520 - 32 - 34 - 40) = 414px tall -> ~24 lines
# The widest typed line is 80 characters, and the output is 19 lines.

Output assets/ci.gif

Require python3

Set Shell "bash"
Set Theme "Dracula"
Set FontSize 14
Set LineHeight 1.2
Set Width 900
Set Height 470
Set Padding 20
Set Framerate 30
Set TypingSpeed 45ms
Set LoopOffset 40%

Hide
Type "PS1='$ '"
Enter
Type "clear"
Enter
Sleep 400ms
Show

Sleep 600ms
Type "python3 tinfoil.py --demo --json > report.json"
Enter
Sleep 1500ms

Type "head -16 report.json"
Enter
Sleep 3500ms

# The part that matters for a pipeline: the threshold sets the exit code.
Type 'python3 tinfoil.py --demo --json --fail-under 85 > /dev/null; echo "gate: exit $?"'
Sleep 400ms
Enter
Sleep 4s

Hide
Type "rm -f report.json"
Enter
