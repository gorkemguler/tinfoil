# tinfoil — hero recording for the README.
#
#   brew install vhs          # or: go install github.com/charmbracelet/vhs@latest
#   vhs assets/demo.tape      # run from the repository root, not from assets/
#
# Sizing is deliberate. The report is 48 lines at these flags and never exceeds
# 97 columns, so the terminal below holds it with no wrapping and no scrolling —
# if it scrolls, the score at the top is lost, which is the whole point of the
# image. After changing the flags, re-check with:
#
#   python3 tinfoil.py --demo --quiet --no-fix | wc -l
#   python3 tinfoil.py --demo --quiet --no-fix | awk '{ print length }' | sort -rn | head -1
#
# Terminal area here: (940 - 2*16 margin - 2*20 padding) = 828px wide  -> ~106 cols
#                     (1000 - 32 - 34 bar - 40 padding)  = 894px tall  -> ~57 lines

Output assets/demo.gif

Require python3

Set Shell "bash"
Set Theme "Dracula"
Set FontSize 13
Set LineHeight 1.2
Set Width 940
Set Height 1000
Set Padding 20
Set Margin 16
Set MarginFill "#181a24"
Set BorderRadius 10
Set WindowBar Colorful
Set WindowBarSize 34
Set Framerate 30
Set TypingSpeed 55ms
Set LoopOffset 45%

# Start recording on a clean screen with a bare prompt.
Hide
Type "export PS1='❯ ' && clear"
Enter
Sleep 600ms
Show

Sleep 700ms
Type "python3 tinfoil.py --demo --quiet --no-fix"
Sleep 500ms
Enter

# The report arrives in a single flush, so the hold is the whole performance.
# Long enough to read the score, scan the findings, and notice the last line.
Sleep 9s
