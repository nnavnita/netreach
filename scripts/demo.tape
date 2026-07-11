# vhs tape — record a demo GIF of netreach.
#
# Install vhs: https://github.com/charmbracelet/vhs
# Then run: vhs scripts/demo.tape
#
# Output: docs/demo.gif

Output docs/demo.gif

Set FontSize 14
Set Width 1000
Set Height 640
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Type "make build"
Enter
Sleep 3s

Type "./netreach analyze --config testdata/simple.yaml --src eni-web --dst 1.1.1.1 --port 443 --protocol tcp"
Enter
Sleep 3s

Type "./netreach analyze --config testdata/simple.yaml --src eni-web --dst eni-app --port 22 --protocol tcp"
Enter
Sleep 4s

Type "./netreach analyze --config testdata/multi_vpc.yaml --src eni-web --dst eni-db --port 5432 --protocol tcp"
Enter
Sleep 4s
