 #!/usr/bin/env bash

#? Any custom directory changes will not be reflected in this installer, and directories must be created manually
# Create directories in user space
mkdir ~/.config/secarch/
mkdir ~/.secarch/
mkdir ~/Documents/archived-items/
mkdir ~/usr/share/secarch/

mv config/config.json ~/.config/secarch/
mv keygen/* usr/share/secarch/

chmod +r usr/share/secarch/*
