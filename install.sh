 #!/usr/bin/env bash

#? Any custom directory changes will not be reflected in this installer, and directories must be created manually
# Create directories in user space
mkdir -p ~/.config/secarch/
mkdir -p ~/.secarch/
mkdir -p ~/Documents/archived-items/
mkdir -p ~/usr/share/secarch/

mv config/config.json ~/.config/secarch/
mv keygen/* usr/share/secarch/

chmod +r /usr/share/secarch/*
