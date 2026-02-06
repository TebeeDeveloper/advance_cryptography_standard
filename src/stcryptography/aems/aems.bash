#!/bin/bash

# 1. Cai dat colorama
if ! python3 -c "import colorama" &> /dev/null; then
    pip3 install colorama
fi

# 2. Tao Shortcut (.desktop file)
DESKTOP_FILE="$HOME/Desktop/aems.desktop"
if [ ! -f "$DESKTOP_FILE" ]; then
    echo "[!] Dang tao Shortcut tren Linux Desktop..."
    cat <<EOF > "$DESKTOP_FILE"
[Desktop Entry]
Version=1.0
Type=Application
Name=AEMS Terminal
Comment=Advanced Encryption Matrix System
Exec=gnome-terminal -- bash -c "cd $(pwd) && ./aems.bash; exec bash"
Icon=utilities-terminal
Terminal=true
Categories=Development;Security;
EOF
    chmod +x "$DESKTOP_FILE"
    # Neu dung Ubuntu, can tin tuong file nay
    gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null
    echo "[+] Da tao Shortcut xong rui do!"
fi

# 3. Chay Terminal
clear
python3 terminal.py