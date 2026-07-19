#!/usr/bin/env bash
# script to download and setup essential wordlists (Rockyou, SecLists subsets)

set -e

DATA_DIR="data/wordlists"
mkdir -p "$DATA_DIR"

echo "[*] Setting up essential wordlists in $DATA_DIR..."

# 1. Rockyou (using the SecLists repo source for reliability)
ROCKYOU_PATH="$DATA_DIR/rockyou.txt"
if [ ! -f "$ROCKYOU_PATH" ]; then
    echo "[*] Downloading rockyou.txt..."
    curl -L -o "$ROCKYOU_PATH" "https://github.com/brannondorsey/PassDicts/raw/master/rockyou.txt.tar.bz2" || true
    if [ -f "$ROCKYOU_PATH" ] && file "$ROCKYOU_PATH" | grep -q "bzip2"; then
        echo "[*] Extracting rockyou.txt..."
        tar -xjf "$ROCKYOU_PATH" -C "$DATA_DIR"
        rm "$ROCKYOU_PATH"
    else
        # fallback
        curl -L -o "$ROCKYOU_PATH" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz" || true
        if file "$ROCKYOU_PATH" | grep -q "gzip"; then
            tar -xzf "$ROCKYOU_PATH" -C "$DATA_DIR"
            rm "$ROCKYOU_PATH"
        fi
    fi
    echo "[+] rockyou.txt ready."
else
    echo "[+] rockyou.txt already exists."
fi

# 2. SecLists (Subsets only to save space)
SECLISTS_DIR="$DATA_DIR/seclists"
mkdir -p "$SECLISTS_DIR"

# Common usernames
USERNAMES_PATH="$SECLISTS_DIR/usernames.txt"
if [ ! -f "$USERNAMES_PATH" ]; then
    echo "[*] Downloading common usernames..."
    curl -L -o "$USERNAMES_PATH" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt"
    echo "[+] Usernames list ready."
fi

# Common directory/file fuzzing
WEB_DIR_PATH="$SECLISTS_DIR/common_web_dirs.txt"
if [ ! -f "$WEB_DIR_PATH" ]; then
    echo "[*] Downloading common web directories..."
    curl -L -o "$WEB_DIR_PATH" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    echo "[+] Web directories list ready."
fi

echo "[*] Wordlist setup complete."
