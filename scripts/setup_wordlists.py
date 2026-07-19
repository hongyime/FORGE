import os
import sys
import tarfile
import urllib.request
from pathlib import Path


def download_file(url: str, dest: Path) -> bool:
    print(f"[*] Downloading {url} ...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            with open(dest, 'wb') as out_file:
                out_file.write(response.read())
        return True
    except Exception as e:
        print(f"[!] Failed to download {url}: {e}")
        return False


def main() -> int:
    # Identify root directory
    script_dir = Path(__file__).resolve().parent
    root = script_dir.parent
    data_dir = root / "data" / "wordlists"
    seclists_dir = data_dir / "seclists"

    data_dir.mkdir(parents=True, exist_ok=True)
    seclists_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Setting up essential wordlists in {data_dir}...")

    # 1. Rockyou
    rockyou_txt = data_dir / "rockyou.txt"
    if not rockyou_txt.exists():
        archive_path = data_dir / "rockyou.txt.tar.bz2"
        # Primary source
        if download_file("https://github.com/brannondorsey/PassDicts/raw/master/rockyou.txt.tar.bz2", archive_path):
            print("[*] Extracting rockyou.txt...")
            try:
                with tarfile.open(archive_path, "r:bz2") as tar:
                    tar.extractall(path=data_dir)
                if archive_path.exists():
                    archive_path.unlink()
                print("[+] rockyou.txt ready.")
            except Exception as e:
                print(f"[!] Extraction failed: {e}")
                # Try fallback source
                archive_path2 = data_dir / "rockyou.txt.tar.gz"
                if download_file("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz", archive_path2):
                    print("[*] Extracting (fallback)...")
                    try:
                        with tarfile.open(archive_path2, "r:gz") as tar2:
                            tar2.extractall(path=data_dir)
                        if archive_path2.exists():
                            archive_path2.unlink()
                        print("[+] rockyou.txt ready.")
                    except Exception as e2:
                        print(f"[!] Fallback extraction failed: {e2}")
    else:
        print("[+] rockyou.txt already exists.")

    # 2. SecLists (Subsets)
    usernames_path = seclists_dir / "usernames.txt"
    if not usernames_path.exists():
        if download_file("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt", usernames_path):
            print("[+] Usernames list ready.")

    common_web_path = seclists_dir / "common_web_dirs.txt"
    if not common_web_path.exists():
        if download_file("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", common_web_path):
            print("[+] Web directories list ready.")

    print("[*] Wordlist setup complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
