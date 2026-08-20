from __future__ import annotations

import argparse
import hashlib
import os
import platform
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from forge.connectors.binaries import connector_binary_search_paths

# ---------------------------------------------------------------------------
# Graceful Ctrl+C — first press requests stop, second forces exit
# ---------------------------------------------------------------------------
try:
    from forge.opsec.resilience import _SHUTDOWN as _FORGE_SHUTDOWN

    def _handle_sigint(signum: int, frame: object) -> None:
        if _FORGE_SHUTDOWN.is_set():
            print("\n[FORCE EXIT] Forcing exit now.")
            raise SystemExit(1)
        _FORGE_SHUTDOWN.set()
        print("\n[STOPPING] Finishing current operation... Ctrl+C again to force exit.")

    signal.signal(signal.SIGINT, _handle_sigint)
except Exception:
    pass  # resilience not yet importable during initial setup

RUNTIME_PACKAGES = [
    "questionary==2.1.1",
    "rich==13.9.4",
    "click==8.1.8",
    "typer==0.17.5",
    "pydantic==2.10.4",
    "curl_cffi==0.7.4",
    "jinja2==3.1.4",
    "markupsafe==3.0.2",
    "playwright==1.50.0",
    "playwright-stealth==1.0.6",
    "packaging==24.2",
    "llama-cpp-python==0.3.8",
    "pycryptodome==3.21.0",
    "anyio==4.8.0",
    "dnspython==2.7.0",
    "huggingface-hub==0.28.1",
    "sqlalchemy==2.0.37",
    "ftfy==6.3.1",
    "httpx==0.28.1",
    "boto3==1.37.5",
    "azure-core==1.32.0",
    "azure-identity==1.19.0",
    "azure-mgmt-authorization==4.0.0",
    "azure-mgmt-keyvault==10.3.1",
    "azure-mgmt-resource==23.2.0",
    "azure-mgmt-sql==3.0.1",
    "azure-mgmt-storage==22.1.0",
    "azure-mgmt-web==7.2.0",
    "phonenumbers>=8.13,<9.0",
]

OFFENSIVE_PACKAGES = [
    "impacket==0.12.0",
    "asyncssh==2.18.0",
    "pywinrm==0.4.3",
    "smbprotocol==1.14.0",
    "pyperclip==1.9.0",
    "psutil==6.1.1",
]

ARTIFACT_PACKAGES = [
    "py7zr>=0.21,<1.0",
    "zstandard>=0.23,<1.0",
    "brotli>=1.1,<2.0",
    "lz4>=4.3,<5.0",
]

# External OSINT CLIs installed as Python packages (optional, but recommended).
# Added 2026-07-06: enables Modules 2-E (theHarvester), 2-H (Sherlock /
# Maigret), 2-L (Holehe), and GHunt. These intentionally install into a
# dedicated OSINT tool virtualenv by default because their pins regularly
# conflict with FORGE's runtime dependencies.
OSINT_TOOL_PACKAGE_GROUPS = {
    "sherlock": ["sherlock-project"],  # Module 2-H username scanner
    "maigret": ["maigret"],            # Module 2-H alt username scanner
    "holehe": ["holehe"],              # Module 2-L account-existence per email
    "ghunt": ["ghunt"],                # Module 2-G Google account enrichment
}

CONNECTOR_PYTHON_TOOL_PACKAGES = {
    "detect-secrets": ["detect-secrets"],
}

CONNECTOR_GO_TOOLS = {
    "gitleaks": "github.com/zricethezav/gitleaks/v8@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
}
CONNECTOR_TOOL_INSTALL_TIMEOUT_SECONDS = 600
TRUFFLEHOG_VERSION = "v3.97.0"
TRUFFLEHOG_ASSET_VERSION = TRUFFLEHOG_VERSION.removeprefix("v")
TRUFFLEHOG_RELEASE_BASE = (
    "https://github.com/trufflesecurity/trufflehog/releases/download/"
    f"{TRUFFLEHOG_VERSION}"
)
TRUFFLEHOG_URLS = {
    ("Windows", "AMD64"): (
        f"{TRUFFLEHOG_RELEASE_BASE}/"
        f"trufflehog_{TRUFFLEHOG_ASSET_VERSION}_windows_amd64.tar.gz"
    ),
    ("Windows", "ARM64"): (
        f"{TRUFFLEHOG_RELEASE_BASE}/"
        f"trufflehog_{TRUFFLEHOG_ASSET_VERSION}_windows_arm64.tar.gz"
    ),
    ("Linux", "x86_64"): (
        f"{TRUFFLEHOG_RELEASE_BASE}/"
        f"trufflehog_{TRUFFLEHOG_ASSET_VERSION}_linux_amd64.tar.gz"
    ),
    ("Linux", "aarch64"): (
        f"{TRUFFLEHOG_RELEASE_BASE}/"
        f"trufflehog_{TRUFFLEHOG_ASSET_VERSION}_linux_arm64.tar.gz"
    ),
    ("Darwin", "x86_64"): (
        f"{TRUFFLEHOG_RELEASE_BASE}/"
        f"trufflehog_{TRUFFLEHOG_ASSET_VERSION}_darwin_amd64.tar.gz"
    ),
    ("Darwin", "arm64"): (
        f"{TRUFFLEHOG_RELEASE_BASE}/"
        f"trufflehog_{TRUFFLEHOG_ASSET_VERSION}_darwin_arm64.tar.gz"
    ),
}
TRUFFLEHOG_CHECKSUMS_URL = (
    f"{TRUFFLEHOG_RELEASE_BASE}/"
    f"trufflehog_{TRUFFLEHOG_ASSET_VERSION}_checksums.txt"
)
TRUFFLEHOG_DOWNLOAD_MAX_BYTES = 250 * 1024 * 1024

# Optional external Go binary installed to venv Scripts dir. Enables the
# Google-dork half of Module 2-M (phone OSINT). No API key required.
PHONEINFOGA_VERSION = "v2.11.0"
PHONEINFOGA_URLS = {
    ("Windows", "AMD64"): (
        "https://github.com/sundowndev/phoneinfoga/releases/download/"
        f"{PHONEINFOGA_VERSION}/phoneinfoga_Windows_x86_64.tar.gz"
    ),
    ("Linux", "x86_64"): (
        "https://github.com/sundowndev/phoneinfoga/releases/download/"
        f"{PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz"
    ),
    ("Darwin", "x86_64"): (
        "https://github.com/sundowndev/phoneinfoga/releases/download/"
        f"{PHONEINFOGA_VERSION}/phoneinfoga_Darwin_x86_64.tar.gz"
    ),
    ("Darwin", "arm64"): (
        "https://github.com/sundowndev/phoneinfoga/releases/download/"
        f"{PHONEINFOGA_VERSION}/phoneinfoga_Darwin_arm64.tar.gz"
    ),
}


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"[FORGE Bootstrap] Project root does not exist: {root}")
        return 1

    load_env_file(root / ".env", root)
    requested_mode = getattr(args, "venv_mode", None)
    env_mode = os.environ.get("FORGE_VENV_MODE", "auto")
    venv_mode = normalize_venv_mode(requested_mode if isinstance(requested_mode, str) else env_mode)
    venv_dir = resolve_venv_dir(root, venv_mode=venv_mode)

    if args.command == "print-venv":
        print(venv_dir)
        return 0

    if args.command == "setup":
        return setup_environment(
            root=root, venv_dir=venv_dir, dev=args.dev, check_only=args.check_only
        )

    if args.command == "run":
        return run_forge(root=root, venv_dir=venv_dir, forge_args=args.forge_args)

    if args.command == "run-python":
        return run_python(root=root, venv_dir=venv_dir, python_args=args.python_args)

    print(f"[FORGE Bootstrap] Unsupported command: {args.command}")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bootstrap.py")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent))
    parser.add_argument("--venv-mode", choices=["auto", "project", "local", "temp"], default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup")
    setup_parser.add_argument("--dev", action="store_true")
    setup_parser.add_argument("--check-only", action="store_true")

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("forge_args", nargs=argparse.REMAINDER)

    run_python_parser = subparsers.add_parser("run-python")
    run_python_parser.add_argument("python_args", nargs=argparse.REMAINDER)

    subparsers.add_parser("print-venv")
    return parser


def load_env_file(env_path: Path, root: Path) -> None:
    if not env_path.exists():
        example = root / ".env.example"
        if example.exists():
            print(f"[FORGE Bootstrap] Creating .env from {example.name}")
            import shutil

            shutil.copy2(example, env_path)
        else:
            return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            os.environ.setdefault(key, value)


def resolve_venv_dir(root: Path, venv_mode: str) -> Path:
    forced = os.environ.get("FORGE_VENV_DIR", "").strip()
    if forced:
        return Path(os.path.expandvars(os.path.expanduser(forced))).resolve()
    if venv_mode == "project":
        return (root / ".venv").resolve()
    if venv_mode == "local":
        return default_local_venv_dir()
    if venv_mode == "temp":
        return default_temp_venv_dir()
    if should_use_local_venv(root):
        return default_local_venv_dir()
    return (root / ".venv").resolve()


def normalize_venv_mode(value: str) -> str:
    allowed = {"auto", "project", "local", "temp"}
    if value in allowed:
        return value
    return "auto"


def should_use_local_venv(root: Path) -> bool:
    lower = str(root).lower()
    if sys.platform.startswith("win"):
        return "\\onedrive\\" in lower
    markers = ["onedrive", "dropbox", "icloud drive", "google drive"]
    return any(marker in lower for marker in markers)


def default_local_venv_dir() -> Path:
    if sys.platform.startswith("win"):
        localapp = os.environ.get("LOCALAPPDATA")
        if localapp:
            return (Path(localapp) / "FORGE" / "venv").resolve()
        return (Path.home() / "AppData" / "Local" / "FORGE" / "venv").resolve()
    return (Path.home() / ".local" / "share" / "forge" / "venv").resolve()


def default_temp_venv_dir() -> Path:
    return (Path(tempfile.gettempdir()) / "FORGE" / "venv").resolve()


def _osint_tool_env_key(name: str) -> str:
    return {
        "whatsmyname": "WHATSMYNAME",
        "wmn": "WHATSMYNAME",
        "maigret": "MAIGRET",
        "sherlock": "SHERLOCK",
        "ghunt": "GHUNT",
        "holehe": "HOLEHE",
        "theharvester": "THEHARVESTER",
        "phoneinfoga": "PHONEINFOGA",
    }.get(name.strip().lower(), name.strip().upper())


def default_osint_tools_base_dir() -> Path:
    if sys.platform.startswith("win"):
        localapp = os.environ.get("LOCALAPPDATA")
        if localapp:
            return (Path(localapp) / "FORGE" / "osint-tools").resolve()
        return (Path.home() / "AppData" / "Local" / "FORGE" / "osint-tools").resolve()
    return (Path.home() / ".local" / "share" / "forge" / "osint-tools").resolve()


def resolve_osint_tool_venv_dir(root: Path, tool_name: str) -> Path:
    key = _osint_tool_env_key(tool_name)
    forced = os.environ.get(f"FORGE_{key}_VENV", "").strip()
    if forced:
        return Path(os.path.expandvars(os.path.expanduser(forced))).resolve()
    legacy_shared = os.environ.get("FORGE_OSINT_TOOLS_VENV", "").strip()
    if legacy_shared:
        return Path(os.path.expandvars(os.path.expanduser(legacy_shared))).resolve()
    if should_use_local_venv(root):
        return (default_osint_tools_base_dir() / f"{key.lower()}-venv").resolve()
    return (root / ".venv-osint" / key.lower()).resolve()


def venv_python(venv_dir: Path) -> Path:
    if sys.platform.startswith("win"):
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _editable_install_spec(*, safe_mode: bool, dev: bool) -> str:
    extras = ["artifacts"]
    if not safe_mode:
        extras.append("offensive")
    if dev:
        extras.append("dev")
    return f".[{','.join(extras)}]"


def setup_environment(root: Path, venv_dir: Path, dev: bool, check_only: bool) -> int:
    if check_only:
        ok = verify_install(root=root, venv_dir=venv_dir)
        if ok:
            print("[FORGE Setup] Dependency preflight passed.")
            return 0
        print("[FORGE Setup] Dependencies are not ready. Run setup mode.")
        return 1

    if sys.version_info < (3, 11):
        print("[FORGE Setup] Python 3.11+ is required.")
        return 1

    # Check for requirements file based on mode. Older trees used
    # requirements-*.txt; current editable installs can derive dependencies
    # directly from pyproject.toml plus explicit extras.
    safe_mode = os.environ.get("FORGE_SAFE_MODE", "0").strip() in ("1", "true", "yes")
    req_file = "requirements-safe.txt" if safe_mode else "requirements-full.txt"
    install_from_pyproject = False

    # Fallback to requirements.txt if specific file is missing
    if not (root / req_file).exists():
        if (root / "requirements.txt").exists():
            print(f"[FORGE Setup] {req_file} not found, falling back to requirements.txt")
            req_file = "requirements.txt"
        else:
            print(
                f"[FORGE Setup] {req_file} and requirements.txt are absent; "
                "installing from pyproject.toml extras instead."
            )
            install_from_pyproject = True

    if not (root / "pyproject.toml").exists():
        print(f"[FORGE Setup] Missing pyproject.toml at: {root / 'pyproject.toml'}")
        return 1

    if not venv_python(venv_dir).exists():
        print(f"[FORGE Setup] Creating virtual environment at: {venv_dir}")
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        create = subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], cwd=str(root))
        if create.returncode != 0:
            print("[FORGE Setup] Failed to create virtual environment.")
            return create.returncode

    vpy = venv_python(venv_dir)
    if not vpy.exists():
        print(f"[FORGE Setup] Missing venv python executable at: {vpy}")
        return 1

    print("[FORGE Setup] Upgrading pip tooling...")
    subprocess.run(
        [str(vpy), "-m", "pip", "install", "--upgrade", "setuptools", "wheel"], cwd=str(root)
    )
    subprocess.run([str(vpy), "-m", "pip", "install", "--upgrade", "pip"], cwd=str(root))

    if safe_mode:
        print("[FORGE Setup] FORGE_SAFE_MODE=1 — installing core dependencies only (AV-safe).")
    if install_from_pyproject:
        package_spec = _editable_install_spec(safe_mode=safe_mode, dev=dev)
        print(f"[FORGE Setup] Installing runtime dependencies from pyproject: {package_spec}")
        runtime = subprocess.run(
            [str(vpy), "-m", "pip", "install", "-e", package_spec], cwd=str(root)
        )
    else:
        print(f"[FORGE Setup] Installing runtime dependencies from {req_file}...")
        runtime = subprocess.run(
            [str(vpy), "-m", "pip", "install", "-r", str(root / req_file)], cwd=str(root)
        )
    if runtime.returncode != 0 and sys.platform.startswith("win"):
        print("[FORGE Setup] Runtime install fallback for Windows...")
        pkgs = RUNTIME_PACKAGES + ARTIFACT_PACKAGES
        if not safe_mode:
            pkgs += OFFENSIVE_PACKAGES
        fallback = subprocess.run([str(vpy), "-m", "pip", "install", *pkgs], cwd=str(root))
        runtime = fallback
    if runtime.returncode != 0:
        print("[FORGE Setup] Runtime dependency install failed.")
        return runtime.returncode

    if not safe_mode and sys.platform.startswith("win"):
        print("[FORGE Setup] Installing impacket for Phase 5 features...")
        impacket = subprocess.run(
            [str(vpy), "-m", "pip", "install", "impacket==0.12.0"], cwd=str(root)
        )
        if impacket.returncode != 0:
            print("[FORGE Setup] Warning: impacket install failed. Other phases remain usable.")

    if not safe_mode:
        install_connector_tools(root=root, vpy=vpy)

    # -----------------------------------------------------------------
    # OSINT external CLIs (2-E theHarvester, 2-H Sherlock/Maigret,
    # 2-L Holehe, GHunt). Keep these out of the FORGE runtime venv unless
    # explicitly requested; their transitive pins conflict with core deps.
    # -----------------------------------------------------------------
    if not safe_mode:
        install_osint_in_runtime = os.environ.get(
            "FORGE_INSTALL_OSINT_IN_PROJECT_VENV", ""
        ).strip().lower() in ("1", "true", "yes")

        def _tool_python(tool_name: str) -> tuple[Path, Path]:
            tool_venv = (
                venv_dir
                if install_osint_in_runtime
                else resolve_osint_tool_venv_dir(root, tool_name)
            )
            if not venv_python(tool_venv).exists():
                print(f"[FORGE Setup] Creating {tool_name} tool virtualenv at: {tool_venv}")
                tool_venv.parent.mkdir(parents=True, exist_ok=True)
                create_tool = subprocess.run(
                    [sys.executable, "-m", "venv", str(tool_venv)], cwd=str(root)
                )
                if create_tool.returncode != 0:
                    print(f"[FORGE Setup] Warning: {tool_name} tool virtualenv creation failed.")
            tool_vpy = venv_python(tool_venv) if venv_python(tool_venv).exists() else vpy
            if tool_vpy != vpy:
                subprocess.run(
                    [
                        str(tool_vpy),
                        "-m",
                        "pip",
                        "install",
                        "--upgrade",
                        "pip",
                        "setuptools",
                        "wheel",
                    ],
                    cwd=str(root),
                )
                print(f"[FORGE Setup] {tool_name} will install into: {tool_venv}")
            else:
                print(
                    f"[FORGE Setup] {tool_name} will install into the FORGE runtime venv "
                    "(FORGE_INSTALL_OSINT_IN_PROJECT_VENV enabled or tool venv unavailable)."
                )
            return tool_venv, tool_vpy

        for tool_name, packages in OSINT_TOOL_PACKAGE_GROUPS.items():
            _, tool_vpy = _tool_python(tool_name)
            print(f"[FORGE Setup] Installing {tool_name} OSINT package(s): {', '.join(packages)}")
            tool_run = subprocess.run(
                [str(tool_vpy), "-m", "pip", "install", "--no-cache-dir", *packages],
                cwd=str(root),
            )
            if tool_run.returncode != 0:
                print(
                    f"[FORGE Setup] Warning: {tool_name} install partial-fail. "
                    "The Phase 2 module that needs it will report the miss at runtime."
                )

        # theHarvester (from git — the PyPI package is a placeholder).
        _, theharvester_vpy = _tool_python("theharvester")
        print("[FORGE Setup] Installing theHarvester from git...")
        th_run = subprocess.run(
            [str(theharvester_vpy), "-m", "pip", "install", "--no-cache-dir",
             "git+https://github.com/laramies/theHarvester.git@master"],
            cwd=str(root),
        )
        if th_run.returncode != 0:
            print("[FORGE Setup] Warning: theHarvester git install failed. "
                  "Module 2-E will report the miss at runtime.")

        # PhoneInfoga - Go binary for Module 2-M (phone OSINT).
        # Downloads the precompiled release into its tool venv Scripts/bin dir.
        phoneinfoga_venv, _ = _tool_python("phoneinfoga")
        print("[FORGE Setup] Installing PhoneInfoga "
              f"{PHONEINFOGA_VERSION} binary...")
        import platform as _plat
        import tarfile
        import tempfile
        import urllib.request as _url
        sys_key = (_plat.system(), _plat.machine())
        # Normalise machine name variants
        if sys_key[1] in ("AMD64", "x86_64"):
            candidates = [(sys_key[0], "AMD64"), (sys_key[0], "x86_64")]
        else:
            candidates = [sys_key]
        pi_url = None
        for k in candidates:
            if k in PHONEINFOGA_URLS:
                pi_url = PHONEINFOGA_URLS[k]
                break
        if pi_url is None:
            print(f"[FORGE Setup] Warning: no PhoneInfoga binary for "
                  f"{_plat.system()}/{_plat.machine()}. Skipping (2-M "
                  "still works with the phonenumbers-only path).")
        else:
            scripts_dir = phoneinfoga_venv / ("Scripts" if os.name == "nt" else "bin")
            scripts_dir.mkdir(parents=True, exist_ok=True)
            target_exe = scripts_dir / (
                "phoneinfoga.exe" if os.name == "nt" else "phoneinfoga"
            )
            if target_exe.exists():
                print(f"[FORGE Setup] PhoneInfoga already present at {target_exe}")
            else:
                try:
                    with tempfile.NamedTemporaryFile(
                        suffix=".tar.gz", delete=False
                    ) as tmp:
                        tarball = Path(tmp.name)
                    _url.urlretrieve(pi_url, tarball)
                    with tarfile.open(tarball, "r:gz") as tf:
                        for member in tf.getmembers():
                            if member.name.startswith(
                                "phoneinfoga"
                            ) and (member.name.endswith(".exe")
                                   or "/" not in member.name):
                                extracted = tf.extractfile(member)
                                if extracted:
                                    target_exe.write_bytes(extracted.read())
                                    if os.name != "nt":
                                        target_exe.chmod(0o755)
                                    break
                    tarball.unlink(missing_ok=True)
                    if target_exe.exists():
                        print(f"[FORGE Setup] PhoneInfoga installed at "
                              f"{target_exe}")
                    else:
                        print("[FORGE Setup] Warning: PhoneInfoga tarball "
                              "extraction did not produce the binary. "
                              "Module 2-M falls back to phonenumbers-only.")
                except Exception as exc:
                    print(f"[FORGE Setup] Warning: PhoneInfoga download "
                          f"failed ({exc}). Module 2-M falls back to "
                          "phonenumbers-only.")

    # -----------------------------------------------------------------
    # Playwright chromium (required by Phase 0 KB fetchers for LOTS/LOLBAS)
    # -----------------------------------------------------------------
    print("[FORGE Setup] Ensuring Playwright chromium (~87 MB one-time)...")
    pw_run = subprocess.run(
        [str(vpy), "-m", "playwright", "install", "chromium"],
        cwd=str(root),
    )
    if pw_run.returncode != 0:
        print("[FORGE Setup] Warning: Playwright chromium install failed. "
              "'forge kb sync' will attempt an auto-install on first run.")

    if dev and not install_from_pyproject:
        print("[FORGE Setup] Installing development dependencies...")
        if (root / "requirements-full.txt").exists():
            dev_run = subprocess.run(
                [str(vpy), "-m", "pip", "install", "-r", "requirements-full.txt"], cwd=str(root)
            )
        else:
            dev_run = subprocess.run(
                [str(vpy), "-m", "pip", "install", "-e", _editable_install_spec(safe_mode=safe_mode, dev=True)],
                cwd=str(root),
            )
        if dev_run.returncode != 0:
            print("[FORGE Setup] Dev dependency install failed.")
            return dev_run.returncode

    if not install_from_pyproject:
        print("[FORGE Setup] Installing FORGE package...")
        install_pkg = subprocess.run([str(vpy), "-m", "pip", "install", "-e", "."], cwd=str(root))
        if install_pkg.returncode != 0:
            print("[FORGE Setup] Editable install failed.")
            return install_pkg.returncode

    if not verify_install(root=root, venv_dir=venv_dir):
        print("[FORGE Setup] Install verification failed.")
        return 1

    print("[FORGE Setup] Downloading essential wordlists...")
    wordlist_script = root / "scripts" / "setup_wordlists.py"
    if wordlist_script.exists():
        w_run = subprocess.run([str(vpy), str(wordlist_script)], cwd=str(root))
        if w_run.returncode != 0:
            print("[FORGE Setup] Warning: Wordlist setup failed or partially failed.")
    else:
        print(f"[FORGE Setup] Wordlist setup script not found at {wordlist_script}, skipping.")

    print("[FORGE Setup] Setup complete.")
    return 0


def install_connector_tools(root: Path, vpy: Path) -> None:
    """Best-effort install of free/local connector CLIs for full setup mode."""

    if os.environ.get("FORGE_SKIP_CONNECTOR_TOOL_INSTALL", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        print("[FORGE Setup] Skipping connector tool install by FORGE_SKIP_CONNECTOR_TOOL_INSTALL.")
        return

    print("[FORGE Setup] Ensuring free/local connector tools...")
    timeout_seconds = connector_tool_install_timeout_seconds()
    for binary, packages in CONNECTOR_PYTHON_TOOL_PACKAGES.items():
        if resolve_setup_binary(binary, root=root, vpy=vpy):
            print(f"[FORGE Setup] {binary} already available.")
            continue
        try:
            run = subprocess.run(
                [str(vpy), "-m", "pip", "install", "--upgrade", *packages],
                cwd=str(root),
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            print(
                f"[FORGE Setup] Warning: {binary} install exceeded "
                f"{timeout_seconds}s and was stopped."
            )
            continue
        if run.returncode != 0:
            print(
                f"[FORGE Setup] Warning: {binary} install failed. "
                "`forge connectors install-plan --json` will show manual guidance."
            )
        elif resolve_setup_binary(binary, root=root, vpy=vpy):
            print(f"[FORGE Setup] {binary} installed.")
        else:
            print(
                f"[FORGE Setup] Warning: {binary} installed but was not found in "
                "FORGE connector search paths."
            )

    go_exe = shutil.which("go")
    if not go_exe:
        missing = ", ".join(
            binary
            for binary in CONNECTOR_GO_TOOLS
            if not resolve_setup_binary(binary, root=root, vpy=vpy)
        )
        if missing:
            print(
                "[FORGE Setup] Warning: Go is not on PATH; cannot install connector "
                f"Go tools now: {missing}."
            )
        install_trufflehog_release(root=root, vpy=vpy, timeout_seconds=timeout_seconds)
        return

    for binary, package in CONNECTOR_GO_TOOLS.items():
        if resolve_setup_binary(binary, root=root, vpy=vpy):
            print(f"[FORGE Setup] {binary} already available.")
            continue
        try:
            run = subprocess.run(
                [go_exe, "install", package],
                cwd=str(root),
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            print(
                f"[FORGE Setup] Warning: {binary} go install exceeded "
                f"{timeout_seconds}s and was stopped."
            )
            continue
        if run.returncode != 0:
            print(
                f"[FORGE Setup] Warning: {binary} go install failed. "
                "`forge connectors install-plan --json` will show manual guidance."
            )
        elif resolve_setup_binary(binary, root=root, vpy=vpy):
            print(f"[FORGE Setup] {binary} installed.")
        else:
            print(
                f"[FORGE Setup] Warning: {binary} installed but was not found in "
                "FORGE connector search paths."
            )

    install_trufflehog_release(root=root, vpy=vpy, timeout_seconds=timeout_seconds)


def install_trufflehog_release(root: Path, vpy: Path, timeout_seconds: int) -> None:
    """Best-effort install of the TruffleHog release binary into FORGE tools."""

    if resolve_setup_binary("trufflehog", root=root, vpy=vpy):
        print("[FORGE Setup] trufflehog already available.")
        return
    url = trufflehog_release_url()
    if not url:
        print(
            "[FORGE Setup] Warning: no TruffleHog release binary for "
            f"{platform.system()}/{platform.machine()}; install-plan will show guidance."
        )
        return
    target_dir = Path(connector_binary_search_paths()[0])
    target_dir.mkdir(parents=True, exist_ok=True)
    target_exe = target_dir / ("trufflehog.exe" if os.name == "nt" else "trufflehog")
    print(f"[FORGE Setup] Installing TruffleHog {TRUFFLEHOG_VERSION} binary...")
    try:
        archive_bytes = _download_url_bytes(url, timeout_seconds=timeout_seconds)
        expected_sha = _trufflehog_expected_sha256(url, timeout_seconds=timeout_seconds)
        actual_sha = hashlib.sha256(archive_bytes).hexdigest()
        if expected_sha and actual_sha.lower() != expected_sha.lower():
            print(
                "[FORGE Setup] Warning: TruffleHog checksum mismatch; "
                "download discarded."
            )
            return
        _extract_trufflehog_archive(archive_bytes, target_exe)
    except Exception as exc:  # noqa: BLE001 - setup is best-effort.
        print(
            "[FORGE Setup] Warning: TruffleHog release install failed "
            f"({exc}). `forge connectors install-plan --json` will show guidance."
        )
        return
    if target_exe.exists():
        if os.name != "nt":
            target_exe.chmod(0o755)
        print(f"[FORGE Setup] TruffleHog installed at {target_exe}")
    else:
        print(
            "[FORGE Setup] Warning: TruffleHog archive extraction did not "
            "produce the binary."
        )


def trufflehog_release_url() -> str | None:
    sys_key = (platform.system(), platform.machine())
    machine_aliases = {
        "AMD64": ("AMD64", "x86_64"),
        "x86_64": ("x86_64", "AMD64"),
        "arm64": ("arm64", "ARM64", "aarch64"),
        "ARM64": ("ARM64", "arm64", "aarch64"),
        "aarch64": ("aarch64", "arm64", "ARM64"),
    }
    for machine in machine_aliases.get(sys_key[1], (sys_key[1],)):
        url = TRUFFLEHOG_URLS.get((sys_key[0], machine))
        if url:
            return url
    return None


def _trufflehog_expected_sha256(url: str, *, timeout_seconds: int) -> str | None:
    checksum_text = _download_url_bytes(
        TRUFFLEHOG_CHECKSUMS_URL,
        timeout_seconds=timeout_seconds,
        max_bytes=1024 * 1024,
    ).decode("utf-8", errors="replace")
    archive_name = url.rsplit("/", 1)[-1]
    for raw_line in checksum_text.splitlines():
        parts = raw_line.strip().split()
        if len(parts) >= 2 and parts[-1] == archive_name:
            return parts[0]
    return None


def _download_url_bytes(
    url: str,
    *,
    timeout_seconds: int,
    max_bytes: int = TRUFFLEHOG_DOWNLOAD_MAX_BYTES,
) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(f"download exceeded {max_bytes} byte cap")
            chunks.append(chunk)
    return b"".join(chunks)


def _extract_trufflehog_archive(archive_bytes: bytes, target_exe: Path) -> None:
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        archive_path = Path(tmp.name)
        tmp.write(archive_bytes)
    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                member_name = Path(member.name).name.lower()
                if member.isfile() and member_name in {"trufflehog", "trufflehog.exe"}:
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        continue
                    target_exe.write_bytes(extracted.read())
                    return
    finally:
        archive_path.unlink(missing_ok=True)
    raise RuntimeError("trufflehog binary not found in release archive")


def setup_binary_search_paths(root: Path, vpy: Path) -> list[str]:
    scripts_dir = vpy.parent
    scripts = "Scripts" if os.name == "nt" else "bin"
    paths = [
        str(scripts_dir),
        str(root / ".venv" / scripts),
        str(root / ".venv-osint" / "connectors" / scripts),
        *connector_binary_search_paths(),
    ]
    seen: set[str] = set()
    unique: list[str] = []
    for path in paths:
        key = path.lower() if os.name == "nt" else path
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def connector_tool_install_timeout_seconds() -> int:
    raw = os.environ.get("FORGE_CONNECTOR_TOOL_INSTALL_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return CONNECTOR_TOOL_INSTALL_TIMEOUT_SECONDS
    try:
        parsed = int(raw)
    except ValueError:
        return CONNECTOR_TOOL_INSTALL_TIMEOUT_SECONDS
    return max(30, min(parsed, 1800))


def resolve_setup_binary(binary: str, *, root: Path, vpy: Path) -> str | None:
    found = shutil.which(binary)
    if found:
        return found
    extra = os.pathsep.join(setup_binary_search_paths(root, vpy))
    return shutil.which(binary, path=extra) if extra else None


def verify_install(root: Path, venv_dir: Path) -> bool:
    vpy = venv_python(venv_dir)
    if not vpy.exists():
        return False

    # Check for critical runtime imports (must all be present).
    critical_imports = [
        "click",
        "questionary",
        "pydantic",
        "rich",
        "typer",
        "jinja2",
        "anyio",
        "sqlalchemy",
        "httpx",
        "Crypto",
    ]

    # Optional offensive imports — warn on miss but do not fail. Operators
    # can still run Phase 0/1/2/4/6 without these.
    optional_imports: dict[str, str] = {
        "phonenumbers": "phonenumbers",
        "dns.resolver": "dnspython",
        "py7zr": "py7zr",
        "zstandard": "zstandard",
        "brotli": "brotli",
        "lz4.frame": "lz4",
    }
    safe_mode = os.environ.get("FORGE_SAFE_MODE", "0").strip() in ("1", "true", "yes")
    if not safe_mode:
        optional_imports.update(
            {
                "asyncssh": "asyncssh",
                "pyperclip": "pyperclip",
                "psutil": "psutil",
                "impacket": "impacket",
            }
        )

    import_cmd = f"import {', '.join(critical_imports)}"

    imports = subprocess.run(
        [
            str(vpy),
            "-c",
            import_cmd,
        ],
        cwd=str(root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if imports.returncode != 0:
        return False

    # Optional imports — probe individually so a single miss just warns.
    if optional_imports:
        missing_optional: list[str] = []
        missing_packages: list[str] = []
        for mod, package_name in optional_imports.items():
            r = subprocess.run(
                [str(vpy), "-c", f"import {mod}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if r.returncode != 0:
                missing_optional.append(mod)
                if package_name not in missing_packages:
                    missing_packages.append(package_name)
        if missing_optional:
            print(
                f"[FORGE Setup] Warning: optional modules missing: "
                f"{', '.join(missing_optional)}. Credential validation or "
                f"artifact extraction may be limited. Install with: "
                f"pip install {' '.join(missing_packages)}"
            )

    cli = subprocess.run(
        [str(vpy), "-m", "forge.cli", "--help"],
        cwd=str(root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ok = cli.returncode == 0
    if not ok:
        # Fallback 1: try the installed console script (added by editable install).
        forge_bin = venv_dir / ("Scripts" if sys.platform.startswith("win") else "bin")
        forge_exe = forge_bin / ("forge.exe" if sys.platform.startswith("win") else "forge")
        if forge_exe.exists():
            cli2 = subprocess.run(
                [str(forge_exe), "--version"],
                cwd=str(root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ok = cli2.returncode == 0
    if not ok:
        # Fallback 2: check the module imports cleanly at all.
        cli3 = subprocess.run(
            [str(vpy), "-c", "import forge.cli"],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ok = cli3.returncode == 0

    # LLM-provider detection summary — no failures raised, just informational
    # so the operator knows which cascade slots will fire in --provider auto.
    if ok:
        _report_provider_detection(vpy)
    return ok


def _report_provider_detection(vpy: Path) -> None:
    """Print which cloud LLM providers are detected on this machine.

    Non-fatal — only informational. The auto cascade (Phase 6 report
    generation) selects among these in priority order and falls through
    to the local Qwen model or a template-only report if nothing here.
    """
    import shutil

    print("\n[FORGE Setup] LLM provider detection (used by --provider auto):")
    lines: list[tuple[str, bool, str]] = [
        ("kiro_cli",          bool(shutil.which("kiro-cli")),
                              "your Kiro CLI subscription (recommended default)"),
        ("claude_code",       bool(shutil.which("claude") or shutil.which("claude.cmd")),
                              "Claude Code subscription"),
        ("codex_cli",         bool(shutil.which("codex") or shutil.which("codex.cmd")),
                              "OpenAI Codex CLI"),
        ("gemini_cli",        bool(shutil.which("gemini") or shutil.which("gemini.cmd")),
                              "Google Gemini CLI"),
        ("openai_compatible", bool(os.environ.get("FORGE_OPENAI_BASE_URL")
                                   and os.environ.get("FORGE_OPENAI_MODEL")),
                              "requires FORGE_OPENAI_BASE_URL + MODEL in .env"),
        ("bedrock_anthropic", bool(os.environ.get("AWS_PROFILE")
                                   or os.environ.get("AWS_REGION")),
                              "requires AWS creds"),
    ]
    for name, present, note in lines:
        marker = "OK" if present else "--"
        print(f"    [{marker}] {name:20s} {note}")

    # Local llama_cpp check
    try:
        check = subprocess.run(
            [str(vpy), "-c",
             "from forge.phase6.report_synthesizer import DEFAULT_MODEL_DIR, MODEL_FILENAME; "
             "from pathlib import Path; import sys; "
             "sys.exit(0 if (DEFAULT_MODEL_DIR / MODEL_FILENAME).exists() else 1)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        local_ok = check.returncode == 0
    except Exception:
        local_ok = False
    print(f"    [{'OK' if local_ok else '--'}] {'llama_cpp':20s} "
          f"local Qwen 2.5-1.5B GGUF (~1 GB one-time download if missing)")
    print(f"    [OK] {'template':20s} "
          f"deterministic factual report (LLM-free; always available)")
    print("[FORGE Setup] Set FORGE_LLM_PROVIDER=auto in .env to use the "
          "cascade automatically.\n")


def ensure_runtime(root: Path, venv_dir: Path) -> int:
    if verify_install(root=root, venv_dir=venv_dir):
        return 0
    print("[FORGE Bootstrap] Environment missing or incomplete, running setup...")
    return setup_environment(root=root, venv_dir=venv_dir, dev=False, check_only=False)


def normalize_remainder(values: list[str]) -> list[str]:
    if values and values[0] == "--":
        return values[1:]
    return values


def run_forge(root: Path, venv_dir: Path, forge_args: list[str]) -> int:
    normalized = normalize_remainder(forge_args)
    if not normalized:
        print("[FORGE Bootstrap] No forge command provided.")
        return 2
    setup_code = ensure_runtime(root=root, venv_dir=venv_dir)
    if setup_code != 0:
        return setup_code
    vpy = venv_python(venv_dir)
    cmd = [str(vpy), "-m", "forge.cli", *normalized]
    run = subprocess.run(cmd, cwd=str(root))
    return run.returncode


def run_python(root: Path, venv_dir: Path, python_args: list[str]) -> int:
    normalized = normalize_remainder(python_args)
    if not normalized:
        print("[FORGE Bootstrap] No python arguments provided.")
        return 2
    setup_code = ensure_runtime(root=root, venv_dir=venv_dir)
    if setup_code != 0:
        return setup_code
    vpy = venv_python(venv_dir)
    cmd = [str(vpy), *normalized]
    run = subprocess.run(cmd, cwd=str(root))
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
