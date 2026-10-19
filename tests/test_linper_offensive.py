"""FORGE v2 policy tests for formerly offensive Linper entry points."""

import pytest
from forge.governance.rules import PolicyViolation
from forge.hardening.linper_offensive import (
    PersistenceMethod,
    PersistenceDoor,
    ReverseShellConfig,
    generate_reverse_shell_command,
    install_cron_persistence,
    install_systemd_persistence,
    install_bashrc_persistence,
    install_sudo_hijack,
    install_steamth_mode_overrides,
    install_web_server_poison,
    uninstall_persistence,
    enum_defenses,
    linper_install,
)


class TestReverseShellGeneration:
    """Test reverse shell command generation."""

    def test_bash_reverse_shell(self):
        """Test Bash reverse shell generation."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            generate_reverse_shell_command(PersistenceMethod.BASH, "10.10.14.5", 4444)

    def test_python_reverse_shell(self):
        """Test Python reverse shell generation."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            generate_reverse_shell_command(PersistenceMethod.PYTHON, "10.10.14.5", 4444)

    def test_stealth_mode_decimal_ip(self):
        """Test IPv4 decimal conversion for stealth."""
        config = ReverseShellConfig(
            rhost="192.168.1.1", rport=4444, stealth_mode=True, dry_run=True
        )
        # 192.168.1.1 = 3232235777
        assert config.rhost_decimal == 3232235777

    def test_stealth_mode_command(self):
        """Test stealth mode uses decimal in command."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            generate_reverse_shell_command(
                PersistenceMethod.BASH, "192.168.1.1", 4444, stealth_mode=True
            )


class TestPersistenceInstallation:
    """Test persistence installation (dry-run mode)."""

    def test_live_persistence_config_is_rejected(self):
        """Live persistence cannot be enabled through configuration."""
        with pytest.raises(ValueError, match="Live persistence operations are disabled"):
            ReverseShellConfig(
                rhost="10.10.14.5",
                rport=4444,
                dry_run=False,
            )

    def test_cron_persistence_dry_run(self):
        """Test cron persistence installation in dry-run."""
        config = ReverseShellConfig(rhost="10.10.14.5", rport=4444, dry_run=True)
        with pytest.raises(PolicyViolation, match="prohibits"):
            install_cron_persistence(config, PersistenceMethod.BASH)

    def test_systemd_persistence_dry_run(self):
        """Test systemd persistence installation in dry-run."""
        config = ReverseShellConfig(rhost="10.10.14.5", rport=4444, dry_run=True)
        with pytest.raises(PolicyViolation, match="prohibits"):
            install_systemd_persistence(config, PersistenceMethod.BASH)

    def test_bashrc_persistence_dry_run(self):
        """Test bashrc persistence installation in dry-run."""
        config = ReverseShellConfig(rhost="10.10.14.5", rport=4444, dry_run=True)
        with pytest.raises(PolicyViolation, match="prohibits"):
            install_bashrc_persistence(config, PersistenceMethod.BASH)


class TestSudoHijack:
    """Test sudo hijack attack."""

    def test_sudo_hijack_dry_run(self):
        """Test sudo hijack in dry-run mode."""
        config = ReverseShellConfig(rhost="10.10.14.5", rport=4444, dry_run=True)
        with pytest.raises(PolicyViolation, match="prohibits"):
            install_sudo_hijack(config, dry_run=True)


class TestStealthMode:
    """Test stealth mode modifications."""

    def test_stealth_overrides_dry_run(self):
        """Test stealth mode overrides in dry-run."""
        config = ReverseShellConfig(
            rhost="192.168.1.100", rport=4444, stealth_mode=True, dry_run=True
        )
        with pytest.raises(PolicyViolation, match="prohibits"):
            install_steamth_mode_overrides(config)


class TestWebServerPoison:
    """Test web server poison attack."""

    def test_web_poison_dry_run(self):
        """Test web server poison in dry-run mode."""
        config = ReverseShellConfig(rhost="10.10.14.5", rport=4444, dry_run=True)
        with pytest.raises(PolicyViolation, match="prohibits"):
            install_web_server_poison(config, dry_run=True)

    def test_php_shell_generation(self):
        """Test PHP shell command generation."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            generate_reverse_shell_command(PersistenceMethod.PHP, "10.10.14.5", 4444)


class TestCleanup:
    """Test persistence cleanup."""

    def test_live_uninstall_is_rejected(self):
        """Cleanup remains non-mutating outside dry-run mode."""
        with pytest.raises(ValueError, match="Live persistence cleanup is disabled"):
            uninstall_persistence("10.10.14.5", dry_run=False)

    def test_uninstall_dry_run(self):
        """Test uninstall in dry-run mode."""
        result = uninstall_persistence("10.10.14.5", dry_run=True)

        assert result["dry_run"] is True
        assert "removed" in result
        assert isinstance(result["removed"], list)


class TestDefenseEnumeration:
    """Test defense enumeration."""

    def test_enum_defenses_structure(self):
        """Test defense enumeration returns correct structure."""
        result = enum_defenses()

        assert "auditd" in result
        assert "selinux" in result
        assert "apparmor" in result
        assert "antivirus" in result
        assert isinstance(result["antivirus"], list)


class TestFullInstallation:
    """Test full Linper installation."""

    def test_linper_install_dry_run(self):
        """Test full Linper install in dry-run mode."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            linper_install(rhost="10.10.14.5", rport=4444, dry_run=True)

    def test_linper_install_with_methods(self):
        """Test Linper install with specific methods."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            linper_install(
                rhost="10.10.14.5",
                rport=4444,
                methods=["bash", "python"],
                doors=["cron", "bashrc"],
                dry_run=True,
            )

    def test_linper_install_stealth(self):
        """Test Linper install with stealth mode."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            linper_install(rhost="192.168.1.100", rport=4444, stealth_mode=True, dry_run=True)


class TestMethodCoverage:
    """Test all persistence methods."""

    @pytest.mark.parametrize(
        "method",
        [
            PersistenceMethod.BASH,
            PersistenceMethod.NC,
            PersistenceMethod.NCAT,
            PersistenceMethod.PYTHON,
            PersistenceMethod.PYTHON3,
            PersistenceMethod.PHP,
            PersistenceMethod.PERL,
            PersistenceMethod.RUBY,
            PersistenceMethod.CURL,
            PersistenceMethod.WGET,
            PersistenceMethod.SOCAT,
            PersistenceMethod.TLONG,
        ],
    )
    def test_all_methods_generate_commands(self, method):
        """Test all methods can generate commands."""
        with pytest.raises(PolicyViolation, match="prohibits"):
            generate_reverse_shell_command(method, "10.10.14.5", 4444)


class TestDoorCoverage:
    """Test all persistence doors."""

    def test_all_doors_available(self):
        """Test all doors are available."""
        doors = [
            PersistenceDoor.CRON,
            PersistenceDoor.CRONTAB,
            PersistenceDoor.SYSTEMD,
            PersistenceDoor.RC_LOCAL,
            PersistenceDoor.BASHRC,
            PersistenceDoor.PROFILE,
            PersistenceDoor.INIT_D,
            PersistenceDoor.MOTD,
            PersistenceDoor.SSHRC,
        ]
        # Just verify they exist and are valid
        assert len(doors) == 9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
