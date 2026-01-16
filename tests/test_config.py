"""Tests for configuration module."""

import pytest
import json
import tempfile
from pathlib import Path


class TestConfigModels:
    """Tests for configuration models."""

    def test_server_config_defaults(self):
        """Test ServerConfig has correct defaults."""
        from cert_mcp.config.models import ServerConfig

        config = ServerConfig()
        assert config.host == "0.0.0.0"
        assert config.port == 8815
        assert config.name == "cert-mcp-server"
        assert config.version == "1.0.0"

    def test_logging_config_defaults(self):
        """Test LoggingConfig has correct defaults."""
        from cert_mcp.config.models import LoggingConfig

        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.console is True
        assert config.file_path is None

    def test_acme_config_defaults(self):
        """Test ACMEConfig has correct defaults."""
        from cert_mcp.config.models import ACMEConfig

        config = ACMEConfig()
        assert config.email is None
        assert config.staging is False
        assert config.account_key_path is None

    def test_acme_config_path_expansion(self):
        """Test ACMEConfig expands ~ in paths."""
        from cert_mcp.config.models import ACMEConfig

        config = ACMEConfig(account_key_path="~/.acme/key.pem")
        assert "~" not in config.account_key_path
        assert config.account_key_path.endswith(".acme/key.pem")

    def test_fortigate_device_config(self):
        """Test FortiGateDeviceConfig validation."""
        from cert_mcp.config.models import FortiGateDeviceConfig

        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            api_token="test_token"
        )
        assert config.host == "192.168.1.1"
        assert config.port == 443
        assert config.vdom == "root"
        assert config.verify_ssl is False

    def test_linux_device_config(self):
        """Test LinuxDeviceConfig validation."""
        from cert_mcp.config.models import LinuxDeviceConfig

        config = LinuxDeviceConfig(
            host="192.168.1.10",
            username="admin",
            ssh_key_path="~/.ssh/id_rsa",
            service_type="nginx"
        )
        assert config.host == "192.168.1.10"
        assert config.port == 22
        assert config.service_type == "nginx"
        assert "~" not in config.ssh_key_path

    def test_windows_device_config(self):
        """Test WindowsDeviceConfig validation."""
        from cert_mcp.config.models import WindowsDeviceConfig

        config = WindowsDeviceConfig(
            host="192.168.1.20",
            username="Administrator",
            password="secret"
        )
        assert config.host == "192.168.1.20"
        assert config.port == 5986
        assert config.transport == "ntlm"
        assert config.cert_store == "LocalMachine\\My"

    def test_full_config(self):
        """Test full Config model."""
        from cert_mcp.config.models import Config

        config = Config()
        assert config.server.port == 8815
        assert config.logging.level == "INFO"
        assert config.acme.staging is False
        assert len(config.devices.fortigate) == 0


class TestConfigLoader:
    """Tests for configuration loader."""

    def test_load_config_from_env(self, monkeypatch):
        """Test loading config from environment variables."""
        from cert_mcp.config.loader import load_config

        monkeypatch.setenv("ACME_EMAIL", "test@example.com")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        config = load_config()
        assert config.acme.email == "test@example.com"
        assert config.logging.level == "DEBUG"

    def test_load_config_from_file(self, tmp_path):
        """Test loading config from JSON file."""
        from cert_mcp.config.loader import load_config

        config_data = {
            "server": {"port": 9000},
            "acme": {"email": "file@example.com"},
            "logging": {"level": "WARNING"}
        }

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config(str(config_file))
        assert config.server.port == 9000
        assert config.acme.email == "file@example.com"
        assert config.logging.level == "WARNING"

    def test_load_config_file_not_found(self):
        """Test error when config file not found."""
        from cert_mcp.config.loader import load_config

        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.json")

    def test_env_overrides_file(self, tmp_path, monkeypatch):
        """Test environment variables override file config."""
        from cert_mcp.config.loader import load_config

        config_data = {
            "acme": {"email": "file@example.com"}
        }

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        monkeypatch.setenv("ACME_EMAIL", "env@example.com")

        config = load_config(str(config_file))
        assert config.acme.email == "env@example.com"
