"""Tests for device handlers."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch


class TestCertificateInfo:
    """Tests for CertificateInfo dataclass."""

    def test_certificate_info_creation(self):
        """Test creating CertificateInfo."""
        from cert_mcp.handlers.base import CertificateInfo

        cert = CertificateInfo(
            name="test-cert",
            subject="CN=example.com",
            issuer="CN=Let's Encrypt",
            serial_number="ABC123",
            not_valid_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
            not_valid_after=datetime(2024, 12, 31, tzinfo=timezone.utc),
            domains=["example.com", "www.example.com"],
            status="valid"
        )

        assert cert.name == "test-cert"
        assert cert.subject == "CN=example.com"
        assert len(cert.domains) == 2

    def test_certificate_info_to_dict(self):
        """Test CertificateInfo serialization."""
        from cert_mcp.handlers.base import CertificateInfo

        cert = CertificateInfo(
            name="test-cert",
            subject="CN=example.com",
            issuer="CN=Let's Encrypt",
            serial_number="ABC123",
            not_valid_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
            not_valid_after=datetime(2024, 12, 31, tzinfo=timezone.utc),
            days_remaining=180,
            status="valid"
        )

        data = cert.to_dict()
        assert data["name"] == "test-cert"
        assert data["status"] == "valid"
        assert data["days_remaining"] == 180
        assert "2024-01-01" in data["not_valid_before"]


class TestDeviceHandlerBase:
    """Tests for DeviceHandler base class."""

    def test_format_result_success(self):
        """Test _format_result for success."""
        from cert_mcp.handlers.base import DeviceHandler
        from cert_mcp.config.models import FortiGateDeviceConfig

        # Create a concrete implementation for testing
        class TestHandler(DeviceHandler):
            DEVICE_TYPE = "test"
            async def test_connection(self): return True
            async def list_certificates(self): return []
            async def get_certificate(self, name): return None
            async def import_certificate(self, *args, **kwargs): return {}
            async def delete_certificate(self, name): return {}
            async def replace_certificate(self, *args, **kwargs): return {}

        config = FortiGateDeviceConfig(host="192.168.1.1")
        handler = TestHandler("test-device", config.model_dump())

        result = handler._format_result(True, "Success", {"extra": "data"})
        assert result["success"] is True
        assert result["message"] == "Success"
        assert result["device_id"] == "test-device"
        assert result["extra"] == "data"

    def test_format_result_failure(self):
        """Test _format_result for failure."""
        from cert_mcp.handlers.base import DeviceHandler
        from cert_mcp.config.models import FortiGateDeviceConfig

        class TestHandler(DeviceHandler):
            DEVICE_TYPE = "test"
            async def test_connection(self): return True
            async def list_certificates(self): return []
            async def get_certificate(self, name): return None
            async def import_certificate(self, *args, **kwargs): return {}
            async def delete_certificate(self, name): return {}
            async def replace_certificate(self, *args, **kwargs): return {}

        config = FortiGateDeviceConfig(host="192.168.1.1")
        handler = TestHandler("test-device", config.model_dump())

        result = handler._format_result(False, "Error occurred")
        assert result["success"] is False
        assert result["message"] == "Error occurred"


class TestFortiGateHandler:
    """Tests for FortiGateHandler."""

    def test_handler_initialization(self):
        """Test FortiGateHandler initialization."""
        from cert_mcp.handlers.fortigate import FortiGateHandler
        from cert_mcp.config.models import FortiGateDeviceConfig

        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            api_token="test_token",
            vdom="root"
        )

        handler = FortiGateHandler("fw-01", config)
        assert handler.device_id == "fw-01"
        assert handler.host == "192.168.1.1"
        assert handler.vdom == "root"
        assert handler.DEVICE_TYPE == "fortigate"

    def test_base_url_construction(self):
        """Test base URL is correctly constructed."""
        from cert_mcp.handlers.fortigate import FortiGateHandler
        from cert_mcp.config.models import FortiGateDeviceConfig

        config = FortiGateDeviceConfig(host="fw.example.com", port=8443)
        handler = FortiGateHandler("fw-01", config)

        assert handler._base_url == "https://fw.example.com:8443"


class TestLinuxHandler:
    """Tests for LinuxHandler."""

    def test_handler_initialization(self):
        """Test LinuxHandler initialization."""
        from cert_mcp.handlers.linux import LinuxHandler
        from cert_mcp.config.models import LinuxDeviceConfig

        config = LinuxDeviceConfig(
            host="192.168.1.10",
            username="admin",
            service_type="nginx"
        )

        handler = LinuxHandler("nginx-01", config)
        assert handler.device_id == "nginx-01"
        assert handler.host == "192.168.1.10"
        assert handler.service_type == "nginx"
        assert handler.DEVICE_TYPE == "linux"

    def test_service_paths_nginx(self):
        """Test nginx service paths."""
        from cert_mcp.handlers.linux import LinuxHandler
        from cert_mcp.config.models import LinuxDeviceConfig

        config = LinuxDeviceConfig(
            host="192.168.1.10",
            username="admin",
            service_type="nginx"
        )

        handler = LinuxHandler("nginx-01", config)

        cert_path = handler._get_cert_path("example")
        key_path = handler._get_key_path("example")

        assert "/nginx/" in cert_path
        assert "example.crt" in cert_path
        assert "example.key" in key_path

    def test_service_paths_haproxy(self):
        """Test haproxy service paths (combined PEM)."""
        from cert_mcp.handlers.linux import LinuxHandler
        from cert_mcp.config.models import LinuxDeviceConfig

        config = LinuxDeviceConfig(
            host="192.168.1.10",
            username="admin",
            service_type="haproxy"
        )

        handler = LinuxHandler("haproxy-01", config)

        cert_path = handler._get_cert_path("example")
        key_path = handler._get_key_path("example")

        # HAProxy uses combined PEM, so key path should equal cert path
        assert "/haproxy/" in cert_path
        assert ".pem" in cert_path

    def test_custom_paths(self):
        """Test custom certificate paths."""
        from cert_mcp.handlers.linux import LinuxHandler
        from cert_mcp.config.models import LinuxDeviceConfig

        config = LinuxDeviceConfig(
            host="192.168.1.10",
            username="admin",
            service_type="generic",
            cert_path="/opt/app/certs/{name}.crt",
            key_path="/opt/app/certs/{name}.key"
        )

        handler = LinuxHandler("custom-01", config)

        cert_path = handler._get_cert_path("myapp")
        key_path = handler._get_key_path("myapp")

        assert cert_path == "/opt/app/certs/myapp.crt"
        assert key_path == "/opt/app/certs/myapp.key"


class TestWindowsHandler:
    """Tests for WindowsHandler."""

    def test_handler_initialization(self):
        """Test WindowsHandler initialization."""
        from cert_mcp.handlers.windows import WindowsHandler
        from cert_mcp.config.models import WindowsDeviceConfig

        config = WindowsDeviceConfig(
            host="192.168.1.20",
            username="Administrator",
            password="secret"
        )

        handler = WindowsHandler("win-01", config)
        assert handler.device_id == "win-01"
        assert handler.host == "192.168.1.20"
        assert handler.transport == "ntlm"
        assert handler.DEVICE_TYPE == "windows"

    def test_endpoint_construction(self):
        """Test WinRM endpoint URL construction."""
        from cert_mcp.handlers.windows import WindowsHandler
        from cert_mcp.config.models import WindowsDeviceConfig

        # HTTPS (port 5986)
        config = WindowsDeviceConfig(
            host="192.168.1.20",
            port=5986,
            username="admin",
            password="secret"
        )
        handler = WindowsHandler("win-01", config)
        assert handler._endpoint == "https://192.168.1.20:5986/wsman"

        # HTTP (port 5985)
        config = WindowsDeviceConfig(
            host="192.168.1.20",
            port=5985,
            username="admin",
            password="secret"
        )
        handler = WindowsHandler("win-02", config)
        assert handler._endpoint == "http://192.168.1.20:5985/wsman"
