"""Tests for MCP tools."""

import pytest
from unittest.mock import AsyncMock, MagicMock


class TestToolDefinitions:
    """Tests for tool definitions."""

    def test_tool_definitions_count(self):
        """Test that all 30 tools are defined."""
        from cert_mcp.tools.definitions import TOOL_DEFINITIONS

        assert len(TOOL_DEFINITIONS) == 30

    def test_tool_definitions_categories(self):
        """Test tool categories are present."""
        from cert_mcp.tools.definitions import TOOL_DEFINITIONS

        # Device management
        assert "list_devices" in TOOL_DEFINITIONS
        assert "add_device" in TOOL_DEFINITIONS
        assert "remove_device" in TOOL_DEFINITIONS

        # Certificate operations
        assert "list_certificates" in TOOL_DEFINITIONS
        assert "import_certificate" in TOOL_DEFINITIONS
        assert "delete_certificate" in TOOL_DEFINITIONS

        # Let's Encrypt
        assert "request_certificate" in TOOL_DEFINITIONS
        assert "list_cloudflare_zones" in TOOL_DEFINITIONS

        # FortiManager
        assert "fmg_list_managed_devices" in TOOL_DEFINITIONS
        assert "fmg_push_certificate" in TOOL_DEFINITIONS

        # System
        assert "health_check" in TOOL_DEFINITIONS
        assert "get_server_info" in TOOL_DEFINITIONS

    def test_tool_descriptions_not_empty(self):
        """Test all tool descriptions are non-empty."""
        from cert_mcp.tools.definitions import TOOL_DEFINITIONS

        for name, description in TOOL_DEFINITIONS.items():
            assert description, f"Tool {name} has empty description"
            assert len(description) > 10, f"Tool {name} description too short"


class TestDeviceTools:
    """Tests for DeviceTools."""

    @pytest.mark.asyncio
    async def test_list_devices(self):
        """Test list_devices tool."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.tools.device_tools import DeviceTools

        manager = DeviceManager()
        tools = DeviceTools(manager)

        result = await tools.list_devices()

        assert result["success"] is True
        assert "devices" in result
        assert result["count"] == 0

    @pytest.mark.asyncio
    async def test_list_devices_by_type_invalid(self):
        """Test list_devices_by_type with invalid type."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.tools.device_tools import DeviceTools

        manager = DeviceManager()
        tools = DeviceTools(manager)

        result = await tools.list_devices_by_type("invalid_type")

        assert result["success"] is False
        assert "Invalid device type" in result["error"]

    @pytest.mark.asyncio
    async def test_add_device(self):
        """Test add_device tool."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.tools.device_tools import DeviceTools

        manager = DeviceManager()
        tools = DeviceTools(manager)

        result = await tools.add_device(
            device_id="test-fw",
            device_type="fortigate",
            host="192.168.1.1",
            api_token="test_token"
        )

        assert result["success"] is True
        assert manager.get_device_count() == 1


class TestCertificateTools:
    """Tests for CertificateTools."""

    @pytest.mark.asyncio
    async def test_list_certificates_device_not_found(self):
        """Test list_certificates with non-existent device."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager
        from cert_mcp.tools.certificate_tools import CertificateTools

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)
        tools = CertificateTools(device_manager, cert_manager)

        result = await tools.list_certificates("nonexistent")

        assert result["success"] is False
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_check_all_expiring(self):
        """Test check_all_expiring tool."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager
        from cert_mcp.tools.certificate_tools import CertificateTools

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)
        tools = CertificateTools(device_manager, cert_manager)

        result = await tools.check_all_expiring(days_threshold=30)

        assert result["success"] is True
        assert result["threshold_days"] == 30


class TestACMETools:
    """Tests for ACMETools."""

    def test_list_cloudflare_zones_no_token(self):
        """Test list_cloudflare_zones without token."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager
        from cert_mcp.tools.acme_tools import ACMETools

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)
        tools = ACMETools(cert_manager)

        result = tools.list_cloudflare_zones()

        assert result["success"] is False

    def test_verify_cloudflare_token_no_token(self):
        """Test verify_cloudflare_token without token."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager
        from cert_mcp.tools.acme_tools import ACMETools

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)
        tools = ACMETools(cert_manager)

        result = tools.verify_cloudflare_token()

        assert result["success"] is False

    def test_get_acme_account_info_no_email(self):
        """Test get_acme_account_info without email."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager
        from cert_mcp.tools.acme_tools import ACMETools

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)
        tools = ACMETools(cert_manager)

        result = tools.get_acme_account_info()

        assert result["success"] is False
