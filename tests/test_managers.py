"""Tests for manager classes."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestDeviceManager:
    """Tests for DeviceManager."""

    def test_initialization_empty(self):
        """Test DeviceManager initialization without config."""
        from cert_mcp.managers.device_manager import DeviceManager

        manager = DeviceManager()
        assert manager.get_device_count() == 0
        assert manager.list_devices() == []

    def test_initialization_with_config(self):
        """Test DeviceManager initialization with config."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.config.models import DevicesConfig, FortiGateDeviceConfig

        devices_config = DevicesConfig(
            fortigate={
                "fw-01": FortiGateDeviceConfig(host="192.168.1.1", api_token="token")
            }
        )

        manager = DeviceManager(devices_config)
        assert manager.get_device_count() == 1
        assert len(manager.list_devices()) == 1

    def test_get_handler(self):
        """Test getting a device handler."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.config.models import DevicesConfig, FortiGateDeviceConfig

        devices_config = DevicesConfig(
            fortigate={
                "fw-01": FortiGateDeviceConfig(host="192.168.1.1", api_token="token")
            }
        )

        manager = DeviceManager(devices_config)
        handler = manager.get_handler("fw-01")

        assert handler is not None
        assert handler.device_id == "fw-01"

    def test_get_handler_not_found(self):
        """Test getting non-existent handler."""
        from cert_mcp.managers.device_manager import DeviceManager

        manager = DeviceManager()
        handler = manager.get_handler("nonexistent")

        assert handler is None

    def test_list_devices_by_type(self):
        """Test listing devices by type."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.config.models import (
            DevicesConfig, FortiGateDeviceConfig, LinuxDeviceConfig
        )

        devices_config = DevicesConfig(
            fortigate={
                "fw-01": FortiGateDeviceConfig(host="192.168.1.1", api_token="token"),
                "fw-02": FortiGateDeviceConfig(host="192.168.1.2", api_token="token")
            },
            linux={
                "nginx-01": LinuxDeviceConfig(host="192.168.1.10", username="admin")
            }
        )

        manager = DeviceManager(devices_config)

        fortigates = manager.list_devices_by_type("fortigate")
        linux_devices = manager.list_devices_by_type("linux")

        assert len(fortigates) == 2
        assert len(linux_devices) == 1

    @pytest.mark.asyncio
    async def test_add_device(self):
        """Test adding a device dynamically."""
        from cert_mcp.managers.device_manager import DeviceManager

        manager = DeviceManager()
        assert manager.get_device_count() == 0

        result = await manager.add_device(
            device_id="fw-new",
            device_type="fortigate",
            host="192.168.1.100",
            api_token="new_token"
        )

        assert result["success"] is True
        assert manager.get_device_count() == 1
        assert manager.get_handler("fw-new") is not None

    @pytest.mark.asyncio
    async def test_add_device_duplicate(self):
        """Test adding duplicate device fails."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.config.models import DevicesConfig, FortiGateDeviceConfig

        devices_config = DevicesConfig(
            fortigate={
                "fw-01": FortiGateDeviceConfig(host="192.168.1.1", api_token="token")
            }
        )

        manager = DeviceManager(devices_config)

        result = await manager.add_device(
            device_id="fw-01",
            device_type="fortigate",
            host="192.168.1.100",
            api_token="new_token"
        )

        assert result["success"] is False
        assert "already exists" in result["message"]

    @pytest.mark.asyncio
    async def test_add_device_invalid_type(self):
        """Test adding device with invalid type fails."""
        from cert_mcp.managers.device_manager import DeviceManager

        manager = DeviceManager()

        result = await manager.add_device(
            device_id="invalid-01",
            device_type="invalid_type",
            host="192.168.1.100"
        )

        assert result["success"] is False
        assert "Unknown device type" in result["message"]

    @pytest.mark.asyncio
    async def test_remove_device(self):
        """Test removing a device."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.config.models import DevicesConfig, FortiGateDeviceConfig

        devices_config = DevicesConfig(
            fortigate={
                "fw-01": FortiGateDeviceConfig(host="192.168.1.1", api_token="token")
            }
        )

        manager = DeviceManager(devices_config)
        assert manager.get_device_count() == 1

        result = await manager.remove_device("fw-01")

        assert result["success"] is True
        assert manager.get_device_count() == 0

    @pytest.mark.asyncio
    async def test_remove_device_not_found(self):
        """Test removing non-existent device."""
        from cert_mcp.managers.device_manager import DeviceManager

        manager = DeviceManager()

        result = await manager.remove_device("nonexistent")

        assert result["success"] is False
        assert "not found" in result["message"]

    def test_get_device_types(self):
        """Test getting available device types."""
        from cert_mcp.managers.device_manager import DeviceManager

        manager = DeviceManager()
        types = manager.get_device_types()

        assert "fortigate" in types
        assert "fortimanager" in types
        assert "fortianalyzer" in types
        assert "windows" in types
        assert "linux" in types


class TestCertificateManager:
    """Tests for CertificateManager."""

    def test_initialization(self):
        """Test CertificateManager initialization."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)

        assert cert_manager.device_manager is device_manager

    def test_list_cloudflare_zones_no_token(self):
        """Test list_cloudflare_zones without token."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)

        result = cert_manager.list_cloudflare_zones()

        assert result["success"] is False
        assert "required" in result["message"].lower()

    def test_verify_cloudflare_token_no_token(self):
        """Test verify_cloudflare_token without token."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)

        result = cert_manager.verify_cloudflare_token()

        assert result["success"] is False

    def test_get_acme_account_info_no_email(self):
        """Test get_acme_account_info without email."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)

        result = cert_manager.get_acme_account_info()

        assert result["success"] is False
        assert "email" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_import_certificate_device_not_found(self):
        """Test import_certificate with non-existent device."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)

        result = await cert_manager.import_certificate(
            device_id="nonexistent",
            cert_name="test",
            cert_pem=b"cert",
            key_pem=b"key"
        )

        assert result["success"] is False
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_certificate_device_not_found(self):
        """Test delete_certificate with non-existent device."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)

        result = await cert_manager.delete_certificate(
            device_id="nonexistent",
            cert_name="test"
        )

        assert result["success"] is False
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_check_all_expiring_empty(self):
        """Test check_all_expiring with no devices."""
        from cert_mcp.managers.device_manager import DeviceManager
        from cert_mcp.managers.certificate_manager import CertificateManager

        device_manager = DeviceManager()
        cert_manager = CertificateManager(device_manager)

        result = await cert_manager.check_all_expiring(days_threshold=30)

        assert result["success"] is True
        assert result["expiring_count"] == 0
        assert result["expiring_certificates"] == []
