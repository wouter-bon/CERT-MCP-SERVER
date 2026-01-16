"""Device management tools for MCP."""

from typing import Optional, Dict, Any, List

from .base import BaseTool
from ..managers.device_manager import DeviceManager


class DeviceTools(BaseTool):
    """Tools for device management operations."""

    def __init__(self, device_manager: DeviceManager):
        """Initialize device tools.

        Args:
            device_manager: DeviceManager instance
        """
        super().__init__("device")
        self.device_manager = device_manager

    async def list_devices(self) -> Dict[str, Any]:
        """List all registered devices."""
        devices = self.device_manager.list_devices()
        return self._format_success(
            f"Found {len(devices)} devices",
            {
                "devices": devices,
                "count": len(devices)
            }
        )

    async def list_devices_by_type(self, device_type: str) -> Dict[str, Any]:
        """List devices filtered by type."""
        valid_types = self.device_manager.get_device_types()
        if device_type not in valid_types:
            return self._format_error(
                f"Invalid device type: {device_type}. Valid types: {valid_types}"
            )

        devices = self.device_manager.list_devices_by_type(device_type)
        return self._format_success(
            f"Found {len(devices)} {device_type} devices",
            {
                "devices": devices,
                "device_type": device_type,
                "count": len(devices)
            }
        )

    async def add_device(
        self,
        device_id: str,
        device_type: str,
        host: str,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_token: Optional[str] = None,
        vdom: Optional[str] = None,
        adom: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 30,
        transport: Optional[str] = None,
        cert_store: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        service_type: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Add a new device."""
        # Build config based on device type
        config = {"host": host, "verify_ssl": verify_ssl, "timeout": timeout}

        if port:
            config["port"] = port
        if username:
            config["username"] = username
        if password:
            config["password"] = password
        if api_token:
            config["api_token"] = api_token

        # Type-specific configs
        if device_type == "fortigate" and vdom:
            config["vdom"] = vdom
        if device_type in ("fortimanager", "fortianalyzer") and adom:
            config["adom"] = adom
        if device_type == "windows":
            if transport:
                config["transport"] = transport
            if cert_store:
                config["cert_store"] = cert_store
        if device_type == "linux":
            if ssh_key_path:
                config["ssh_key_path"] = ssh_key_path
            if service_type:
                config["service_type"] = service_type

        # Add any additional kwargs
        config.update(kwargs)

        return await self.device_manager.add_device(device_id, device_type, **config)

    async def remove_device(self, device_id: str) -> Dict[str, Any]:
        """Remove a device."""
        return await self.device_manager.remove_device(device_id)

    async def test_device_connection(self, device_id: str) -> Dict[str, Any]:
        """Test connection to a device."""
        return await self.device_manager.test_device_connection(device_id)

    async def get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get device information."""
        return await self.device_manager.get_device_info(device_id)
