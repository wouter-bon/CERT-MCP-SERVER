"""Device manager for handling multiple device types."""

from typing import Optional, Dict, Any, List, Type, Union

from ..config.models import (
    DevicesConfig,
    FortiGateDeviceConfig,
    FortiManagerDeviceConfig,
    FortiAnalyzerDeviceConfig,
    WindowsDeviceConfig,
    LinuxDeviceConfig,
)
from ..handlers.base import DeviceHandler, CertificateInfo
from ..handlers.fortigate import FortiGateHandler
from ..handlers.fortimanager import FortiManagerHandler
from ..handlers.fortianalyzer import FortiAnalyzerHandler
from ..handlers.windows import WindowsHandler
from ..handlers.linux import LinuxHandler
from ..core.logging import get_logger


# Type alias for all config types
DeviceConfig = Union[
    FortiGateDeviceConfig,
    FortiManagerDeviceConfig,
    FortiAnalyzerDeviceConfig,
    WindowsDeviceConfig,
    LinuxDeviceConfig,
]


class DeviceManager:
    """Manager for handling devices across multiple types."""

    HANDLER_MAP: Dict[str, Type[DeviceHandler]] = {
        "fortigate": FortiGateHandler,
        "fortimanager": FortiManagerHandler,
        "fortianalyzer": FortiAnalyzerHandler,
        "windows": WindowsHandler,
        "linux": LinuxHandler,
    }

    CONFIG_MAP: Dict[str, Type] = {
        "fortigate": FortiGateDeviceConfig,
        "fortimanager": FortiManagerDeviceConfig,
        "fortianalyzer": FortiAnalyzerDeviceConfig,
        "windows": WindowsDeviceConfig,
        "linux": LinuxDeviceConfig,
    }

    def __init__(self, devices_config: Optional[DevicesConfig] = None):
        """Initialize device manager.

        Args:
            devices_config: Initial devices configuration
        """
        self.logger = get_logger("device_manager")
        self._handlers: Dict[str, DeviceHandler] = {}
        self._configs: Dict[str, Dict[str, Any]] = {}

        # Load devices from config
        if devices_config:
            self._load_devices(devices_config)

    def _load_devices(self, devices_config: DevicesConfig) -> None:
        """Load devices from configuration."""
        # FortiGate devices
        for device_id, config in devices_config.fortigate.items():
            self._register_device("fortigate", device_id, config)

        # FortiManager devices
        for device_id, config in devices_config.fortimanager.items():
            self._register_device("fortimanager", device_id, config)

        # FortiAnalyzer devices
        for device_id, config in devices_config.fortianalyzer.items():
            self._register_device("fortianalyzer", device_id, config)

        # Windows devices
        for device_id, config in devices_config.windows.items():
            self._register_device("windows", device_id, config)

        # Linux devices
        for device_id, config in devices_config.linux.items():
            self._register_device("linux", device_id, config)

        self.logger.info(f"Loaded {len(self._handlers)} devices")

    def _register_device(
        self,
        device_type: str,
        device_id: str,
        config: DeviceConfig
    ) -> None:
        """Register a device with the manager."""
        handler_class = self.HANDLER_MAP.get(device_type)
        if not handler_class:
            self.logger.error(f"Unknown device type: {device_type}")
            return

        try:
            handler = handler_class(device_id, config)
            self._handlers[device_id] = handler
            self._configs[device_id] = {
                "device_type": device_type,
                "config": config.model_dump() if hasattr(config, 'model_dump') else config
            }
            self.logger.info(f"Registered device: {device_id} ({device_type})")
        except Exception as e:
            self.logger.error(f"Failed to register device {device_id}: {e}")

    def get_handler(self, device_id: str) -> Optional[DeviceHandler]:
        """Get handler for a specific device.

        Args:
            device_id: Device identifier

        Returns:
            DeviceHandler or None if not found
        """
        return self._handlers.get(device_id)

    def list_devices(self) -> List[Dict[str, Any]]:
        """List all registered devices.

        Returns:
            List of device info dictionaries
        """
        devices = []
        for device_id, handler in self._handlers.items():
            config = self._configs.get(device_id, {})
            devices.append({
                "device_id": device_id,
                "device_type": handler.DEVICE_TYPE,
                "host": config.get("config", {}).get("host", "unknown"),
            })
        return devices

    def list_devices_by_type(self, device_type: str) -> List[Dict[str, Any]]:
        """List devices filtered by type.

        Args:
            device_type: Device type to filter by

        Returns:
            List of device info dictionaries
        """
        devices = []
        for device_id, handler in self._handlers.items():
            if handler.DEVICE_TYPE == device_type:
                config = self._configs.get(device_id, {})
                devices.append({
                    "device_id": device_id,
                    "device_type": handler.DEVICE_TYPE,
                    "host": config.get("config", {}).get("host", "unknown"),
                })
        return devices

    async def add_device(
        self,
        device_id: str,
        device_type: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Add a new device dynamically.

        Args:
            device_id: Unique device identifier
            device_type: Type of device (fortigate, fortimanager, etc.)
            **kwargs: Device configuration parameters

        Returns:
            Result dictionary
        """
        if device_id in self._handlers:
            return {
                "success": False,
                "message": f"Device {device_id} already exists"
            }

        config_class = self.CONFIG_MAP.get(device_type)
        if not config_class:
            return {
                "success": False,
                "message": f"Unknown device type: {device_type}. "
                          f"Valid types: {list(self.CONFIG_MAP.keys())}"
            }

        try:
            config = config_class(**kwargs)
            self._register_device(device_type, device_id, config)

            return {
                "success": True,
                "message": f"Device {device_id} added successfully",
                "device_id": device_id,
                "device_type": device_type
            }
        except Exception as e:
            self.logger.error(f"Failed to add device {device_id}: {e}")
            return {
                "success": False,
                "message": str(e)
            }

    async def remove_device(self, device_id: str) -> Dict[str, Any]:
        """Remove a device.

        Args:
            device_id: Device identifier to remove

        Returns:
            Result dictionary
        """
        if device_id not in self._handlers:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        del self._handlers[device_id]
        del self._configs[device_id]

        self.logger.info(f"Removed device: {device_id}")

        return {
            "success": True,
            "message": f"Device {device_id} removed successfully"
        }

    async def test_device_connection(self, device_id: str) -> Dict[str, Any]:
        """Test connection to a device.

        Args:
            device_id: Device identifier

        Returns:
            Result dictionary with connection status
        """
        handler = self.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        try:
            connected = await handler.test_connection()
            return {
                "success": True,
                "connected": connected,
                "device_id": device_id,
                "device_type": handler.DEVICE_TYPE,
                "message": "Connection successful" if connected else "Connection failed"
            }
        except Exception as e:
            return {
                "success": False,
                "connected": False,
                "device_id": device_id,
                "message": str(e)
            }

    async def get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get detailed device information.

        Args:
            device_id: Device identifier

        Returns:
            Device information dictionary
        """
        handler = self.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        try:
            info = await handler.get_device_info()
            return {
                "success": True,
                **info
            }
        except Exception as e:
            return {
                "success": False,
                "device_id": device_id,
                "message": str(e)
            }

    async def list_certificates(self, device_id: str) -> Dict[str, Any]:
        """List certificates on a device.

        Args:
            device_id: Device identifier

        Returns:
            Result dictionary with certificates list
        """
        handler = self.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found",
                "certificates": []
            }

        try:
            certs = await handler.list_certificates()
            return {
                "success": True,
                "device_id": device_id,
                "device_type": handler.DEVICE_TYPE,
                "certificates": [cert.to_dict() for cert in certs],
                "count": len(certs)
            }
        except Exception as e:
            return {
                "success": False,
                "device_id": device_id,
                "message": str(e),
                "certificates": []
            }

    async def get_certificate(
        self,
        device_id: str,
        cert_name: str
    ) -> Dict[str, Any]:
        """Get certificate details from a device.

        Args:
            device_id: Device identifier
            cert_name: Certificate name

        Returns:
            Result dictionary with certificate details
        """
        handler = self.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        try:
            cert = await handler.get_certificate(cert_name)
            if cert:
                return {
                    "success": True,
                    "device_id": device_id,
                    "certificate": cert.to_dict()
                }
            else:
                return {
                    "success": False,
                    "device_id": device_id,
                    "message": f"Certificate {cert_name} not found"
                }
        except Exception as e:
            return {
                "success": False,
                "device_id": device_id,
                "message": str(e)
            }

    def get_device_count(self) -> int:
        """Get total number of registered devices."""
        return len(self._handlers)

    def get_device_types(self) -> List[str]:
        """Get list of available device types."""
        return list(self.HANDLER_MAP.keys())
