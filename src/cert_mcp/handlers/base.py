"""Base device handler interface for certificate management."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any

from ..core.logging import get_logger


@dataclass
class CertificateInfo:
    """Certificate information from a device."""

    name: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    domains: List[str] = field(default_factory=list)
    fingerprint: str = ""
    key_type: str = ""
    key_size: int = 0
    is_ca: bool = False
    days_remaining: int = 0
    status: str = "valid"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_valid_before": self.not_valid_before.isoformat() if self.not_valid_before else None,
            "not_valid_after": self.not_valid_after.isoformat() if self.not_valid_after else None,
            "domains": self.domains,
            "fingerprint": self.fingerprint,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "is_ca": self.is_ca,
            "days_remaining": self.days_remaining,
            "status": self.status,
        }


class DeviceHandler(ABC):
    """Abstract base class for device handlers."""

    DEVICE_TYPE: str = "unknown"

    def __init__(self, device_id: str, config: dict):
        """Initialize device handler.

        Args:
            device_id: Unique device identifier
            config: Device configuration dictionary
        """
        self.device_id = device_id
        self.config = config
        self.logger = get_logger(f"handler.{self.DEVICE_TYPE}.{device_id}")

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connection to the device.

        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    async def list_certificates(self) -> List[CertificateInfo]:
        """List all certificates on the device.

        Returns:
            List of CertificateInfo objects
        """
        pass

    @abstractmethod
    async def get_certificate(self, cert_name: str) -> Optional[CertificateInfo]:
        """Get details of a specific certificate.

        Args:
            cert_name: Certificate name/identifier

        Returns:
            CertificateInfo or None if not found
        """
        pass

    @abstractmethod
    async def import_certificate(
        self,
        cert_name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Import a certificate to the device.

        Args:
            cert_name: Name for the certificate
            cert_pem: PEM-encoded certificate
            key_pem: PEM-encoded private key
            chain_pem: Optional PEM-encoded certificate chain

        Returns:
            Result dictionary with status and details
        """
        pass

    @abstractmethod
    async def delete_certificate(self, cert_name: str) -> Dict[str, Any]:
        """Delete a certificate from the device.

        Args:
            cert_name: Certificate name to delete

        Returns:
            Result dictionary with status
        """
        pass

    @abstractmethod
    async def replace_certificate(
        self,
        cert_name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Replace an existing certificate on the device.

        Args:
            cert_name: Name of certificate to replace
            cert_pem: New PEM-encoded certificate
            key_pem: New PEM-encoded private key
            chain_pem: Optional new PEM-encoded certificate chain

        Returns:
            Result dictionary with status and details
        """
        pass

    async def import_ca_certificate(
        self,
        cert_name: str,
        cert_pem: bytes
    ) -> Dict[str, Any]:
        """Import a CA certificate to the device.

        Args:
            cert_name: Name for the CA certificate
            cert_pem: PEM-encoded CA certificate

        Returns:
            Result dictionary with status
        """
        raise NotImplementedError(
            f"CA certificate import not supported for {self.DEVICE_TYPE}"
        )

    async def get_device_info(self) -> Dict[str, Any]:
        """Get device information.

        Returns:
            Device information dictionary
        """
        return {
            "device_id": self.device_id,
            "device_type": self.DEVICE_TYPE,
            "host": self.config.get("host", "unknown"),
        }

    def _format_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Format a standard result dictionary.

        Args:
            success: Whether operation was successful
            message: Result message
            data: Optional additional data

        Returns:
            Formatted result dictionary
        """
        result = {
            "success": success,
            "message": message,
            "device_id": self.device_id,
            "device_type": self.DEVICE_TYPE,
        }
        if data:
            result.update(data)
        return result
