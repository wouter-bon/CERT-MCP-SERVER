"""Certificate management tools for MCP."""

from typing import Optional, Dict, Any, List

from .base import BaseTool
from ..managers.device_manager import DeviceManager
from ..managers.certificate_manager import CertificateManager
from ..handlers.fortimanager import FortiManagerHandler


class CertificateTools(BaseTool):
    """Tools for certificate management operations."""

    def __init__(
        self,
        device_manager: DeviceManager,
        certificate_manager: CertificateManager
    ):
        """Initialize certificate tools.

        Args:
            device_manager: DeviceManager instance
            certificate_manager: CertificateManager instance
        """
        super().__init__("certificate")
        self.device_manager = device_manager
        self.certificate_manager = certificate_manager

    async def list_certificates(self, device_id: str) -> Dict[str, Any]:
        """List certificates on a device."""
        return await self.device_manager.list_certificates(device_id)

    async def get_certificate_detail(
        self,
        device_id: str,
        cert_name: str
    ) -> Dict[str, Any]:
        """Get certificate details."""
        return await self.device_manager.get_certificate(device_id, cert_name)

    async def check_certificate_expiry(
        self,
        device_id: str,
        cert_name: str,
        days_threshold: int = 30
    ) -> Dict[str, Any]:
        """Check certificate expiry status."""
        return await self.certificate_manager.check_expiry(
            device_id, cert_name, days_threshold
        )

    async def check_all_expiring(
        self,
        days_threshold: int = 30
    ) -> Dict[str, Any]:
        """Find all expiring certificates."""
        return await self.certificate_manager.check_all_expiring(days_threshold)

    async def verify_certificate_chain(
        self,
        cert_pem: str,
        chain_pem: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verify certificate chain."""
        try:
            result = self.certificate_manager.cert_utils.verify_certificate_chain(
                cert_pem.encode(),
                chain_pem.encode() if chain_pem else None
            )
            return {
                "success": True,
                **result
            }
        except Exception as e:
            return self._format_error(str(e))

    async def import_certificate(
        self,
        device_id: str,
        cert_name: str,
        certificate: str,
        private_key: str,
        chain: Optional[str] = None
    ) -> Dict[str, Any]:
        """Import certificate to a device."""
        return await self.certificate_manager.import_certificate(
            device_id=device_id,
            cert_name=cert_name,
            cert_pem=certificate.encode(),
            key_pem=private_key.encode(),
            chain_pem=chain.encode() if chain else None
        )

    async def import_ca_certificate(
        self,
        device_id: str,
        cert_name: str,
        certificate: str
    ) -> Dict[str, Any]:
        """Import CA certificate to a device."""
        return await self.certificate_manager.import_ca_certificate(
            device_id=device_id,
            cert_name=cert_name,
            cert_pem=certificate.encode()
        )

    async def replace_certificate(
        self,
        device_id: str,
        cert_name: str,
        certificate: str,
        private_key: str,
        chain: Optional[str] = None
    ) -> Dict[str, Any]:
        """Replace certificate on a device."""
        return await self.certificate_manager.replace_certificate(
            device_id=device_id,
            cert_name=cert_name,
            cert_pem=certificate.encode(),
            key_pem=private_key.encode(),
            chain_pem=chain.encode() if chain else None
        )

    async def delete_certificate(
        self,
        device_id: str,
        cert_name: str
    ) -> Dict[str, Any]:
        """Delete certificate from a device."""
        return await self.certificate_manager.delete_certificate(device_id, cert_name)

    async def delete_certificate_batch(
        self,
        device_ids: List[str],
        cert_name: str
    ) -> Dict[str, Any]:
        """Delete certificate from multiple devices."""
        return await self.certificate_manager.delete_certificate_batch(
            device_ids, cert_name
        )

    async def copy_certificate(
        self,
        source_device_id: str,
        target_device_id: str,
        cert_name: str,
        target_cert_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Copy certificate between devices."""
        return await self.certificate_manager.copy_certificate(
            source_device_id, target_device_id, cert_name, target_cert_name
        )

    async def renew_certificate(
        self,
        device_id: str,
        cert_name: str,
        domains: Optional[List[str]] = None,
        email: Optional[str] = None,
        cloudflare_api_token: Optional[str] = None,
        staging: bool = False
    ) -> Dict[str, Any]:
        """Renew certificate using Let's Encrypt."""
        return await self.certificate_manager.renew_certificate(
            device_id=device_id,
            cert_name=cert_name,
            domains=domains,
            email=email,
            cloudflare_api_token=cloudflare_api_token,
            staging=staging
        )

    async def auto_renew_check(
        self,
        days_threshold: int = 30,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Check and optionally renew expiring certificates."""
        return await self.certificate_manager.auto_renew_check(
            days_threshold, dry_run
        )

    # FortiManager-specific tools
    async def fmg_list_managed_devices(
        self,
        device_id: str
    ) -> Dict[str, Any]:
        """List devices managed by a FortiManager."""
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return self._format_error(f"Device {device_id} not found")

        if not isinstance(handler, FortiManagerHandler):
            return self._format_error(
                f"Device {device_id} is not a FortiManager"
            )

        try:
            devices = await handler.list_managed_devices()
            return self._format_success(
                f"Found {len(devices)} managed devices",
                {"devices": devices, "count": len(devices)}
            )
        except Exception as e:
            return self._format_error(str(e))

    async def fmg_get_certificates_all(
        self,
        device_id: str
    ) -> Dict[str, Any]:
        """Get certificates from all FortiGates managed by FortiManager."""
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return self._format_error(f"Device {device_id} not found")

        if not isinstance(handler, FortiManagerHandler):
            return self._format_error(
                f"Device {device_id} is not a FortiManager"
            )

        try:
            devices = await handler.list_managed_devices()
            results = {}

            for device in devices:
                device_name = device.get("name")
                if device_name:
                    certs = await handler.get_certificates_from_managed_device(device_name)
                    results[device_name] = [cert.to_dict() for cert in certs]

            return self._format_success(
                f"Retrieved certificates from {len(results)} devices",
                {"devices": results}
            )
        except Exception as e:
            return self._format_error(str(e))

    async def fmg_push_certificate(
        self,
        device_id: str,
        cert_name: str,
        target_devices: List[str]
    ) -> Dict[str, Any]:
        """Push certificate to managed FortiGate devices."""
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return self._format_error(f"Device {device_id} not found")

        if not isinstance(handler, FortiManagerHandler):
            return self._format_error(
                f"Device {device_id} is not a FortiManager"
            )

        results = {}
        for target in target_devices:
            try:
                result = await handler.push_certificate_to_device(cert_name, target)
                results[target] = result
            except Exception as e:
                results[target] = {"success": False, "error": str(e)}

        success_count = sum(1 for r in results.values() if r.get("success"))
        return self._format_success(
            f"Pushed certificate to {success_count}/{len(target_devices)} devices",
            {"results": results}
        )

    async def fmg_check_certificate_status(
        self,
        device_id: str,
        cert_name: str
    ) -> Dict[str, Any]:
        """Check certificate status across managed FortiGate devices."""
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return self._format_error(f"Device {device_id} not found")

        if not isinstance(handler, FortiManagerHandler):
            return self._format_error(
                f"Device {device_id} is not a FortiManager"
            )

        try:
            devices = await handler.list_managed_devices()
            status_results = {}

            for device in devices:
                device_name = device.get("name")
                if device_name:
                    certs = await handler.get_certificates_from_managed_device(device_name)
                    cert_found = any(c.name == cert_name for c in certs)
                    status_results[device_name] = {
                        "installed": cert_found,
                        "connection_status": device.get("connection_status")
                    }

            installed_count = sum(1 for s in status_results.values() if s.get("installed"))
            return self._format_success(
                f"Certificate installed on {installed_count}/{len(status_results)} devices",
                {
                    "cert_name": cert_name,
                    "devices": status_results,
                    "installed_count": installed_count,
                    "total_devices": len(status_results)
                }
            )
        except Exception as e:
            return self._format_error(str(e))
