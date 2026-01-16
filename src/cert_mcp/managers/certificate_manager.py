"""Certificate manager for handling certificate operations across devices."""

import os
from typing import Optional, Dict, Any, List

from .device_manager import DeviceManager
from ..core.logging import get_logger
from ..core.acme_client import ACMEClient
from ..core.cloudflare_dns import CloudflareDNS, CloudflareDNSChallengeHandler
from ..core.certificate_utils import CertificateUtils
from ..config.models import ACMEConfig


class CertificateManager:
    """Manager for certificate operations across multiple devices."""

    def __init__(
        self,
        device_manager: DeviceManager,
        acme_config: Optional[ACMEConfig] = None,
        cloudflare_api_token: Optional[str] = None
    ):
        """Initialize certificate manager.

        Args:
            device_manager: DeviceManager instance
            acme_config: ACME configuration
            cloudflare_api_token: Cloudflare API token
        """
        self.device_manager = device_manager
        self.acme_config = acme_config or ACMEConfig()
        self.cloudflare_api_token = cloudflare_api_token or os.environ.get("CLOUDFLARE_API_TOKEN")
        self.logger = get_logger("certificate_manager")
        self.cert_utils = CertificateUtils()

        # Initialize ACME client if configured
        self._acme_client: Optional[ACMEClient] = None
        self._cloudflare: Optional[CloudflareDNS] = None

    def _get_acme_client(self, email: Optional[str] = None, staging: Optional[bool] = None) -> ACMEClient:
        """Get or create ACME client."""
        acme_email = email or self.acme_config.email or os.environ.get("ACME_EMAIL")
        if not acme_email:
            raise ValueError("ACME email is required. Set via config, parameter, or ACME_EMAIL env var.")

        use_staging = staging if staging is not None else self.acme_config.staging
        account_key_path = self.acme_config.account_key_path or os.environ.get("ACME_ACCOUNT_KEY_PATH")

        # Return cached client if settings match
        if self._acme_client:
            if (self._acme_client.email == acme_email and
                self._acme_client.staging == use_staging):
                return self._acme_client

        self._acme_client = ACMEClient(
            email=acme_email,
            staging=use_staging,
            account_key_path=account_key_path
        )
        return self._acme_client

    def _get_cloudflare(self, api_token: Optional[str] = None) -> CloudflareDNS:
        """Get or create Cloudflare client."""
        token = api_token or self.cloudflare_api_token
        if not token:
            raise ValueError("Cloudflare API token is required. Set via config, parameter, or CLOUDFLARE_API_TOKEN env var.")

        if self._cloudflare and self._cloudflare.api_token == token:
            return self._cloudflare

        self._cloudflare = CloudflareDNS(token)
        return self._cloudflare

    async def request_certificate(
        self,
        domains: List[str],
        email: Optional[str] = None,
        cloudflare_api_token: Optional[str] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        staging: bool = False
    ) -> Dict[str, Any]:
        """Request a new certificate from Let's Encrypt.

        Args:
            domains: List of domain names
            email: Contact email
            cloudflare_api_token: Cloudflare API token
            key_type: Key type (rsa or ec)
            key_size: Key size for RSA
            staging: Use staging environment

        Returns:
            Result dictionary with certificate data
        """
        try:
            acme_client = self._get_acme_client(email, staging)
            cloudflare = self._get_cloudflare(cloudflare_api_token)
            challenge_handler = CloudflareDNSChallengeHandler(cloudflare)

            private_key_pem, cert_pem, chain_pem = acme_client.request_certificate(
                domains=domains,
                dns_challenge_handler=challenge_handler.create_challenge,
                dns_cleanup_handler=challenge_handler.cleanup_challenge,
                key_type=key_type,
                key_size=key_size
            )

            # Parse certificate info
            cert_info = self.cert_utils.parse_certificate(cert_pem, domains[0])

            return {
                "success": True,
                "message": "Certificate requested successfully",
                "domains": domains,
                "certificate": cert_pem.decode(),
                "private_key": private_key_pem.decode(),
                "chain": chain_pem.decode() if chain_pem else "",
                "cert_info": cert_info.to_dict(),
                "staging": staging
            }
        except Exception as e:
            self.logger.error(f"Failed to request certificate: {e}")
            return {
                "success": False,
                "message": str(e),
                "domains": domains
            }

    async def request_and_install(
        self,
        device_id: str,
        domains: List[str],
        cert_name: str,
        email: Optional[str] = None,
        cloudflare_api_token: Optional[str] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        staging: bool = False
    ) -> Dict[str, Any]:
        """Request a certificate and install it on a device.

        Args:
            device_id: Device to install certificate on
            domains: List of domain names
            cert_name: Name for the certificate
            email: Contact email
            cloudflare_api_token: Cloudflare API token
            key_type: Key type
            key_size: Key size
            staging: Use staging environment

        Returns:
            Result dictionary
        """
        # Request certificate
        cert_result = await self.request_certificate(
            domains=domains,
            email=email,
            cloudflare_api_token=cloudflare_api_token,
            key_type=key_type,
            key_size=key_size,
            staging=staging
        )

        if not cert_result.get("success"):
            return cert_result

        # Install on device
        return await self.import_certificate(
            device_id=device_id,
            cert_name=cert_name,
            cert_pem=cert_result["certificate"].encode(),
            key_pem=cert_result["private_key"].encode(),
            chain_pem=cert_result["chain"].encode() if cert_result["chain"] else None
        )

    async def import_certificate(
        self,
        device_id: str,
        cert_name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Import a certificate to a device.

        Args:
            device_id: Device identifier
            cert_name: Certificate name
            cert_pem: PEM-encoded certificate
            key_pem: PEM-encoded private key
            chain_pem: Optional PEM-encoded chain

        Returns:
            Result dictionary
        """
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        try:
            result = await handler.import_certificate(
                cert_name=cert_name,
                cert_pem=cert_pem,
                key_pem=key_pem,
                chain_pem=chain_pem
            )
            return result
        except Exception as e:
            self.logger.error(f"Failed to import certificate to {device_id}: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "message": str(e)
            }

    async def import_ca_certificate(
        self,
        device_id: str,
        cert_name: str,
        cert_pem: bytes
    ) -> Dict[str, Any]:
        """Import a CA certificate to a device.

        Args:
            device_id: Device identifier
            cert_name: Certificate name
            cert_pem: PEM-encoded CA certificate

        Returns:
            Result dictionary
        """
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        try:
            result = await handler.import_ca_certificate(
                cert_name=cert_name,
                cert_pem=cert_pem
            )
            return result
        except NotImplementedError:
            return {
                "success": False,
                "device_id": device_id,
                "message": f"CA certificate import not supported for {handler.DEVICE_TYPE}"
            }
        except Exception as e:
            self.logger.error(f"Failed to import CA certificate to {device_id}: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "message": str(e)
            }

    async def replace_certificate(
        self,
        device_id: str,
        cert_name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Replace an existing certificate on a device.

        Args:
            device_id: Device identifier
            cert_name: Certificate name to replace
            cert_pem: New PEM-encoded certificate
            key_pem: New PEM-encoded private key
            chain_pem: Optional new PEM-encoded chain

        Returns:
            Result dictionary
        """
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        try:
            result = await handler.replace_certificate(
                cert_name=cert_name,
                cert_pem=cert_pem,
                key_pem=key_pem,
                chain_pem=chain_pem
            )
            return result
        except Exception as e:
            self.logger.error(f"Failed to replace certificate on {device_id}: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "message": str(e)
            }

    async def delete_certificate(
        self,
        device_id: str,
        cert_name: str
    ) -> Dict[str, Any]:
        """Delete a certificate from a device.

        Args:
            device_id: Device identifier
            cert_name: Certificate name to delete

        Returns:
            Result dictionary
        """
        handler = self.device_manager.get_handler(device_id)
        if not handler:
            return {
                "success": False,
                "message": f"Device {device_id} not found"
            }

        try:
            result = await handler.delete_certificate(cert_name)
            return result
        except Exception as e:
            self.logger.error(f"Failed to delete certificate from {device_id}: {e}")
            return {
                "success": False,
                "device_id": device_id,
                "message": str(e)
            }

    async def delete_certificate_batch(
        self,
        device_ids: List[str],
        cert_name: str
    ) -> Dict[str, Any]:
        """Delete a certificate from multiple devices.

        Args:
            device_ids: List of device identifiers
            cert_name: Certificate name to delete

        Returns:
            Result dictionary with per-device results
        """
        results = {}
        success_count = 0
        fail_count = 0

        for device_id in device_ids:
            result = await self.delete_certificate(device_id, cert_name)
            results[device_id] = result
            if result.get("success"):
                success_count += 1
            else:
                fail_count += 1

        return {
            "success": fail_count == 0,
            "message": f"Deleted from {success_count}/{len(device_ids)} devices",
            "cert_name": cert_name,
            "results": results,
            "success_count": success_count,
            "fail_count": fail_count
        }

    async def copy_certificate(
        self,
        source_device_id: str,
        target_device_id: str,
        cert_name: str,
        target_cert_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Copy a certificate from one device to another.

        Note: This requires the source device to support certificate export,
        which may not be available on all device types.

        Args:
            source_device_id: Source device identifier
            target_device_id: Target device identifier
            cert_name: Certificate name on source
            target_cert_name: Certificate name on target (defaults to same name)

        Returns:
            Result dictionary
        """
        # This operation is limited because we can't export private keys from most devices
        return {
            "success": False,
            "message": "Certificate copy between devices is not supported for security reasons. "
                      "Private keys cannot be exported from most device types. "
                      "Use request_and_install to create a new certificate for each device."
        }

    async def check_expiry(
        self,
        device_id: str,
        cert_name: str,
        days_threshold: int = 30
    ) -> Dict[str, Any]:
        """Check certificate expiry status.

        Args:
            device_id: Device identifier
            cert_name: Certificate name
            days_threshold: Days before expiry to warn

        Returns:
            Expiry status dictionary
        """
        cert_result = await self.device_manager.get_certificate(device_id, cert_name)
        if not cert_result.get("success"):
            return cert_result

        cert = cert_result.get("certificate", {})
        days_remaining = cert.get("days_remaining", 0)

        if days_remaining < 0:
            status = "expired"
        elif days_remaining <= days_threshold:
            status = "expiring_soon"
        else:
            status = "valid"

        return {
            "success": True,
            "device_id": device_id,
            "cert_name": cert_name,
            "status": status,
            "days_remaining": days_remaining,
            "threshold_days": days_threshold,
            "expiry_date": cert.get("not_valid_after")
        }

    async def check_all_expiring(
        self,
        days_threshold: int = 30
    ) -> Dict[str, Any]:
        """Find all expiring certificates across all devices.

        Args:
            days_threshold: Days before expiry to include

        Returns:
            Dictionary with list of expiring certificates
        """
        expiring = []
        devices = self.device_manager.list_devices()

        for device in devices:
            device_id = device["device_id"]
            certs_result = await self.device_manager.list_certificates(device_id)

            if certs_result.get("success"):
                for cert in certs_result.get("certificates", []):
                    days_remaining = cert.get("days_remaining", 999)
                    if days_remaining <= days_threshold:
                        expiring.append({
                            "device_id": device_id,
                            "device_type": device.get("device_type"),
                            "cert_name": cert.get("name"),
                            "days_remaining": days_remaining,
                            "status": cert.get("status"),
                            "expiry_date": cert.get("not_valid_after")
                        })

        # Sort by days remaining
        expiring.sort(key=lambda x: x.get("days_remaining", 999))

        return {
            "success": True,
            "threshold_days": days_threshold,
            "expiring_count": len(expiring),
            "expiring_certificates": expiring
        }

    async def renew_certificate(
        self,
        device_id: str,
        cert_name: str,
        domains: Optional[List[str]] = None,
        email: Optional[str] = None,
        cloudflare_api_token: Optional[str] = None,
        staging: bool = False
    ) -> Dict[str, Any]:
        """Renew a certificate on a device.

        Args:
            device_id: Device identifier
            cert_name: Certificate name to renew
            domains: Domains for the new cert (if not provided, uses existing)
            email: Contact email
            cloudflare_api_token: Cloudflare API token
            staging: Use staging environment

        Returns:
            Result dictionary
        """
        # Get existing certificate to get domains if not provided
        if not domains:
            cert_result = await self.device_manager.get_certificate(device_id, cert_name)
            if not cert_result.get("success"):
                return cert_result

            cert = cert_result.get("certificate", {})
            domains = cert.get("domains", [])

            if not domains:
                return {
                    "success": False,
                    "message": "Could not determine domains from existing certificate. Please specify domains."
                }

        # Request new certificate and install
        return await self.request_and_install(
            device_id=device_id,
            domains=domains,
            cert_name=cert_name,
            email=email,
            cloudflare_api_token=cloudflare_api_token,
            staging=staging
        )

    async def auto_renew_check(
        self,
        days_threshold: int = 30,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Check for expiring certificates and optionally renew them.

        Args:
            days_threshold: Days before expiry to renew
            dry_run: If True, only report what would be renewed

        Returns:
            Result dictionary with renewal actions/results
        """
        expiring = await self.check_all_expiring(days_threshold)
        expiring_certs = expiring.get("expiring_certificates", [])

        actions = []
        for cert in expiring_certs:
            action = {
                "device_id": cert["device_id"],
                "cert_name": cert["cert_name"],
                "days_remaining": cert["days_remaining"],
                "action": "would_renew" if dry_run else "pending"
            }

            if not dry_run:
                # Attempt renewal
                result = await self.renew_certificate(
                    device_id=cert["device_id"],
                    cert_name=cert["cert_name"]
                )
                action["action"] = "renewed" if result.get("success") else "failed"
                action["result"] = result

            actions.append(action)

        return {
            "success": True,
            "dry_run": dry_run,
            "threshold_days": days_threshold,
            "certificates_checked": len(expiring_certs),
            "actions": actions
        }

    def list_cloudflare_zones(
        self,
        api_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """List Cloudflare DNS zones.

        Args:
            api_token: Optional Cloudflare API token override

        Returns:
            Result dictionary with zones list
        """
        try:
            cloudflare = self._get_cloudflare(api_token)
            zones = cloudflare.list_zones()
            return {
                "success": True,
                "zones": zones,
                "count": len(zones)
            }
        except Exception as e:
            return {
                "success": False,
                "message": str(e),
                "zones": []
            }

    def verify_cloudflare_token(
        self,
        api_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verify Cloudflare API token.

        Args:
            api_token: Optional Cloudflare API token override

        Returns:
            Verification result dictionary
        """
        try:
            cloudflare = self._get_cloudflare(api_token)
            result = cloudflare.verify_token()
            return {
                "success": True,
                **result
            }
        except Exception as e:
            return {
                "success": False,
                "valid": False,
                "message": str(e)
            }

    def get_acme_account_info(
        self,
        email: Optional[str] = None,
        staging: bool = False
    ) -> Dict[str, Any]:
        """Get ACME account information.

        Args:
            email: Contact email
            staging: Use staging environment

        Returns:
            Account info dictionary
        """
        try:
            acme_client = self._get_acme_client(email, staging)
            info = acme_client.get_account_info()
            return {
                "success": True,
                **info
            }
        except Exception as e:
            return {
                "success": False,
                "message": str(e)
            }
