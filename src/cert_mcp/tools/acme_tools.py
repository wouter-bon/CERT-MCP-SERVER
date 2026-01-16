"""ACME/Let's Encrypt tools for MCP."""

from typing import Optional, Dict, Any, List

from .base import BaseTool
from ..managers.certificate_manager import CertificateManager


class ACMETools(BaseTool):
    """Tools for ACME/Let's Encrypt operations."""

    def __init__(self, certificate_manager: CertificateManager):
        """Initialize ACME tools.

        Args:
            certificate_manager: CertificateManager instance
        """
        super().__init__("acme")
        self.certificate_manager = certificate_manager

    async def request_certificate(
        self,
        domains: List[str],
        email: Optional[str] = None,
        cloudflare_api_token: Optional[str] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        staging: bool = False
    ) -> Dict[str, Any]:
        """Request a new certificate from Let's Encrypt."""
        return await self.certificate_manager.request_certificate(
            domains=domains,
            email=email,
            cloudflare_api_token=cloudflare_api_token,
            key_type=key_type,
            key_size=key_size,
            staging=staging
        )

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
        """Request a certificate and install it on a device."""
        return await self.certificate_manager.request_and_install(
            device_id=device_id,
            domains=domains,
            cert_name=cert_name,
            email=email,
            cloudflare_api_token=cloudflare_api_token,
            key_type=key_type,
            key_size=key_size,
            staging=staging
        )

    def list_cloudflare_zones(
        self,
        cloudflare_api_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """List Cloudflare DNS zones."""
        return self.certificate_manager.list_cloudflare_zones(cloudflare_api_token)

    def verify_cloudflare_token(
        self,
        cloudflare_api_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verify Cloudflare API token."""
        return self.certificate_manager.verify_cloudflare_token(cloudflare_api_token)

    def get_acme_account_info(
        self,
        email: Optional[str] = None,
        staging: bool = False
    ) -> Dict[str, Any]:
        """Get ACME account information."""
        return self.certificate_manager.get_acme_account_info(email, staging)
