"""FortiGate device handler using REST API."""

import base64
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import httpx

from .base import DeviceHandler, CertificateInfo
from ..config.models import FortiGateDeviceConfig


class FortiGateHandler(DeviceHandler):
    """Handler for FortiGate devices using REST API."""

    DEVICE_TYPE = "fortigate"

    def __init__(self, device_id: str, config: FortiGateDeviceConfig):
        """Initialize FortiGate handler.

        Args:
            device_id: Unique device identifier
            config: FortiGate device configuration
        """
        super().__init__(device_id, config.model_dump())
        self.host = config.host
        self.port = config.port
        self.api_token = config.api_token
        self.username = config.username
        self.password = config.password
        self.vdom = config.vdom
        self.verify_ssl = config.verify_ssl
        self.timeout = config.timeout

        self._base_url = f"https://{self.host}:{self.port}"
        self._session_token: Optional[str] = None

    def _get_headers(self) -> dict:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        params: Optional[dict] = None
    ) -> dict:
        """Make API request to FortiGate."""
        url = f"{self._base_url}{endpoint}"

        # Add vdom parameter
        if params is None:
            params = {}
        if self.vdom:
            params["vdom"] = self.vdom

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            if method == "GET":
                response = await client.get(url, headers=self._get_headers(), params=params)
            elif method == "POST":
                response = await client.post(
                    url, headers=self._get_headers(), json=data, params=params
                )
            elif method == "PUT":
                response = await client.put(
                    url, headers=self._get_headers(), json=data, params=params
                )
            elif method == "DELETE":
                response = await client.delete(url, headers=self._get_headers(), params=params)
            else:
                raise ValueError(f"Unsupported method: {method}")

            if response.status_code >= 400:
                error_detail = response.text
                raise Exception(f"FortiGate API error ({response.status_code}): {error_detail}")

            return response.json()

    async def test_connection(self) -> bool:
        """Test connection to FortiGate."""
        try:
            result = await self._make_request("GET", "/api/v2/monitor/system/status")
            return result.get("status") == "success" or "results" in result
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    async def list_certificates(self) -> List[CertificateInfo]:
        """List local certificates on FortiGate."""
        try:
            result = await self._make_request(
                "GET", "/api/v2/monitor/vpn-certificate/local"
            )
            certs = []

            for cert_data in result.get("results", []):
                cert_info = self._parse_certificate_data(cert_data)
                if cert_info:
                    certs.append(cert_info)

            return certs
        except Exception as e:
            self.logger.error(f"Failed to list certificates: {e}")
            return []

    async def get_certificate(self, cert_name: str) -> Optional[CertificateInfo]:
        """Get details of a specific certificate."""
        try:
            result = await self._make_request(
                "GET", f"/api/v2/monitor/vpn-certificate/local?mkey={cert_name}"
            )
            results = result.get("results", [])
            if results:
                return self._parse_certificate_data(results[0])
            return None
        except Exception as e:
            self.logger.error(f"Failed to get certificate {cert_name}: {e}")
            return None

    async def import_certificate(
        self,
        cert_name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Import a certificate to FortiGate."""
        try:
            # Combine cert with chain if provided
            full_cert = cert_pem
            if chain_pem:
                if not full_cert.endswith(b"\n"):
                    full_cert += b"\n"
                full_cert += chain_pem

            # FortiGate expects base64 encoded content
            cert_content = base64.b64encode(full_cert).decode()
            key_content = base64.b64encode(key_pem).decode()

            data = {
                "type": "local",
                "certname": cert_name,
                "file_content": cert_content,
                "key_file_content": key_content,
                "scope": "global"
            }

            result = await self._make_request(
                "POST",
                "/api/v2/monitor/vpn-certificate/local/import",
                data=data
            )

            success = result.get("status") == "success"
            return self._format_result(
                success=success,
                message="Certificate imported successfully" if success else "Import failed",
                data={"cert_name": cert_name, "response": result}
            )
        except Exception as e:
            self.logger.error(f"Failed to import certificate: {e}")
            return self._format_result(False, str(e))

    async def delete_certificate(self, cert_name: str) -> Dict[str, Any]:
        """Delete a certificate from FortiGate."""
        try:
            result = await self._make_request(
                "DELETE",
                f"/api/v2/cmdb/vpn.certificate/local/{cert_name}"
            )

            success = result.get("status") == "success"
            return self._format_result(
                success=success,
                message=f"Certificate {cert_name} deleted" if success else "Delete failed",
                data={"cert_name": cert_name}
            )
        except Exception as e:
            self.logger.error(f"Failed to delete certificate: {e}")
            return self._format_result(False, str(e))

    async def replace_certificate(
        self,
        cert_name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Replace a certificate on FortiGate."""
        # FortiGate doesn't have a direct replace - delete and re-import
        delete_result = await self.delete_certificate(cert_name)
        if not delete_result.get("success"):
            # Certificate might not exist, proceed with import anyway
            self.logger.warning(f"Delete before replace failed: {delete_result.get('message')}")

        return await self.import_certificate(cert_name, cert_pem, key_pem, chain_pem)

    async def import_ca_certificate(
        self,
        cert_name: str,
        cert_pem: bytes
    ) -> Dict[str, Any]:
        """Import a CA certificate to FortiGate."""
        try:
            cert_content = base64.b64encode(cert_pem).decode()

            data = {
                "type": "ca",
                "certname": cert_name,
                "file_content": cert_content,
                "scope": "global"
            }

            result = await self._make_request(
                "POST",
                "/api/v2/monitor/vpn-certificate/ca/import",
                data=data
            )

            success = result.get("status") == "success"
            return self._format_result(
                success=success,
                message="CA certificate imported successfully" if success else "Import failed",
                data={"cert_name": cert_name, "response": result}
            )
        except Exception as e:
            self.logger.error(f"Failed to import CA certificate: {e}")
            return self._format_result(False, str(e))

    async def get_device_info(self) -> Dict[str, Any]:
        """Get FortiGate device information."""
        try:
            result = await self._make_request("GET", "/api/v2/monitor/system/status")
            status = result.get("results", {})

            return {
                "device_id": self.device_id,
                "device_type": self.DEVICE_TYPE,
                "host": self.host,
                "vdom": self.vdom,
                "hostname": status.get("hostname"),
                "serial": status.get("serial"),
                "version": status.get("version"),
                "model": status.get("model"),
            }
        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return await super().get_device_info()

    def _parse_certificate_data(self, cert_data: dict) -> Optional[CertificateInfo]:
        """Parse FortiGate certificate data into CertificateInfo."""
        try:
            name = cert_data.get("name", "unknown")

            # Parse dates
            not_before = cert_data.get("not_before")
            not_after = cert_data.get("not_after")

            if not_before:
                not_valid_before = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            else:
                not_valid_before = datetime.min.replace(tzinfo=timezone.utc)

            if not_after:
                not_valid_after = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            else:
                not_valid_after = datetime.max.replace(tzinfo=timezone.utc)

            # Calculate days remaining
            now = datetime.now(timezone.utc)
            days_remaining = (not_valid_after - now).days

            # Determine status
            if now < not_valid_before:
                status = "not_yet_valid"
            elif now > not_valid_after:
                status = "expired"
            elif days_remaining <= 30:
                status = "expiring_soon"
            else:
                status = "valid"

            # Get domains from SAN
            domains = []
            san = cert_data.get("subjectAlternativeName", "")
            if san:
                for entry in san.split(", "):
                    if entry.startswith("DNS:"):
                        domains.append(entry[4:])

            return CertificateInfo(
                name=name,
                subject=cert_data.get("subject", ""),
                issuer=cert_data.get("issuer", ""),
                serial_number=cert_data.get("serial", ""),
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                domains=domains,
                fingerprint=cert_data.get("fingerprint", ""),
                key_type=cert_data.get("key_type", ""),
                key_size=cert_data.get("key_size", 0),
                is_ca=cert_data.get("is_ca", False),
                days_remaining=days_remaining,
                status=status,
                raw_data=cert_data
            )
        except Exception as e:
            self.logger.error(f"Failed to parse certificate data: {e}")
            return None
