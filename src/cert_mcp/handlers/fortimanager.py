"""FortiManager device handler using JSON-RPC API."""

import base64
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import httpx

from .base import DeviceHandler, CertificateInfo
from ..config.models import FortiManagerDeviceConfig


class FortiManagerHandler(DeviceHandler):
    """Handler for FortiManager devices using JSON-RPC API."""

    DEVICE_TYPE = "fortimanager"

    def __init__(self, device_id: str, config: FortiManagerDeviceConfig):
        """Initialize FortiManager handler.

        Args:
            device_id: Unique device identifier
            config: FortiManager device configuration
        """
        super().__init__(device_id, config.model_dump())
        self.host = config.host
        self.port = config.port
        self.api_token = config.api_token
        self.username = config.username
        self.password = config.password
        self.adom = config.adom
        self.verify_ssl = config.verify_ssl
        self.timeout = config.timeout

        self._base_url = f"https://{self.host}:{self.port}/jsonrpc"
        self._session_token: Optional[str] = None
        self._request_id = 0

    async def _login(self) -> str:
        """Login and get session token."""
        if self._session_token:
            return self._session_token

        if self.api_token:
            self._session_token = self.api_token
            return self._session_token

        # Login with username/password
        payload = {
            "method": "exec",
            "params": [
                {
                    "url": "/sys/login/user",
                    "data": {
                        "user": self.username,
                        "passwd": self.password
                    }
                }
            ],
            "id": self._get_request_id()
        }

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            response = await client.post(self._base_url, json=payload)
            result = response.json()

            if result.get("result", [{}])[0].get("status", {}).get("code") != 0:
                raise Exception(f"Login failed: {result}")

            self._session_token = result.get("session")
            return self._session_token

    async def _logout(self) -> None:
        """Logout and invalidate session."""
        if not self._session_token or self.api_token:
            return

        payload = {
            "method": "exec",
            "params": [{"url": "/sys/logout"}],
            "session": self._session_token,
            "id": self._get_request_id()
        }

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
                await client.post(self._base_url, json=payload)
        finally:
            self._session_token = None

    def _get_request_id(self) -> int:
        """Get next request ID."""
        self._request_id += 1
        return self._request_id

    async def _make_request(
        self,
        method: str,
        url: str,
        data: Optional[dict] = None
    ) -> dict:
        """Make JSON-RPC request to FortiManager."""
        session = await self._login()

        payload = {
            "method": method,
            "params": [{"url": url}],
            "session": session,
            "id": self._get_request_id()
        }

        if data:
            payload["params"][0]["data"] = data

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            response = await client.post(self._base_url, json=payload)
            result = response.json()

            status = result.get("result", [{}])[0].get("status", {})
            if status.get("code") != 0:
                raise Exception(f"FortiManager API error: {status.get('message', 'Unknown error')}")

            return result.get("result", [{}])[0]

    async def test_connection(self) -> bool:
        """Test connection to FortiManager."""
        try:
            await self._login()
            result = await self._make_request("get", "/sys/status")
            return bool(result.get("data"))
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    async def list_certificates(self) -> List[CertificateInfo]:
        """List certificates on FortiManager."""
        try:
            result = await self._make_request(
                "get",
                f"/pm/config/adom/{self.adom}/_cert/certificate/local"
            )

            certs = []
            for cert_data in result.get("data", []):
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
                "get",
                f"/pm/config/adom/{self.adom}/_cert/certificate/local/{cert_name}"
            )
            data = result.get("data")
            if data:
                return self._parse_certificate_data(data)
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
        """Import a certificate to FortiManager."""
        try:
            full_cert = cert_pem
            if chain_pem:
                if not full_cert.endswith(b"\n"):
                    full_cert += b"\n"
                full_cert += chain_pem

            cert_content = base64.b64encode(full_cert).decode()
            key_content = base64.b64encode(key_pem).decode()

            data = {
                "name": cert_name,
                "certificate": cert_content,
                "private-key": key_content
            }

            result = await self._make_request(
                "add",
                f"/pm/config/adom/{self.adom}/_cert/certificate/local",
                data=data
            )

            return self._format_result(
                success=True,
                message="Certificate imported successfully",
                data={"cert_name": cert_name}
            )
        except Exception as e:
            self.logger.error(f"Failed to import certificate: {e}")
            return self._format_result(False, str(e))

    async def delete_certificate(self, cert_name: str) -> Dict[str, Any]:
        """Delete a certificate from FortiManager."""
        try:
            await self._make_request(
                "delete",
                f"/pm/config/adom/{self.adom}/_cert/certificate/local/{cert_name}"
            )

            return self._format_result(
                success=True,
                message=f"Certificate {cert_name} deleted",
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
        """Replace a certificate on FortiManager."""
        try:
            full_cert = cert_pem
            if chain_pem:
                if not full_cert.endswith(b"\n"):
                    full_cert += b"\n"
                full_cert += chain_pem

            cert_content = base64.b64encode(full_cert).decode()
            key_content = base64.b64encode(key_pem).decode()

            data = {
                "name": cert_name,
                "certificate": cert_content,
                "private-key": key_content
            }

            result = await self._make_request(
                "update",
                f"/pm/config/adom/{self.adom}/_cert/certificate/local/{cert_name}",
                data=data
            )

            return self._format_result(
                success=True,
                message="Certificate replaced successfully",
                data={"cert_name": cert_name}
            )
        except Exception as e:
            self.logger.error(f"Failed to replace certificate: {e}")
            return self._format_result(False, str(e))

    async def list_managed_devices(self) -> List[Dict[str, Any]]:
        """List FortiGate devices managed by this FortiManager."""
        try:
            result = await self._make_request(
                "get",
                f"/dvmdb/adom/{self.adom}/device"
            )

            devices = []
            for device in result.get("data", []):
                devices.append({
                    "name": device.get("name"),
                    "serial": device.get("sn"),
                    "ip": device.get("ip"),
                    "platform": device.get("platform_str"),
                    "version": device.get("os_ver"),
                    "connection_status": device.get("conn_status"),
                    "ha_mode": device.get("ha_mode"),
                })

            return devices
        except Exception as e:
            self.logger.error(f"Failed to list managed devices: {e}")
            return []

    async def push_certificate_to_device(
        self,
        cert_name: str,
        device_name: str
    ) -> Dict[str, Any]:
        """Push a certificate to a managed FortiGate device."""
        try:
            # This requires an install task
            data = {
                "adom": self.adom,
                "scope": [{"name": device_name, "vdom": "global"}],
                "flags": ["install_chg"]
            }

            result = await self._make_request(
                "exec",
                "/securityconsole/install/device",
                data=data
            )

            task_id = result.get("data", {}).get("task")
            return self._format_result(
                success=True,
                message=f"Certificate push initiated to {device_name}",
                data={"task_id": task_id, "device": device_name}
            )
        except Exception as e:
            self.logger.error(f"Failed to push certificate: {e}")
            return self._format_result(False, str(e))

    async def get_certificates_from_managed_device(
        self,
        device_name: str
    ) -> List[CertificateInfo]:
        """Get certificates from a managed FortiGate device."""
        try:
            result = await self._make_request(
                "get",
                f"/pm/config/device/{device_name}/global/vpn/certificate/local"
            )

            certs = []
            for cert_data in result.get("data", []):
                cert_info = self._parse_certificate_data(cert_data)
                if cert_info:
                    certs.append(cert_info)

            return certs
        except Exception as e:
            self.logger.error(f"Failed to get certificates from {device_name}: {e}")
            return []

    async def get_device_info(self) -> Dict[str, Any]:
        """Get FortiManager device information."""
        try:
            result = await self._make_request("get", "/sys/status")
            status = result.get("data", {})

            return {
                "device_id": self.device_id,
                "device_type": self.DEVICE_TYPE,
                "host": self.host,
                "adom": self.adom,
                "hostname": status.get("Hostname"),
                "serial": status.get("Serial Number"),
                "version": status.get("Version"),
                "platform": status.get("Platform Type"),
            }
        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return await super().get_device_info()

    def _parse_certificate_data(self, cert_data: dict) -> Optional[CertificateInfo]:
        """Parse FortiManager certificate data into CertificateInfo."""
        try:
            name = cert_data.get("name", "unknown")
            now = datetime.now(timezone.utc)

            # Parse dates if available
            not_before_str = cert_data.get("not-before", "")
            not_after_str = cert_data.get("not-after", "")

            try:
                not_valid_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
            except:
                not_valid_before = datetime.min.replace(tzinfo=timezone.utc)

            try:
                not_valid_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
            except:
                not_valid_after = datetime.max.replace(tzinfo=timezone.utc)

            days_remaining = (not_valid_after - now).days

            if now < not_valid_before:
                status = "not_yet_valid"
            elif now > not_valid_after:
                status = "expired"
            elif days_remaining <= 30:
                status = "expiring_soon"
            else:
                status = "valid"

            return CertificateInfo(
                name=name,
                subject=cert_data.get("subject", ""),
                issuer=cert_data.get("issuer", ""),
                serial_number=cert_data.get("serial", ""),
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                domains=[],
                fingerprint=cert_data.get("fingerprint", ""),
                key_type="",
                key_size=0,
                is_ca=False,
                days_remaining=days_remaining,
                status=status,
                raw_data=cert_data
            )
        except Exception as e:
            self.logger.error(f"Failed to parse certificate data: {e}")
            return None
