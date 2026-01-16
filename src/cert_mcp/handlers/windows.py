"""Windows device handler using WinRM/PowerShell."""

import base64
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import winrm

from .base import DeviceHandler, CertificateInfo
from ..config.models import WindowsDeviceConfig


class WindowsHandler(DeviceHandler):
    """Handler for Windows devices using WinRM/PowerShell."""

    DEVICE_TYPE = "windows"

    def __init__(self, device_id: str, config: WindowsDeviceConfig):
        """Initialize Windows handler.

        Args:
            device_id: Unique device identifier
            config: Windows device configuration
        """
        super().__init__(device_id, config.model_dump())
        self.host = config.host
        self.port = config.port
        self.username = config.username
        self.password = config.password
        self.transport = config.transport
        self.verify_ssl = config.verify_ssl
        self.cert_store = config.cert_store

        # Determine protocol based on port
        self.protocol = "https" if self.port == 5986 else "http"
        self._endpoint = f"{self.protocol}://{self.host}:{self.port}/wsman"

    def _get_session(self) -> winrm.Session:
        """Get WinRM session."""
        return winrm.Session(
            self._endpoint,
            auth=(self.username, self.password),
            transport=self.transport,
            server_cert_validation="ignore" if not self.verify_ssl else "validate"
        )

    def _run_powershell(self, script: str) -> Dict[str, Any]:
        """Run PowerShell script on remote Windows host."""
        session = self._get_session()
        result = session.run_ps(script)

        return {
            "status_code": result.status_code,
            "std_out": result.std_out.decode("utf-8", errors="replace"),
            "std_err": result.std_err.decode("utf-8", errors="replace")
        }

    async def test_connection(self) -> bool:
        """Test connection to Windows host."""
        try:
            result = self._run_powershell("$env:COMPUTERNAME")
            return result["status_code"] == 0
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    async def list_certificates(self) -> List[CertificateInfo]:
        """List certificates in the Windows certificate store."""
        script = f'''
$certs = Get-ChildItem -Path "Cert:\\{self.cert_store}" | Select-Object `
    Subject, Issuer, Thumbprint, NotBefore, NotAfter, FriendlyName, `
    @{{Name="SerialNumber";Expression={{$_.SerialNumber}}}}, `
    @{{Name="DnsNameList";Expression={{$_.DnsNameList.Unicode -join ","}}}}

$certs | ConvertTo-Json -Depth 3
'''
        try:
            result = self._run_powershell(script)
            if result["status_code"] != 0:
                self.logger.error(f"Failed to list certificates: {result['std_err']}")
                return []

            import json
            certs_data = json.loads(result["std_out"]) if result["std_out"].strip() else []

            # Handle single certificate (not returned as array)
            if isinstance(certs_data, dict):
                certs_data = [certs_data]

            certs = []
            for cert_data in certs_data:
                cert_info = self._parse_certificate_data(cert_data)
                if cert_info:
                    certs.append(cert_info)

            return certs
        except Exception as e:
            self.logger.error(f"Failed to list certificates: {e}")
            return []

    async def get_certificate(self, cert_name: str) -> Optional[CertificateInfo]:
        """Get details of a specific certificate by thumbprint or friendly name."""
        script = f'''
$cert = Get-ChildItem -Path "Cert:\\{self.cert_store}" | Where-Object {{
    $_.Thumbprint -eq "{cert_name}" -or $_.FriendlyName -eq "{cert_name}"
}} | Select-Object -First 1 `
    Subject, Issuer, Thumbprint, NotBefore, NotAfter, FriendlyName, `
    @{{Name="SerialNumber";Expression={{$_.SerialNumber}}}}, `
    @{{Name="DnsNameList";Expression={{$_.DnsNameList.Unicode -join ","}}}}

if ($cert) {{
    $cert | ConvertTo-Json -Depth 3
}}
'''
        try:
            result = self._run_powershell(script)
            if result["status_code"] != 0 or not result["std_out"].strip():
                return None

            import json
            cert_data = json.loads(result["std_out"])
            return self._parse_certificate_data(cert_data)
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
        """Import a certificate to Windows certificate store."""
        try:
            # Combine cert, key, and chain into PFX
            from cryptography.hazmat.primitives.serialization import pkcs12
            from cryptography.hazmat.primitives import serialization
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            key = serialization.load_pem_private_key(key_pem, password=None, backend=default_backend())

            # Parse chain certificates
            cas = []
            if chain_pem:
                chain_data = chain_pem
                while b"-----BEGIN CERTIFICATE-----" in chain_data:
                    start = chain_data.find(b"-----BEGIN CERTIFICATE-----")
                    end = chain_data.find(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
                    ca_cert_pem = chain_data[start:end]
                    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
                    cas.append(ca_cert)
                    chain_data = chain_data[end:]

            # Create PFX with a temporary password
            temp_password = b"TempCertPassword123!"
            pfx_data = pkcs12.serialize_key_and_certificates(
                name=cert_name.encode(),
                key=key,
                cert=cert,
                cas=cas if cas else None,
                encryption_algorithm=serialization.BestAvailableEncryption(temp_password)
            )

            pfx_base64 = base64.b64encode(pfx_data).decode()

            script = f'''
$pfxBytes = [Convert]::FromBase64String("{pfx_base64}")
$pfxPath = [System.IO.Path]::GetTempFileName() + ".pfx"
[System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

$securePassword = ConvertTo-SecureString -String "TempCertPassword123!" -Force -AsPlainText
$cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\\{self.cert_store}" -Password $securePassword

# Set friendly name
$cert.FriendlyName = "{cert_name}"

Remove-Item $pfxPath -Force

@{{
    "Thumbprint" = $cert.Thumbprint
    "Subject" = $cert.Subject
    "FriendlyName" = $cert.FriendlyName
}} | ConvertTo-Json
'''
            result = self._run_powershell(script)

            if result["status_code"] != 0:
                return self._format_result(False, result["std_err"])

            import json
            cert_info = json.loads(result["std_out"]) if result["std_out"].strip() else {}

            return self._format_result(
                success=True,
                message="Certificate imported successfully",
                data={
                    "cert_name": cert_name,
                    "thumbprint": cert_info.get("Thumbprint"),
                    "subject": cert_info.get("Subject")
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to import certificate: {e}")
            return self._format_result(False, str(e))

    async def delete_certificate(self, cert_name: str) -> Dict[str, Any]:
        """Delete a certificate from Windows certificate store."""
        script = f'''
$cert = Get-ChildItem -Path "Cert:\\{self.cert_store}" | Where-Object {{
    $_.Thumbprint -eq "{cert_name}" -or $_.FriendlyName -eq "{cert_name}"
}}

if ($cert) {{
    $cert | Remove-Item -Force
    @{{ "deleted" = $true; "thumbprint" = $cert.Thumbprint }} | ConvertTo-Json
}} else {{
    @{{ "deleted" = $false; "error" = "Certificate not found" }} | ConvertTo-Json
}}
'''
        try:
            result = self._run_powershell(script)

            if result["status_code"] != 0:
                return self._format_result(False, result["std_err"])

            import json
            delete_result = json.loads(result["std_out"]) if result["std_out"].strip() else {}

            if delete_result.get("deleted"):
                return self._format_result(
                    success=True,
                    message=f"Certificate {cert_name} deleted",
                    data={"thumbprint": delete_result.get("thumbprint")}
                )
            else:
                return self._format_result(False, delete_result.get("error", "Unknown error"))

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
        """Replace a certificate on Windows."""
        # Delete existing certificate first
        delete_result = await self.delete_certificate(cert_name)
        if not delete_result.get("success"):
            self.logger.warning(f"Delete before replace failed: {delete_result.get('message')}")

        # Import new certificate
        return await self.import_certificate(cert_name, cert_pem, key_pem, chain_pem)

    async def get_device_info(self) -> Dict[str, Any]:
        """Get Windows device information."""
        script = '''
@{
    "ComputerName" = $env:COMPUTERNAME
    "Domain" = $env:USERDOMAIN
    "OS" = (Get-CimInstance Win32_OperatingSystem).Caption
    "Version" = (Get-CimInstance Win32_OperatingSystem).Version
} | ConvertTo-Json
'''
        try:
            result = self._run_powershell(script)
            if result["status_code"] == 0:
                import json
                info = json.loads(result["std_out"])
                return {
                    "device_id": self.device_id,
                    "device_type": self.DEVICE_TYPE,
                    "host": self.host,
                    "cert_store": self.cert_store,
                    "computer_name": info.get("ComputerName"),
                    "domain": info.get("Domain"),
                    "os": info.get("OS"),
                    "version": info.get("Version"),
                }
        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")

        return await super().get_device_info()

    def _parse_certificate_data(self, cert_data: dict) -> Optional[CertificateInfo]:
        """Parse Windows certificate data into CertificateInfo."""
        try:
            # Windows returns dates in different formats
            def parse_date(date_str):
                if not date_str:
                    return datetime.min.replace(tzinfo=timezone.utc)
                # Handle /Date(timestamp)/ format
                if date_str.startswith("/Date("):
                    timestamp = int(date_str[6:-2]) / 1000
                    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
                # Try ISO format
                try:
                    return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except:
                    return datetime.min.replace(tzinfo=timezone.utc)

            not_valid_before = parse_date(cert_data.get("NotBefore"))
            not_valid_after = parse_date(cert_data.get("NotAfter"))

            now = datetime.now(timezone.utc)
            days_remaining = (not_valid_after - now).days

            if now < not_valid_before:
                status = "not_yet_valid"
            elif now > not_valid_after:
                status = "expired"
            elif days_remaining <= 30:
                status = "expiring_soon"
            else:
                status = "valid"

            # Parse DNS names
            domains = []
            dns_list = cert_data.get("DnsNameList", "")
            if dns_list:
                domains = [d.strip() for d in dns_list.split(",") if d.strip()]

            name = cert_data.get("FriendlyName") or cert_data.get("Thumbprint", "unknown")

            return CertificateInfo(
                name=name,
                subject=cert_data.get("Subject", ""),
                issuer=cert_data.get("Issuer", ""),
                serial_number=cert_data.get("SerialNumber", ""),
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                domains=domains,
                fingerprint=cert_data.get("Thumbprint", ""),
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
