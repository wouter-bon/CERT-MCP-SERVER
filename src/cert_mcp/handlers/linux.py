"""Linux device handler using SSH."""

import base64
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pathlib import Path

import paramiko

from .base import DeviceHandler, CertificateInfo
from ..config.models import LinuxDeviceConfig


class LinuxHandler(DeviceHandler):
    """Handler for Linux devices using SSH."""

    DEVICE_TYPE = "linux"

    # Default certificate paths for common services
    SERVICE_PATHS = {
        "nginx": {
            "cert_path": "/etc/nginx/ssl/{name}.crt",
            "key_path": "/etc/nginx/ssl/{name}.key",
            "chain_path": "/etc/nginx/ssl/{name}.chain.crt",
            "reload_command": "systemctl reload nginx",
            "search_paths": ["/etc/nginx/ssl", "/etc/ssl/certs", "/etc/pki/tls/certs"]
        },
        "apache": {
            "cert_path": "/etc/apache2/ssl/{name}.crt",
            "key_path": "/etc/apache2/ssl/{name}.key",
            "chain_path": "/etc/apache2/ssl/{name}.chain.crt",
            "reload_command": "systemctl reload apache2",
            "search_paths": ["/etc/apache2/ssl", "/etc/ssl/certs", "/etc/pki/tls/certs"]
        },
        "haproxy": {
            "cert_path": "/etc/haproxy/certs/{name}.pem",
            "key_path": None,  # HAProxy uses combined PEM
            "chain_path": None,
            "reload_command": "systemctl reload haproxy",
            "search_paths": ["/etc/haproxy/certs"]
        },
        "generic": {
            "cert_path": "/etc/ssl/certs/{name}.crt",
            "key_path": "/etc/ssl/private/{name}.key",
            "chain_path": "/etc/ssl/certs/{name}.chain.crt",
            "reload_command": None,
            "search_paths": ["/etc/ssl/certs", "/etc/ssl/private", "/etc/pki/tls/certs"]
        }
    }

    def __init__(self, device_id: str, config: LinuxDeviceConfig):
        """Initialize Linux handler.

        Args:
            device_id: Unique device identifier
            config: Linux device configuration
        """
        super().__init__(device_id, config.model_dump())
        self.host = config.host
        self.port = config.port
        self.username = config.username
        self.password = config.password
        self.ssh_key_path = config.ssh_key_path
        self.service_type = config.service_type

        # Custom paths override defaults
        self.cert_path = config.cert_path
        self.key_path = config.key_path
        self.chain_path = config.chain_path
        self.reload_command = config.reload_command

        # Get service defaults
        self.service_config = self.SERVICE_PATHS.get(self.service_type, self.SERVICE_PATHS["generic"])

    def _get_ssh_client(self) -> paramiko.SSHClient:
        """Create and connect SSH client."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
        }

        if self.ssh_key_path:
            key_path = Path(self.ssh_key_path).expanduser()
            connect_kwargs["key_filename"] = str(key_path)
        elif self.password:
            connect_kwargs["password"] = self.password

        client.connect(**connect_kwargs)
        return client

    def _run_command(self, command: str) -> Dict[str, Any]:
        """Run command via SSH."""
        client = self._get_ssh_client()
        try:
            stdin, stdout, stderr = client.exec_command(command)
            return {
                "exit_code": stdout.channel.recv_exit_status(),
                "stdout": stdout.read().decode("utf-8", errors="replace"),
                "stderr": stderr.read().decode("utf-8", errors="replace")
            }
        finally:
            client.close()

    def _get_cert_path(self, cert_name: str) -> str:
        """Get certificate file path."""
        if self.cert_path:
            return self.cert_path.format(name=cert_name)
        return self.service_config["cert_path"].format(name=cert_name)

    def _get_key_path(self, cert_name: str) -> str:
        """Get private key file path."""
        if self.key_path:
            return self.key_path.format(name=cert_name)
        key_path = self.service_config["key_path"]
        if key_path:
            return key_path.format(name=cert_name)
        # HAProxy combined PEM
        return self._get_cert_path(cert_name)

    def _get_chain_path(self, cert_name: str) -> Optional[str]:
        """Get certificate chain file path."""
        if self.chain_path:
            return self.chain_path.format(name=cert_name)
        chain_path = self.service_config["chain_path"]
        if chain_path:
            return chain_path.format(name=cert_name)
        return None

    def _get_reload_command(self) -> Optional[str]:
        """Get service reload command."""
        if self.reload_command:
            return self.reload_command
        return self.service_config.get("reload_command")

    async def test_connection(self) -> bool:
        """Test SSH connection to Linux host."""
        try:
            result = self._run_command("hostname")
            return result["exit_code"] == 0
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    async def list_certificates(self) -> List[CertificateInfo]:
        """List certificates on Linux host."""
        certs = []
        search_paths = self.service_config.get("search_paths", [])

        for search_path in search_paths:
            try:
                # Find certificate files
                result = self._run_command(
                    f"find {search_path} -name '*.crt' -o -name '*.pem' 2>/dev/null | head -50"
                )

                if result["exit_code"] != 0:
                    continue

                for cert_file in result["stdout"].strip().split("\n"):
                    if not cert_file:
                        continue

                    cert_info = await self._parse_cert_file(cert_file)
                    if cert_info:
                        certs.append(cert_info)

            except Exception as e:
                self.logger.error(f"Error searching {search_path}: {e}")

        return certs

    async def _parse_cert_file(self, cert_path: str) -> Optional[CertificateInfo]:
        """Parse a certificate file on the remote host."""
        try:
            # Use openssl to parse the certificate
            result = self._run_command(
                f"openssl x509 -in {cert_path} -noout "
                f"-subject -issuer -dates -serial -fingerprint -text 2>/dev/null"
            )

            if result["exit_code"] != 0:
                return None

            output = result["stdout"]

            # Parse the openssl output
            def extract_field(prefix: str) -> str:
                for line in output.split("\n"):
                    if line.strip().startswith(prefix):
                        return line.split("=", 1)[-1].strip()
                return ""

            subject = extract_field("subject")
            issuer = extract_field("issuer")
            serial = extract_field("serial")
            fingerprint = extract_field("SHA256 Fingerprint") or extract_field("SHA1 Fingerprint")

            # Parse dates
            not_before_str = extract_field("notBefore")
            not_after_str = extract_field("notAfter")

            def parse_openssl_date(date_str: str) -> datetime:
                if not date_str:
                    return datetime.min.replace(tzinfo=timezone.utc)
                try:
                    # OpenSSL format: "Jun 15 12:00:00 2024 GMT"
                    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                except:
                    return datetime.min.replace(tzinfo=timezone.utc)

            not_valid_before = parse_openssl_date(not_before_str)
            not_valid_after = parse_openssl_date(not_after_str)

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

            # Extract SANs
            domains = []
            if "DNS:" in output:
                for line in output.split("\n"):
                    if "DNS:" in line:
                        for part in line.split(","):
                            if "DNS:" in part:
                                domains.append(part.split("DNS:")[-1].strip())

            # Use filename as name
            name = Path(cert_path).stem

            return CertificateInfo(
                name=name,
                subject=subject,
                issuer=issuer,
                serial_number=serial,
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                domains=domains,
                fingerprint=fingerprint,
                key_type="",
                key_size=0,
                is_ca=False,
                days_remaining=days_remaining,
                status=status,
                raw_data={"path": cert_path}
            )
        except Exception as e:
            self.logger.error(f"Failed to parse {cert_path}: {e}")
            return None

    async def get_certificate(self, cert_name: str) -> Optional[CertificateInfo]:
        """Get details of a specific certificate."""
        cert_path = self._get_cert_path(cert_name)
        return await self._parse_cert_file(cert_path)

    async def import_certificate(
        self,
        cert_name: str,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Import a certificate to Linux host."""
        try:
            cert_path = self._get_cert_path(cert_name)
            key_path = self._get_key_path(cert_name)

            # For HAProxy, combine into single PEM
            if self.service_type == "haproxy":
                combined = cert_pem
                if not combined.endswith(b"\n"):
                    combined += b"\n"
                combined += key_pem
                if chain_pem:
                    if not combined.endswith(b"\n"):
                        combined += b"\n"
                    combined += chain_pem

                cert_b64 = base64.b64encode(combined).decode()

                # Ensure directory exists and write file
                result = self._run_command(
                    f"mkdir -p $(dirname {cert_path}) && "
                    f"echo '{cert_b64}' | base64 -d > {cert_path} && "
                    f"chmod 600 {cert_path}"
                )

                if result["exit_code"] != 0:
                    return self._format_result(False, result["stderr"])

            else:
                # Write certificate and key separately
                cert_b64 = base64.b64encode(cert_pem).decode()
                key_b64 = base64.b64encode(key_pem).decode()

                # Write certificate
                result = self._run_command(
                    f"mkdir -p $(dirname {cert_path}) && "
                    f"echo '{cert_b64}' | base64 -d > {cert_path} && "
                    f"chmod 644 {cert_path}"
                )

                if result["exit_code"] != 0:
                    return self._format_result(False, f"Failed to write certificate: {result['stderr']}")

                # Write private key
                result = self._run_command(
                    f"mkdir -p $(dirname {key_path}) && "
                    f"echo '{key_b64}' | base64 -d > {key_path} && "
                    f"chmod 600 {key_path}"
                )

                if result["exit_code"] != 0:
                    return self._format_result(False, f"Failed to write key: {result['stderr']}")

                # Write chain if provided
                if chain_pem:
                    chain_path = self._get_chain_path(cert_name)
                    if chain_path:
                        chain_b64 = base64.b64encode(chain_pem).decode()
                        result = self._run_command(
                            f"echo '{chain_b64}' | base64 -d > {chain_path} && "
                            f"chmod 644 {chain_path}"
                        )

            # Reload service if configured
            reload_cmd = self._get_reload_command()
            if reload_cmd:
                result = self._run_command(reload_cmd)
                if result["exit_code"] != 0:
                    self.logger.warning(f"Service reload failed: {result['stderr']}")

            return self._format_result(
                success=True,
                message="Certificate imported successfully",
                data={
                    "cert_name": cert_name,
                    "cert_path": cert_path,
                    "key_path": key_path
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to import certificate: {e}")
            return self._format_result(False, str(e))

    async def delete_certificate(self, cert_name: str) -> Dict[str, Any]:
        """Delete a certificate from Linux host."""
        try:
            cert_path = self._get_cert_path(cert_name)
            key_path = self._get_key_path(cert_name)
            chain_path = self._get_chain_path(cert_name)

            files_to_delete = [cert_path]
            if key_path and key_path != cert_path:
                files_to_delete.append(key_path)
            if chain_path:
                files_to_delete.append(chain_path)

            for file_path in files_to_delete:
                result = self._run_command(f"rm -f {file_path}")
                if result["exit_code"] != 0:
                    self.logger.warning(f"Failed to delete {file_path}: {result['stderr']}")

            # Reload service if configured
            reload_cmd = self._get_reload_command()
            if reload_cmd:
                self._run_command(reload_cmd)

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
        """Replace a certificate on Linux host."""
        # Just import - it will overwrite existing files
        return await self.import_certificate(cert_name, cert_pem, key_pem, chain_pem)

    async def get_device_info(self) -> Dict[str, Any]:
        """Get Linux device information."""
        try:
            hostname_result = self._run_command("hostname -f")
            os_result = self._run_command("cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION)=' | head -2")

            hostname = hostname_result["stdout"].strip() if hostname_result["exit_code"] == 0 else "unknown"

            os_info = {}
            if os_result["exit_code"] == 0:
                for line in os_result["stdout"].strip().split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os_info[key] = value.strip('"')

            return {
                "device_id": self.device_id,
                "device_type": self.DEVICE_TYPE,
                "host": self.host,
                "service_type": self.service_type,
                "hostname": hostname,
                "os_name": os_info.get("NAME", "Unknown"),
                "os_version": os_info.get("VERSION", "Unknown"),
            }
        except Exception as e:
            self.logger.error(f"Failed to get device info: {e}")
            return await super().get_device_info()
