"""STDIO server implementation for CERT-MCP-SERVER."""

import os
import sys
import signal
from typing import Optional, Annotated, List
from datetime import datetime

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config.loader import load_config
from .config.models import Config
from .core.logging import setup_logging, get_logger
from .managers.device_manager import DeviceManager
from .managers.certificate_manager import CertificateManager
from .tools.device_tools import DeviceTools
from .tools.certificate_tools import CertificateTools
from .tools.acme_tools import ACMETools
from .tools.definitions import *


class CertMCPServer:
    """Main server class for CERT-MCP-SERVER."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        self.logger = setup_logging(self.config.logging)

        # Initialize managers
        self.device_manager = DeviceManager(self.config.devices)
        self.certificate_manager = CertificateManager(
            device_manager=self.device_manager,
            acme_config=self.config.acme,
            cloudflare_api_token=os.environ.get("CLOUDFLARE_API_TOKEN")
        )

        # Initialize tools
        self.device_tools = DeviceTools(self.device_manager)
        self.certificate_tools = CertificateTools(
            self.device_manager, self.certificate_manager
        )
        self.acme_tools = ACMETools(self.certificate_manager)

        # Initialize MCP server
        self.mcp = FastMCP("CertMCP")
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register MCP tools with the server."""

        # === Device Management Tools (6) ===

        @self.mcp.tool(description=LIST_DEVICES_DESC)
        async def list_devices():
            return await self.device_tools.list_devices()

        @self.mcp.tool(description=ADD_DEVICE_DESC)
        async def add_device(
            device_id: Annotated[str, Field(description="Unique device identifier")],
            device_type: Annotated[str, Field(description="Device type (fortigate, fortimanager, fortianalyzer, windows, linux)")],
            host: Annotated[str, Field(description="Device hostname or IP address")],
            port: Annotated[Optional[int], Field(description="Connection port")] = None,
            username: Annotated[Optional[str], Field(description="Username for authentication")] = None,
            password: Annotated[Optional[str], Field(description="Password for authentication")] = None,
            api_token: Annotated[Optional[str], Field(description="API token for authentication")] = None,
            vdom: Annotated[Optional[str], Field(description="FortiGate Virtual Domain")] = None,
            adom: Annotated[Optional[str], Field(description="FortiManager/FortiAnalyzer Administrative Domain")] = None,
            verify_ssl: Annotated[bool, Field(description="Verify SSL certificate")] = False,
            timeout: Annotated[int, Field(description="Connection timeout in seconds")] = 30,
            transport: Annotated[Optional[str], Field(description="WinRM transport type (ntlm, basic, kerberos)")] = None,
            cert_store: Annotated[Optional[str], Field(description="Windows certificate store")] = None,
            ssh_key_path: Annotated[Optional[str], Field(description="Path to SSH private key")] = None,
            service_type: Annotated[Optional[str], Field(description="Linux service type (nginx, apache, haproxy, generic)")] = None
        ):
            return await self.device_tools.add_device(
                device_id=device_id,
                device_type=device_type,
                host=host,
                port=port,
                username=username,
                password=password,
                api_token=api_token,
                vdom=vdom,
                adom=adom,
                verify_ssl=verify_ssl,
                timeout=timeout,
                transport=transport,
                cert_store=cert_store,
                ssh_key_path=ssh_key_path,
                service_type=service_type
            )

        @self.mcp.tool(description=REMOVE_DEVICE_DESC)
        async def remove_device(
            device_id: Annotated[str, Field(description="Device identifier to remove")]
        ):
            return await self.device_tools.remove_device(device_id)

        @self.mcp.tool(description=TEST_DEVICE_CONNECTION_DESC)
        async def test_device_connection(
            device_id: Annotated[str, Field(description="Device identifier")]
        ):
            return await self.device_tools.test_device_connection(device_id)

        @self.mcp.tool(description=GET_DEVICE_INFO_DESC)
        async def get_device_info(
            device_id: Annotated[str, Field(description="Device identifier")]
        ):
            return await self.device_tools.get_device_info(device_id)

        @self.mcp.tool(description=LIST_DEVICES_BY_TYPE_DESC)
        async def list_devices_by_type(
            device_type: Annotated[str, Field(description="Device type to filter by")]
        ):
            return await self.device_tools.list_devices_by_type(device_type)

        # === Certificate Check Tools (5) ===

        @self.mcp.tool(description=LIST_CERTIFICATES_DESC)
        async def list_certificates(
            device_id: Annotated[str, Field(description="Device identifier")]
        ):
            return await self.certificate_tools.list_certificates(device_id)

        @self.mcp.tool(description=GET_CERTIFICATE_DETAIL_DESC)
        async def get_certificate_detail(
            device_id: Annotated[str, Field(description="Device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")]
        ):
            return await self.certificate_tools.get_certificate_detail(device_id, cert_name)

        @self.mcp.tool(description=CHECK_CERTIFICATE_EXPIRY_DESC)
        async def check_certificate_expiry(
            device_id: Annotated[str, Field(description="Device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            days_threshold: Annotated[int, Field(description="Days before expiry to warn")] = 30
        ):
            return await self.certificate_tools.check_certificate_expiry(
                device_id, cert_name, days_threshold
            )

        @self.mcp.tool(description=CHECK_ALL_EXPIRING_DESC)
        async def check_all_expiring(
            days_threshold: Annotated[int, Field(description="Days before expiry to include")] = 30
        ):
            return await self.certificate_tools.check_all_expiring(days_threshold)

        @self.mcp.tool(description=VERIFY_CERTIFICATE_CHAIN_DESC)
        async def verify_certificate_chain(
            certificate: Annotated[str, Field(description="PEM-encoded certificate")],
            chain: Annotated[Optional[str], Field(description="PEM-encoded certificate chain")] = None
        ):
            return await self.certificate_tools.verify_certificate_chain(certificate, chain)

        # === Let's Encrypt Tools (4) ===

        @self.mcp.tool(description=REQUEST_CERTIFICATE_DESC)
        async def request_certificate(
            domains: Annotated[List[str], Field(description="List of domain names")],
            email: Annotated[Optional[str], Field(description="Contact email for Let's Encrypt")] = None,
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None,
            key_type: Annotated[str, Field(description="Key type (rsa or ec)")] = "rsa",
            key_size: Annotated[int, Field(description="Key size for RSA")] = 2048,
            staging: Annotated[bool, Field(description="Use staging environment")] = False
        ):
            return await self.acme_tools.request_certificate(
                domains, email, cloudflare_api_token, key_type, key_size, staging
            )

        @self.mcp.tool(description=LIST_CLOUDFLARE_ZONES_DESC)
        async def list_cloudflare_zones(
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None
        ):
            return self.acme_tools.list_cloudflare_zones(cloudflare_api_token)

        @self.mcp.tool(description=VERIFY_CLOUDFLARE_TOKEN_DESC)
        async def verify_cloudflare_token(
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None
        ):
            return self.acme_tools.verify_cloudflare_token(cloudflare_api_token)

        @self.mcp.tool(description=GET_ACME_ACCOUNT_INFO_DESC)
        async def get_acme_account_info(
            email: Annotated[Optional[str], Field(description="Contact email")] = None,
            staging: Annotated[bool, Field(description="Use staging environment")] = False
        ):
            return self.acme_tools.get_acme_account_info(email, staging)

        # === Certificate Install Tools (4) ===

        @self.mcp.tool(description=IMPORT_CERTIFICATE_DESC)
        async def import_certificate(
            device_id: Annotated[str, Field(description="Device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            certificate: Annotated[str, Field(description="PEM-encoded certificate")],
            private_key: Annotated[str, Field(description="PEM-encoded private key")],
            chain: Annotated[Optional[str], Field(description="PEM-encoded certificate chain")] = None
        ):
            return await self.certificate_tools.import_certificate(
                device_id, cert_name, certificate, private_key, chain
            )

        @self.mcp.tool(description=REQUEST_AND_INSTALL_DESC)
        async def request_and_install(
            device_id: Annotated[str, Field(description="Device identifier")],
            domains: Annotated[List[str], Field(description="List of domain names")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            email: Annotated[Optional[str], Field(description="Contact email")] = None,
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None,
            key_type: Annotated[str, Field(description="Key type (rsa or ec)")] = "rsa",
            key_size: Annotated[int, Field(description="Key size for RSA")] = 2048,
            staging: Annotated[bool, Field(description="Use staging environment")] = False
        ):
            return await self.acme_tools.request_and_install(
                device_id, domains, cert_name, email, cloudflare_api_token,
                key_type, key_size, staging
            )

        @self.mcp.tool(description=IMPORT_CA_CERTIFICATE_DESC)
        async def import_ca_certificate(
            device_id: Annotated[str, Field(description="Device identifier")],
            cert_name: Annotated[str, Field(description="CA certificate name")],
            certificate: Annotated[str, Field(description="PEM-encoded CA certificate")]
        ):
            return await self.certificate_tools.import_ca_certificate(
                device_id, cert_name, certificate
            )

        @self.mcp.tool(description=COPY_CERTIFICATE_DESC)
        async def copy_certificate(
            source_device_id: Annotated[str, Field(description="Source device identifier")],
            target_device_id: Annotated[str, Field(description="Target device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            target_cert_name: Annotated[Optional[str], Field(description="Name on target device")] = None
        ):
            return await self.certificate_tools.copy_certificate(
                source_device_id, target_device_id, cert_name, target_cert_name
            )

        # === Certificate Replace/Renew Tools (3) ===

        @self.mcp.tool(description=REPLACE_CERTIFICATE_DESC)
        async def replace_certificate(
            device_id: Annotated[str, Field(description="Device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            certificate: Annotated[str, Field(description="PEM-encoded certificate")],
            private_key: Annotated[str, Field(description="PEM-encoded private key")],
            chain: Annotated[Optional[str], Field(description="PEM-encoded certificate chain")] = None
        ):
            return await self.certificate_tools.replace_certificate(
                device_id, cert_name, certificate, private_key, chain
            )

        @self.mcp.tool(description=RENEW_CERTIFICATE_DESC)
        async def renew_certificate(
            device_id: Annotated[str, Field(description="Device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            domains: Annotated[Optional[List[str]], Field(description="Domains (uses existing if not provided)")] = None,
            email: Annotated[Optional[str], Field(description="Contact email")] = None,
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None,
            staging: Annotated[bool, Field(description="Use staging environment")] = False
        ):
            return await self.certificate_tools.renew_certificate(
                device_id, cert_name, domains, email, cloudflare_api_token, staging
            )

        @self.mcp.tool(description=AUTO_RENEW_CHECK_DESC)
        async def auto_renew_check(
            days_threshold: Annotated[int, Field(description="Days before expiry to renew")] = 30,
            dry_run: Annotated[bool, Field(description="Preview without renewing")] = True
        ):
            return await self.certificate_tools.auto_renew_check(days_threshold, dry_run)

        # === Certificate Delete Tools (2) ===

        @self.mcp.tool(description=DELETE_CERTIFICATE_DESC)
        async def delete_certificate(
            device_id: Annotated[str, Field(description="Device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")]
        ):
            return await self.certificate_tools.delete_certificate(device_id, cert_name)

        @self.mcp.tool(description=DELETE_CERTIFICATE_BATCH_DESC)
        async def delete_certificate_batch(
            device_ids: Annotated[List[str], Field(description="List of device identifiers")],
            cert_name: Annotated[str, Field(description="Certificate name")]
        ):
            return await self.certificate_tools.delete_certificate_batch(device_ids, cert_name)

        # === FortiManager-Specific Tools (4) ===

        @self.mcp.tool(description=FMG_LIST_MANAGED_DEVICES_DESC)
        async def fmg_list_managed_devices(
            device_id: Annotated[str, Field(description="FortiManager device identifier")]
        ):
            return await self.certificate_tools.fmg_list_managed_devices(device_id)

        @self.mcp.tool(description=FMG_GET_CERTIFICATES_ALL_DESC)
        async def fmg_get_certificates_all(
            device_id: Annotated[str, Field(description="FortiManager device identifier")]
        ):
            return await self.certificate_tools.fmg_get_certificates_all(device_id)

        @self.mcp.tool(description=FMG_PUSH_CERTIFICATE_DESC)
        async def fmg_push_certificate(
            device_id: Annotated[str, Field(description="FortiManager device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            target_devices: Annotated[List[str], Field(description="List of target FortiGate names")]
        ):
            return await self.certificate_tools.fmg_push_certificate(
                device_id, cert_name, target_devices
            )

        @self.mcp.tool(description=FMG_CHECK_CERTIFICATE_STATUS_DESC)
        async def fmg_check_certificate_status(
            device_id: Annotated[str, Field(description="FortiManager device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")]
        ):
            return await self.certificate_tools.fmg_check_certificate_status(device_id, cert_name)

        # === System Tools (2) ===

        @self.mcp.tool(description=HEALTH_CHECK_DESC)
        async def health_check():
            return {
                "status": "healthy",
                "server_name": self.config.server.name,
                "server_version": self.config.server.version,
                "registered_devices": self.device_manager.get_device_count(),
                "device_types": self.device_manager.get_device_types(),
                "timestamp": datetime.now().isoformat()
            }

        @self.mcp.tool(description=GET_SERVER_INFO_DESC)
        async def get_server_info():
            return {
                "name": self.config.server.name,
                "version": self.config.server.version,
                "registered_devices": self.device_manager.get_device_count(),
                "device_types": self.device_manager.get_device_types(),
                "tool_categories": {
                    "device_management": 6,
                    "certificate_check": 5,
                    "lets_encrypt": 4,
                    "certificate_install": 4,
                    "certificate_replace_renew": 3,
                    "certificate_delete": 2,
                    "fortimanager_specific": 4,
                    "system": 2
                },
                "total_tools": 30
            }

    def start(self) -> None:
        """Start the MCP server."""
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.logger.info(f"Starting {self.config.server.name} v{self.config.server.version}...")
            self.logger.info(f"Registered {self.device_manager.get_device_count()} devices")
            anyio.run(self.mcp.run_stdio_async)
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            sys.exit(1)


def main():
    """Main entry point."""
    config_path = os.environ.get("CERT_MCP_CONFIG")

    try:
        server = CertMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
