"""HTTP server implementation for CERT-MCP-SERVER."""

import os
import sys
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from .config.loader import load_config
from .config.models import Config
from .core.logging import setup_logging, get_logger
from .managers.device_manager import DeviceManager
from .managers.certificate_manager import CertificateManager
from .tools.device_tools import DeviceTools
from .tools.certificate_tools import CertificateTools
from .tools.acme_tools import ACMETools


# Request/Response models
class AddDeviceRequest(BaseModel):
    device_id: str
    device_type: str
    host: str
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_token: Optional[str] = None
    vdom: Optional[str] = None
    adom: Optional[str] = None
    verify_ssl: bool = False
    timeout: int = 30
    transport: Optional[str] = None
    cert_store: Optional[str] = None
    ssh_key_path: Optional[str] = None
    service_type: Optional[str] = None


class ImportCertificateRequest(BaseModel):
    cert_name: str
    certificate: str
    private_key: str
    chain: Optional[str] = None


class RequestCertificateRequest(BaseModel):
    domains: list[str]
    email: Optional[str] = None
    cloudflare_api_token: Optional[str] = None
    key_type: str = "rsa"
    key_size: int = 2048
    staging: bool = False


class RequestAndInstallRequest(BaseModel):
    device_id: str
    domains: list[str]
    cert_name: str
    email: Optional[str] = None
    cloudflare_api_token: Optional[str] = None
    key_type: str = "rsa"
    key_size: int = 2048
    staging: bool = False


# Global state
config: Optional[Config] = None
device_manager: Optional[DeviceManager] = None
certificate_manager: Optional[CertificateManager] = None
device_tools: Optional[DeviceTools] = None
certificate_tools: Optional[CertificateTools] = None
acme_tools: Optional[ACMETools] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global config, device_manager, certificate_manager, device_tools, certificate_tools, acme_tools

    # Startup
    config_path = os.environ.get("CERT_MCP_CONFIG")
    config = load_config(config_path)
    logger = setup_logging(config.logging)

    device_manager = DeviceManager(config.devices)
    certificate_manager = CertificateManager(
        device_manager=device_manager,
        acme_config=config.acme,
        cloudflare_api_token=os.environ.get("CLOUDFLARE_API_TOKEN")
    )

    device_tools = DeviceTools(device_manager)
    certificate_tools = CertificateTools(device_manager, certificate_manager)
    acme_tools = ACMETools(certificate_manager)

    logger.info(f"Starting {config.server.name} HTTP server v{config.server.version}")
    logger.info(f"Registered {device_manager.get_device_count()} devices")

    yield

    # Shutdown
    logger.info("Shutting down HTTP server")


# Create FastAPI app
app = FastAPI(
    title="CERT-MCP-SERVER",
    description="SSL/TLS Certificate Management API",
    version="1.0.0",
    lifespan=lifespan
)


# === Health and Info ===

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "server_name": config.server.name,
        "server_version": config.server.version,
        "registered_devices": device_manager.get_device_count()
    }


@app.get("/info")
async def server_info():
    """Server information endpoint."""
    return {
        "name": config.server.name,
        "version": config.server.version,
        "registered_devices": device_manager.get_device_count(),
        "device_types": device_manager.get_device_types(),
        "total_tools": 30
    }


# === Device Management ===

@app.get("/devices")
async def list_devices():
    """List all registered devices."""
    return await device_tools.list_devices()


@app.get("/devices/type/{device_type}")
async def list_devices_by_type(device_type: str):
    """List devices by type."""
    return await device_tools.list_devices_by_type(device_type)


@app.post("/devices")
async def add_device(request: AddDeviceRequest):
    """Add a new device."""
    return await device_tools.add_device(**request.model_dump())


@app.delete("/devices/{device_id}")
async def remove_device(device_id: str):
    """Remove a device."""
    return await device_tools.remove_device(device_id)


@app.get("/devices/{device_id}/test")
async def test_device_connection(device_id: str):
    """Test device connection."""
    return await device_tools.test_device_connection(device_id)


@app.get("/devices/{device_id}/info")
async def get_device_info(device_id: str):
    """Get device information."""
    return await device_tools.get_device_info(device_id)


# === Certificate Operations ===

@app.get("/devices/{device_id}/certificates")
async def list_certificates(device_id: str):
    """List certificates on a device."""
    return await certificate_tools.list_certificates(device_id)


@app.get("/devices/{device_id}/certificates/{cert_name}")
async def get_certificate_detail(device_id: str, cert_name: str):
    """Get certificate details."""
    return await certificate_tools.get_certificate_detail(device_id, cert_name)


@app.get("/devices/{device_id}/certificates/{cert_name}/expiry")
async def check_certificate_expiry(device_id: str, cert_name: str, days_threshold: int = 30):
    """Check certificate expiry status."""
    return await certificate_tools.check_certificate_expiry(device_id, cert_name, days_threshold)


@app.get("/certificates/expiring")
async def check_all_expiring(days_threshold: int = 30):
    """Find all expiring certificates."""
    return await certificate_tools.check_all_expiring(days_threshold)


@app.post("/devices/{device_id}/certificates")
async def import_certificate(device_id: str, request: ImportCertificateRequest):
    """Import a certificate to a device."""
    return await certificate_tools.import_certificate(
        device_id=device_id,
        cert_name=request.cert_name,
        certificate=request.certificate,
        private_key=request.private_key,
        chain=request.chain
    )


@app.put("/devices/{device_id}/certificates/{cert_name}")
async def replace_certificate(device_id: str, cert_name: str, request: ImportCertificateRequest):
    """Replace a certificate on a device."""
    return await certificate_tools.replace_certificate(
        device_id=device_id,
        cert_name=cert_name,
        certificate=request.certificate,
        private_key=request.private_key,
        chain=request.chain
    )


@app.delete("/devices/{device_id}/certificates/{cert_name}")
async def delete_certificate(device_id: str, cert_name: str):
    """Delete a certificate from a device."""
    return await certificate_tools.delete_certificate(device_id, cert_name)


# === Let's Encrypt ===

@app.post("/acme/request")
async def request_certificate(request: RequestCertificateRequest):
    """Request a certificate from Let's Encrypt."""
    return await acme_tools.request_certificate(
        domains=request.domains,
        email=request.email,
        cloudflare_api_token=request.cloudflare_api_token,
        key_type=request.key_type,
        key_size=request.key_size,
        staging=request.staging
    )


@app.post("/acme/request-and-install")
async def request_and_install(request: RequestAndInstallRequest):
    """Request and install a certificate."""
    return await acme_tools.request_and_install(
        device_id=request.device_id,
        domains=request.domains,
        cert_name=request.cert_name,
        email=request.email,
        cloudflare_api_token=request.cloudflare_api_token,
        key_type=request.key_type,
        key_size=request.key_size,
        staging=request.staging
    )


@app.get("/cloudflare/zones")
async def list_cloudflare_zones(cloudflare_api_token: Optional[str] = None):
    """List Cloudflare DNS zones."""
    return acme_tools.list_cloudflare_zones(cloudflare_api_token)


@app.get("/cloudflare/verify")
async def verify_cloudflare_token(cloudflare_api_token: Optional[str] = None):
    """Verify Cloudflare API token."""
    return acme_tools.verify_cloudflare_token(cloudflare_api_token)


@app.get("/acme/account")
async def get_acme_account_info(email: Optional[str] = None, staging: bool = False):
    """Get ACME account information."""
    return acme_tools.get_acme_account_info(email, staging)


# === Auto-Renew ===

@app.get("/certificates/auto-renew")
async def auto_renew_check(days_threshold: int = 30, dry_run: bool = True):
    """Check and optionally renew expiring certificates."""
    return await certificate_tools.auto_renew_check(days_threshold, dry_run)


@app.post("/devices/{device_id}/certificates/{cert_name}/renew")
async def renew_certificate(
    device_id: str,
    cert_name: str,
    email: Optional[str] = None,
    cloudflare_api_token: Optional[str] = None,
    staging: bool = False
):
    """Renew a certificate using Let's Encrypt."""
    return await certificate_tools.renew_certificate(
        device_id=device_id,
        cert_name=cert_name,
        email=email,
        cloudflare_api_token=cloudflare_api_token,
        staging=staging
    )


# === FortiManager-Specific ===

@app.get("/fortimanager/{device_id}/managed-devices")
async def fmg_list_managed_devices(device_id: str):
    """List devices managed by FortiManager."""
    return await certificate_tools.fmg_list_managed_devices(device_id)


@app.get("/fortimanager/{device_id}/certificates")
async def fmg_get_certificates_all(device_id: str):
    """Get certificates from all managed FortiGates."""
    return await certificate_tools.fmg_get_certificates_all(device_id)


@app.post("/fortimanager/{device_id}/push/{cert_name}")
async def fmg_push_certificate(device_id: str, cert_name: str, target_devices: list[str]):
    """Push certificate to managed FortiGates."""
    return await certificate_tools.fmg_push_certificate(device_id, cert_name, target_devices)


@app.get("/fortimanager/{device_id}/certificates/{cert_name}/status")
async def fmg_check_certificate_status(device_id: str, cert_name: str):
    """Check certificate status across managed FortiGates."""
    return await certificate_tools.fmg_check_certificate_status(device_id, cert_name)


def main():
    """Main entry point for HTTP server."""
    config_path = os.environ.get("CERT_MCP_CONFIG")
    cfg = load_config(config_path)

    uvicorn.run(
        "cert_mcp.server_http:app",
        host=cfg.server.host,
        port=cfg.server.port,
        reload=False
    )


if __name__ == "__main__":
    main()
