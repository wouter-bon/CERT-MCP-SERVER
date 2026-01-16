# CLAUDE.md - CERT-MCP-SERVER

## Project Overview

CERT-MCP-SERVER is a Python MCP (Model Context Protocol) server for SSL/TLS certificate management across multiple device types using Let's Encrypt with Cloudflare DNS-01 challenges.

## Quick Start

```bash
# Run STDIO server
uv run python -m cert_mcp.server

# Run HTTP server
uv run python -m cert_mcp.server_http

# With config
CERT_MCP_CONFIG=config/config.json uv run python -m cert_mcp.server
```

## Project Structure

```
src/cert_mcp/
├── server.py              # STDIO MCP server (main entry point)
├── server_http.py         # HTTP REST API server
├── config/
│   ├── models.py          # Pydantic config models
│   └── loader.py          # Configuration loading
├── core/
│   ├── logging.py         # Logging utilities
│   ├── acme_client.py     # Let's Encrypt ACME client
│   ├── cloudflare_dns.py  # Cloudflare DNS management
│   └── certificate_utils.py # Certificate parsing utilities
├── handlers/
│   ├── base.py            # Abstract DeviceHandler interface
│   ├── fortigate.py       # FortiGate REST API handler
│   ├── fortimanager.py    # FortiManager JSON-RPC handler
│   ├── fortianalyzer.py   # FortiAnalyzer JSON-RPC handler
│   ├── windows.py         # Windows WinRM handler
│   └── linux.py           # Linux SSH handler
├── managers/
│   ├── device_manager.py      # Multi-device management
│   └── certificate_manager.py # Certificate operations
└── tools/
    ├── definitions.py     # Tool descriptions
    ├── device_tools.py    # Device management tools
    ├── certificate_tools.py # Certificate tools
    └── acme_tools.py      # ACME/Let's Encrypt tools
```

## Key Classes

### DeviceHandler (handlers/base.py)
Abstract interface all device handlers implement:
- `test_connection()` - Test device connectivity
- `list_certificates()` - List all certificates
- `get_certificate()` - Get certificate details
- `import_certificate()` - Import cert + key
- `delete_certificate()` - Delete certificate
- `replace_certificate()` - Replace existing certificate

### DeviceManager (managers/device_manager.py)
Manages multiple devices across all types. Key methods:
- `get_handler(device_id)` - Get handler for device
- `list_devices()` - List all registered devices
- `add_device()` - Add device dynamically
- `remove_device()` - Remove device

### CertificateManager (managers/certificate_manager.py)
Certificate operations across devices. Key methods:
- `request_certificate()` - Request from Let's Encrypt
- `request_and_install()` - Request and install in one step
- `import_certificate()` - Import to device
- `check_all_expiring()` - Find expiring certs
- `renew_certificate()` - Renew via Let's Encrypt

## Environment Variables

- `CERT_MCP_CONFIG` - Path to config file
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token for DNS-01
- `ACME_EMAIL` - Let's Encrypt contact email
- `ACME_ACCOUNT_KEY_PATH` - ACME account key storage path

## Device Types

| Type | Handler | Protocol | Auth |
|------|---------|----------|------|
| fortigate | FortiGateHandler | REST API | api_token or username/password |
| fortimanager | FortiManagerHandler | JSON-RPC | api_token or username/password |
| fortianalyzer | FortiAnalyzerHandler | JSON-RPC | api_token or username/password |
| windows | WindowsHandler | WinRM | username/password |
| linux | LinuxHandler | SSH | password or ssh_key_path |

## MCP Tools (30 total)

Device Management (6): list_devices, add_device, remove_device, test_device_connection, get_device_info, list_devices_by_type

Certificate Check (5): list_certificates, get_certificate_detail, check_certificate_expiry, check_all_expiring, verify_certificate_chain

Let's Encrypt (4): request_certificate, list_cloudflare_zones, verify_cloudflare_token, get_acme_account_info

Certificate Install (4): import_certificate, request_and_install, import_ca_certificate, copy_certificate

Certificate Replace/Renew (3): replace_certificate, renew_certificate, auto_renew_check

Certificate Delete (2): delete_certificate, delete_certificate_batch

FortiManager-Specific (4): fmg_list_managed_devices, fmg_get_certificates_all, fmg_push_certificate, fmg_check_certificate_status

System (2): health_check, get_server_info

## Common Tasks

### Add a device and test connection
```python
await add_device(device_id="fw-01", device_type="fortigate", host="192.168.1.1", api_token="...")
await test_device_connection(device_id="fw-01")
```

### Request and install Let's Encrypt certificate
```python
await request_and_install(
    device_id="fw-01",
    domains=["example.com"],
    cert_name="example-cert"
)
```

### Find expiring certificates
```python
result = await check_all_expiring(days_threshold=30)
# Returns list of all certs expiring within 30 days
```

### Auto-renew preview
```python
result = await auto_renew_check(days_threshold=30, dry_run=True)
# Shows what would be renewed without actually renewing
```

## Dependencies

Core: mcp, fastmcp, httpx, pydantic, cryptography, acme, josepy
Device-specific: paramiko (SSH/Linux), pywinrm (Windows)
HTTP server: fastapi, uvicorn
