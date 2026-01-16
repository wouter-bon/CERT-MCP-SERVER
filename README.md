# CERT-MCP-SERVER

A standalone Python MCP (Model Context Protocol) server for managing SSL/TLS certificates across multiple device types using Let's Encrypt with Cloudflare DNS-01 challenges.

## Features

- **Multi-Device Support**: Manage certificates on FortiGate, FortiManager, FortiAnalyzer, Windows, and Linux devices
- **Let's Encrypt Integration**: Automated certificate issuance using ACME protocol with DNS-01 challenges
- **Cloudflare DNS**: Automatic DNS record management for certificate validation
- **30 MCP Tools**: Comprehensive toolset for certificate lifecycle management
- **Dual Transport**: Supports both STDIO (for MCP clients) and HTTP (REST API)

## Supported Device Types

| Device Type | Protocol | Authentication |
|-------------|----------|----------------|
| FortiGate | REST API | API Token / Username+Password |
| FortiManager | JSON-RPC | API Token / Username+Password |
| FortiAnalyzer | JSON-RPC | API Token / Username+Password |
| Windows | WinRM/PowerShell | NTLM / Basic / Kerberos |
| Linux | SSH | Password / SSH Key |

## Installation

```bash
# Clone the repository
cd /home/twingate/CERT-MCP-SERVER

# Install with uv
uv sync

# Or install with pip
pip install -e .
```

## Configuration

### Environment Variables

```bash
export CERT_MCP_CONFIG=/path/to/config.json
export CLOUDFLARE_API_TOKEN=your_cloudflare_token
export ACME_EMAIL=admin@example.com
export ACME_ACCOUNT_KEY_PATH=~/.acme/account.key
```

### Configuration File

Create a `config.json` file:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8815,
    "name": "cert-mcp-server",
    "version": "1.0.0"
  },
  "devices": {
    "fortigate": {
      "fw-01": {
        "host": "192.168.1.1",
        "api_token": "your_api_token",
        "vdom": "root"
      }
    },
    "linux": {
      "nginx-01": {
        "host": "192.168.1.10",
        "username": "admin",
        "ssh_key_path": "~/.ssh/id_rsa",
        "service_type": "nginx"
      }
    }
  },
  "acme": {
    "email": "admin@example.com",
    "staging": false,
    "account_key_path": "~/.acme/account.key"
  },
  "logging": {
    "level": "INFO",
    "console": true
  }
}
```

## Usage

### STDIO Mode (MCP Client)

```bash
# Run the server
uv run python -m cert_mcp.server

# Or use the entry point
cert-mcp
```

### HTTP Mode (REST API)

```bash
# Run the HTTP server
uv run python -m cert_mcp.server_http

# Or use the entry point
cert-mcp-http
```

The HTTP server provides a REST API at `http://localhost:8815`.

## MCP Tools (30 total)

### Device Management (6)
- `list_devices` - List all registered devices
- `add_device` - Add a new device
- `remove_device` - Remove a device
- `test_device_connection` - Test connectivity
- `get_device_info` - Get device details
- `list_devices_by_type` - Filter devices by type

### Certificate Check (5)
- `list_certificates` - List certificates on a device
- `get_certificate_detail` - Get certificate details
- `check_certificate_expiry` - Check expiry status
- `check_all_expiring` - Find all expiring certificates
- `verify_certificate_chain` - Verify chain validity

### Let's Encrypt (4)
- `request_certificate` - Request new certificate
- `list_cloudflare_zones` - List DNS zones
- `verify_cloudflare_token` - Verify Cloudflare token
- `get_acme_account_info` - Get ACME account info

### Certificate Install (4)
- `import_certificate` - Import certificate to device
- `request_and_install` - Request and install in one step
- `import_ca_certificate` - Import CA certificate
- `copy_certificate` - Copy between devices

### Certificate Replace/Renew (3)
- `replace_certificate` - Replace existing certificate
- `renew_certificate` - Renew with Let's Encrypt
- `auto_renew_check` - Check and renew expiring certs

### Certificate Delete (2)
- `delete_certificate` - Delete from device
- `delete_certificate_batch` - Delete from multiple devices

### FortiManager-Specific (4)
- `fmg_list_managed_devices` - List managed FortiGates
- `fmg_get_certificates_all` - Get certs from all managed devices
- `fmg_push_certificate` - Push cert to managed devices
- `fmg_check_certificate_status` - Check cert status on devices

### System (2)
- `health_check` - Server health status
- `get_server_info` - Server information

## MCP Client Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "cert-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/home/twingate/CERT-MCP-SERVER", "python", "-m", "cert_mcp.server"],
      "env": {
        "CERT_MCP_CONFIG": "/path/to/config.json",
        "CLOUDFLARE_API_TOKEN": "your_token"
      }
    }
  }
}
```

## Examples

### Request and Install Certificate

```python
# Using MCP tool
await request_and_install(
    device_id="fw-01",
    domains=["example.com", "www.example.com"],
    cert_name="example-cert",
    staging=False
)
```

### Check Expiring Certificates

```python
# Find all certificates expiring in 30 days
result = await check_all_expiring(days_threshold=30)
```

### Add a Device Dynamically

```python
await add_device(
    device_id="nginx-02",
    device_type="linux",
    host="192.168.1.20",
    username="admin",
    ssh_key_path="~/.ssh/id_rsa",
    service_type="nginx"
)
```

## Development

```bash
# Install dev dependencies
uv sync --dev

# Run tests
uv run pytest

# Format code
uv run black src/
uv run ruff check src/
```

## License

MIT License
