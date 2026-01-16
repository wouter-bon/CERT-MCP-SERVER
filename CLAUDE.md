# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CERT-MCP-SERVER is a Python MCP (Model Context Protocol) server for SSL/TLS certificate management across multiple device types using Let's Encrypt with Cloudflare DNS-01 challenges.

## Development Commands

```bash
# Install dependencies
uv sync
uv sync --dev  # include dev dependencies

# Run STDIO server (MCP)
uv run python -m cert_mcp.server

# Run HTTP server (REST API)
uv run python -m cert_mcp.server_http

# With config file
CERT_MCP_CONFIG=config/config.json uv run python -m cert_mcp.server

# Run all tests
uv run pytest

# Run single test file
uv run pytest tests/test_config.py

# Run single test
uv run pytest tests/test_config.py::TestConfigModels::test_server_config_defaults -v

# Format code
uv run black src/

# Lint code
uv run ruff check src/
uv run ruff check src/ --fix  # auto-fix
```

## Architecture

### Layered Design

```
Server Layer (server.py, server_http.py)
    ↓ registers 30 MCP tools
Tools Layer (tools/*.py)
    ↓ delegates to managers
Managers Layer (managers/*.py)
    ↓ orchestrates handlers + ACME/Cloudflare
Handlers Layer (handlers/*.py) + Core (core/*.py)
    ↓ device protocols + certificate utilities
Config Layer (config/*.py)
```

### Key Abstractions

**DeviceHandler** (`handlers/base.py`) - Abstract interface implemented by all device handlers:
- `test_connection()`, `list_certificates()`, `get_certificate()`
- `import_certificate()`, `delete_certificate()`, `replace_certificate()`

Five implementations: FortiGate (REST), FortiManager (JSON-RPC), FortiAnalyzer (JSON-RPC), Windows (WinRM), Linux (SSH)

**DeviceManager** (`managers/device_manager.py`) - Routes operations to appropriate handlers via `HANDLER_MAP`. Maintains registry of handlers and configs.

**CertificateManager** (`managers/certificate_manager.py`) - Certificate lifecycle operations. Integrates ACME client (Let's Encrypt) and Cloudflare DNS client (DNS-01 challenges).

### Adding a New Device Type

1. Create handler in `handlers/` implementing `DeviceHandler` abstract class
2. Add config model in `config/models.py`
3. Register in `DeviceManager.HANDLER_MAP` (`managers/device_manager.py`)
4. Add device type to `DevicesConfig` in `config/models.py`

## Environment Variables

- `CERT_MCP_CONFIG` - Path to config file
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token for DNS-01
- `ACME_EMAIL` - Let's Encrypt contact email
- `ACME_ACCOUNT_KEY_PATH` - ACME account key storage path

## Device Handler Protocols

| Type | Protocol | Auth |
|------|----------|------|
| fortigate | REST API | api_token or username/password |
| fortimanager | JSON-RPC | api_token or username/password |
| fortianalyzer | JSON-RPC | api_token or username/password |
| windows | WinRM | username/password |
| linux | SSH | password or ssh_key_path |

## Code Style

- Line length: 100 (ruff config)
- Python 3.11+ required
- Async/await throughout handlers and managers
- Pydantic v2 for all config models
