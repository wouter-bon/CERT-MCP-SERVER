"""Configuration loader for CERT-MCP-SERVER."""

import os
import json
from pathlib import Path
from typing import Optional

from .models import Config


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from file or environment.

    Args:
        config_path: Path to configuration file. If not provided,
                    uses CERT_MCP_CONFIG environment variable.

    Returns:
        Config object

    Raises:
        FileNotFoundError: If config file not found
        ValueError: If config file is invalid
    """
    # Get config path from argument or environment
    path = config_path or os.environ.get("CERT_MCP_CONFIG")

    if path:
        config_file = Path(path).expanduser()

        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")

        with open(config_file, "r") as f:
            config_data = json.load(f)

        # Merge with environment variable overrides
        config_data = _apply_env_overrides(config_data)

        return Config(**config_data)

    # No config file - build from environment
    return _config_from_env()


def _apply_env_overrides(config_data: dict) -> dict:
    """Apply environment variable overrides to config data."""
    # ACME overrides
    if "acme" not in config_data:
        config_data["acme"] = {}

    if os.environ.get("ACME_EMAIL"):
        config_data["acme"]["email"] = os.environ["ACME_EMAIL"]

    if os.environ.get("ACME_ACCOUNT_KEY_PATH"):
        config_data["acme"]["account_key_path"] = os.environ["ACME_ACCOUNT_KEY_PATH"]

    if os.environ.get("ACME_STAGING"):
        config_data["acme"]["staging"] = os.environ["ACME_STAGING"].lower() in (
            "true", "1", "yes"
        )

    # Logging overrides
    if "logging" not in config_data:
        config_data["logging"] = {}

    if os.environ.get("LOG_LEVEL"):
        config_data["logging"]["level"] = os.environ["LOG_LEVEL"].upper()

    return config_data


def _config_from_env() -> Config:
    """Build configuration from environment variables only."""
    config_data = {
        "server": {
            "host": os.environ.get("CERT_MCP_HOST", "0.0.0.0"),
            "port": int(os.environ.get("CERT_MCP_PORT", "8815")),
            "name": os.environ.get("CERT_MCP_NAME", "cert-mcp-server"),
        },
        "acme": {
            "email": os.environ.get("ACME_EMAIL"),
            "staging": os.environ.get("ACME_STAGING", "").lower() in ("true", "1", "yes"),
            "account_key_path": os.environ.get("ACME_ACCOUNT_KEY_PATH"),
        },
        "logging": {
            "level": os.environ.get("LOG_LEVEL", "INFO").upper(),
            "console": True,
        },
        "devices": {},
    }

    return Config(**config_data)


def save_config(config: Config, config_path: str) -> None:
    """Save configuration to file.

    Args:
        config: Config object to save
        config_path: Path to save configuration file
    """
    config_file = Path(config_path).expanduser()
    config_file.parent.mkdir(parents=True, exist_ok=True)

    with open(config_file, "w") as f:
        json.dump(config.model_dump(exclude_none=True), f, indent=2)
