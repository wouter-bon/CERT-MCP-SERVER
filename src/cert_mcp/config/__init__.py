"""Configuration module for CERT-MCP-SERVER."""

from .loader import load_config
from .models import Config

__all__ = ["load_config", "Config"]
