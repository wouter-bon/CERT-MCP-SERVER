"""Logging utilities for CERT-MCP-SERVER."""

import logging
import sys
from typing import Optional

from ..config.models import LoggingConfig


_loggers: dict[str, logging.Logger] = {}
_root_configured = False


def setup_logging(config: LoggingConfig) -> logging.Logger:
    """Set up logging based on configuration.

    Args:
        config: Logging configuration

    Returns:
        Root logger for the application
    """
    global _root_configured

    if _root_configured:
        return logging.getLogger("cert_mcp")

    # Get or create root logger
    logger = logging.getLogger("cert_mcp")
    logger.setLevel(getattr(logging, config.level))

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(config.format)

    # Console handler
    if config.console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(getattr(logging, config.level))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if config.file_path:
        file_handler = logging.FileHandler(config.file_path)
        file_handler.setLevel(getattr(logging, config.level))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _root_configured = True
    _loggers["cert_mcp"] = logger

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name.

    Args:
        name: Logger name (will be prefixed with 'cert_mcp.')

    Returns:
        Logger instance
    """
    full_name = f"cert_mcp.{name}" if not name.startswith("cert_mcp") else name

    if full_name in _loggers:
        return _loggers[full_name]

    logger = logging.getLogger(full_name)
    _loggers[full_name] = logger

    return logger


def set_log_level(level: str) -> None:
    """Set log level for all loggers.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_level = getattr(logging, level.upper())

    for logger in _loggers.values():
        logger.setLevel(log_level)
        for handler in logger.handlers:
            handler.setLevel(log_level)
