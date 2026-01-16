"""Base tool class for MCP tools."""

from typing import Any, Dict
from ..core.logging import get_logger


class BaseTool:
    """Base class for tool implementations."""

    def __init__(self, name: str):
        """Initialize base tool.

        Args:
            name: Tool name for logging
        """
        self.name = name
        self.logger = get_logger(f"tools.{name}")

    def _format_success(
        self,
        message: str,
        data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Format a success response."""
        result = {
            "success": True,
            "message": message
        }
        if data:
            result.update(data)
        return result

    def _format_error(
        self,
        message: str,
        data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Format an error response."""
        result = {
            "success": False,
            "error": message
        }
        if data:
            result.update(data)
        return result
