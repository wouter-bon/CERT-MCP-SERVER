"""Device handlers for CERT-MCP-SERVER."""

from .base import DeviceHandler, CertificateInfo
from .fortigate import FortiGateHandler
from .fortimanager import FortiManagerHandler
from .fortianalyzer import FortiAnalyzerHandler
from .windows import WindowsHandler
from .linux import LinuxHandler

__all__ = [
    "DeviceHandler",
    "CertificateInfo",
    "FortiGateHandler",
    "FortiManagerHandler",
    "FortiAnalyzerHandler",
    "WindowsHandler",
    "LinuxHandler",
]
