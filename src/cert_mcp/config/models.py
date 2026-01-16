"""Pydantic configuration models for CERT-MCP-SERVER."""

from typing import Optional, Dict, Literal
from pydantic import BaseModel, Field, field_validator
from pathlib import Path


class ServerConfig(BaseModel):
    """Server configuration."""

    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8815, description="Server port")
    name: str = Field(default="cert-mcp-server", description="Server name")
    version: str = Field(default="1.0.0", description="Server version")


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO", description="Log level"
    )
    console: bool = Field(default=True, description="Enable console logging")
    file_path: Optional[str] = Field(default=None, description="Log file path")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format"
    )


class ACMEConfig(BaseModel):
    """ACME/Let's Encrypt configuration."""

    email: Optional[str] = Field(default=None, description="Contact email for Let's Encrypt")
    staging: bool = Field(default=False, description="Use staging environment")
    account_key_path: Optional[str] = Field(
        default=None, description="Path to ACME account key"
    )

    @field_validator("account_key_path")
    @classmethod
    def expand_path(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return str(Path(v).expanduser())
        return v


class FortiGateDeviceConfig(BaseModel):
    """FortiGate device configuration."""

    host: str = Field(..., description="FortiGate IP address or hostname")
    port: int = Field(default=443, description="HTTPS port")
    api_token: Optional[str] = Field(default=None, description="API token")
    username: Optional[str] = Field(default=None, description="Username for auth")
    password: Optional[str] = Field(default=None, description="Password for auth")
    vdom: str = Field(default="root", description="Virtual Domain")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificate")
    timeout: int = Field(default=30, description="Request timeout in seconds")


class FortiManagerDeviceConfig(BaseModel):
    """FortiManager device configuration."""

    host: str = Field(..., description="FortiManager IP address or hostname")
    port: int = Field(default=443, description="HTTPS port")
    api_token: Optional[str] = Field(default=None, description="API token")
    username: Optional[str] = Field(default=None, description="Username for auth")
    password: Optional[str] = Field(default=None, description="Password for auth")
    adom: str = Field(default="root", description="Administrative Domain")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificate")
    timeout: int = Field(default=30, description="Request timeout in seconds")


class FortiAnalyzerDeviceConfig(BaseModel):
    """FortiAnalyzer device configuration."""

    host: str = Field(..., description="FortiAnalyzer IP address or hostname")
    port: int = Field(default=443, description="HTTPS port")
    api_token: Optional[str] = Field(default=None, description="API token")
    username: Optional[str] = Field(default=None, description="Username for auth")
    password: Optional[str] = Field(default=None, description="Password for auth")
    adom: str = Field(default="root", description="Administrative Domain")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificate")
    timeout: int = Field(default=30, description="Request timeout in seconds")


class WindowsDeviceConfig(BaseModel):
    """Windows device configuration for WinRM."""

    host: str = Field(..., description="Windows host IP or hostname")
    port: int = Field(default=5986, description="WinRM port (5986 for HTTPS, 5985 for HTTP)")
    username: str = Field(..., description="Windows username")
    password: str = Field(..., description="Windows password")
    transport: Literal["ntlm", "basic", "kerberos", "credssp"] = Field(
        default="ntlm", description="WinRM transport type"
    )
    verify_ssl: bool = Field(default=False, description="Verify SSL certificate")
    cert_store: str = Field(
        default="LocalMachine\\My", description="Certificate store location"
    )


class LinuxDeviceConfig(BaseModel):
    """Linux device configuration for SSH."""

    host: str = Field(..., description="Linux host IP or hostname")
    port: int = Field(default=22, description="SSH port")
    username: str = Field(..., description="SSH username")
    password: Optional[str] = Field(default=None, description="SSH password")
    ssh_key_path: Optional[str] = Field(default=None, description="Path to SSH private key")
    service_type: Literal["nginx", "apache", "haproxy", "generic"] = Field(
        default="generic", description="Service type for certificate paths"
    )
    cert_path: Optional[str] = Field(
        default=None, description="Custom certificate path"
    )
    key_path: Optional[str] = Field(
        default=None, description="Custom private key path"
    )
    chain_path: Optional[str] = Field(
        default=None, description="Custom certificate chain path"
    )
    reload_command: Optional[str] = Field(
        default=None, description="Custom service reload command"
    )

    @field_validator("ssh_key_path")
    @classmethod
    def expand_ssh_key_path(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return str(Path(v).expanduser())
        return v


class DevicesConfig(BaseModel):
    """All devices configuration."""

    fortigate: Dict[str, FortiGateDeviceConfig] = Field(
        default_factory=dict, description="FortiGate devices"
    )
    fortimanager: Dict[str, FortiManagerDeviceConfig] = Field(
        default_factory=dict, description="FortiManager devices"
    )
    fortianalyzer: Dict[str, FortiAnalyzerDeviceConfig] = Field(
        default_factory=dict, description="FortiAnalyzer devices"
    )
    windows: Dict[str, WindowsDeviceConfig] = Field(
        default_factory=dict, description="Windows devices"
    )
    linux: Dict[str, LinuxDeviceConfig] = Field(
        default_factory=dict, description="Linux devices"
    )


class Config(BaseModel):
    """Main configuration model."""

    server: ServerConfig = Field(default_factory=ServerConfig)
    devices: DevicesConfig = Field(default_factory=DevicesConfig)
    acme: ACMEConfig = Field(default_factory=ACMEConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
