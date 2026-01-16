"""Tool descriptions for MCP tools."""

# Device Management Tools (6)
LIST_DEVICES_DESC = """List all registered devices across all types.
Returns device IDs, types, and basic connection info for all FortiGate, FortiManager, FortiAnalyzer, Windows, and Linux devices."""

ADD_DEVICE_DESC = """Add a new device to the certificate management system.
Supports device types: fortigate, fortimanager, fortianalyzer, windows, linux.
Each type requires specific configuration parameters (host, credentials, etc.)."""

REMOVE_DEVICE_DESC = """Remove a device from the certificate management system.
The device will no longer be available for certificate operations."""

TEST_DEVICE_CONNECTION_DESC = """Test connectivity to a specific device.
Verifies that the device is reachable and credentials are valid."""

GET_DEVICE_INFO_DESC = """Get detailed information about a specific device.
Returns device type, hostname, version, and other device-specific details."""

LIST_DEVICES_BY_TYPE_DESC = """List devices filtered by type.
Valid types: fortigate, fortimanager, fortianalyzer, windows, linux."""

# Certificate Check Tools (5)
LIST_CERTIFICATES_DESC = """List all certificates on a device.
Returns certificate names, subjects, expiry dates, and status for all certificates on the specified device."""

GET_CERTIFICATE_DETAIL_DESC = """Get detailed information about a specific certificate.
Returns full certificate details including subject, issuer, SANs, expiry, and status."""

CHECK_CERTIFICATE_EXPIRY_DESC = """Check the expiry status of a specific certificate.
Returns days remaining and expiry status (valid, expiring_soon, expired)."""

CHECK_ALL_EXPIRING_DESC = """Find all certificates expiring within a threshold across all devices.
Scans all registered devices and returns certificates expiring within the specified days."""

VERIFY_CERTIFICATE_CHAIN_DESC = """Verify the certificate chain validity.
Checks that the certificate chain is complete and all certificates are valid."""

# Let's Encrypt Tools (4)
REQUEST_CERTIFICATE_DESC = """Request a new certificate from Let's Encrypt using DNS-01 challenge.
Uses Cloudflare DNS for automatic DNS record management.
Returns the certificate, private key, and chain in PEM format."""

LIST_CLOUDFLARE_ZONES_DESC = """List all DNS zones available in the Cloudflare account.
Returns zone names, IDs, and status for domain validation."""

VERIFY_CLOUDFLARE_TOKEN_DESC = """Verify that the Cloudflare API token is valid.
Tests the token and returns its status and permissions."""

GET_ACME_ACCOUNT_INFO_DESC = """Get ACME account information.
Returns account email, status, and whether using staging environment."""

# Certificate Install Tools (4)
IMPORT_CERTIFICATE_DESC = """Import a certificate and private key to a device.
The certificate should be in PEM format. Optionally include a certificate chain."""

REQUEST_AND_INSTALL_DESC = """Request a new Let's Encrypt certificate and install it directly to a device.
Combines certificate request with automatic installation in a single operation."""

IMPORT_CA_CERTIFICATE_DESC = """Import a CA certificate to a device.
Used for establishing trust for internal CAs. Not all device types support this operation."""

COPY_CERTIFICATE_DESC = """Copy a certificate between devices.
Note: Limited support due to security restrictions on private key export."""

# Certificate Replace/Renew Tools (3)
REPLACE_CERTIFICATE_DESC = """Replace an existing certificate on a device.
Removes the old certificate and installs the new one with the same name."""

RENEW_CERTIFICATE_DESC = """Renew a certificate using Let's Encrypt.
Requests a new certificate for the same domains and replaces the existing one."""

AUTO_RENEW_CHECK_DESC = """Check for expiring certificates and optionally renew them.
Can run in dry-run mode to preview what would be renewed."""

# Certificate Delete Tools (2)
DELETE_CERTIFICATE_DESC = """Delete a certificate from a device.
Permanently removes the certificate and private key from the device."""

DELETE_CERTIFICATE_BATCH_DESC = """Delete a certificate from multiple devices.
Removes the same certificate from all specified devices in one operation."""

# FortiManager-Specific Tools (4)
FMG_LIST_MANAGED_DEVICES_DESC = """List FortiGate devices managed by a FortiManager.
Returns device names, serial numbers, IPs, and connection status."""

FMG_GET_CERTIFICATES_ALL_DESC = """Get certificates from all FortiGates managed by a FortiManager.
Returns a consolidated view of certificates across all managed devices."""

FMG_PUSH_CERTIFICATE_DESC = """Push a certificate from FortiManager to managed FortiGate devices.
Deploys certificate changes to specified managed devices."""

FMG_CHECK_CERTIFICATE_STATUS_DESC = """Check certificate status across all managed FortiGate devices.
Returns certificate installation status for each managed device."""

# System Tools (2)
HEALTH_CHECK_DESC = """Check the health status of the certificate management server.
Returns server status, registered device count, and system information."""

GET_SERVER_INFO_DESC = """Get information about the certificate management server.
Returns server name, version, available tools, and configuration summary."""

# Tool definitions for registration
TOOL_DEFINITIONS = {
    # Device Management
    "list_devices": LIST_DEVICES_DESC,
    "add_device": ADD_DEVICE_DESC,
    "remove_device": REMOVE_DEVICE_DESC,
    "test_device_connection": TEST_DEVICE_CONNECTION_DESC,
    "get_device_info": GET_DEVICE_INFO_DESC,
    "list_devices_by_type": LIST_DEVICES_BY_TYPE_DESC,

    # Certificate Check
    "list_certificates": LIST_CERTIFICATES_DESC,
    "get_certificate_detail": GET_CERTIFICATE_DETAIL_DESC,
    "check_certificate_expiry": CHECK_CERTIFICATE_EXPIRY_DESC,
    "check_all_expiring": CHECK_ALL_EXPIRING_DESC,
    "verify_certificate_chain": VERIFY_CERTIFICATE_CHAIN_DESC,

    # Let's Encrypt
    "request_certificate": REQUEST_CERTIFICATE_DESC,
    "list_cloudflare_zones": LIST_CLOUDFLARE_ZONES_DESC,
    "verify_cloudflare_token": VERIFY_CLOUDFLARE_TOKEN_DESC,
    "get_acme_account_info": GET_ACME_ACCOUNT_INFO_DESC,

    # Certificate Install
    "import_certificate": IMPORT_CERTIFICATE_DESC,
    "request_and_install": REQUEST_AND_INSTALL_DESC,
    "import_ca_certificate": IMPORT_CA_CERTIFICATE_DESC,
    "copy_certificate": COPY_CERTIFICATE_DESC,

    # Certificate Replace/Renew
    "replace_certificate": REPLACE_CERTIFICATE_DESC,
    "renew_certificate": RENEW_CERTIFICATE_DESC,
    "auto_renew_check": AUTO_RENEW_CHECK_DESC,

    # Certificate Delete
    "delete_certificate": DELETE_CERTIFICATE_DESC,
    "delete_certificate_batch": DELETE_CERTIFICATE_BATCH_DESC,

    # FortiManager-Specific
    "fmg_list_managed_devices": FMG_LIST_MANAGED_DEVICES_DESC,
    "fmg_get_certificates_all": FMG_GET_CERTIFICATES_ALL_DESC,
    "fmg_push_certificate": FMG_PUSH_CERTIFICATE_DESC,
    "fmg_check_certificate_status": FMG_CHECK_CERTIFICATE_STATUS_DESC,

    # System
    "health_check": HEALTH_CHECK_DESC,
    "get_server_info": GET_SERVER_INFO_DESC,
}
