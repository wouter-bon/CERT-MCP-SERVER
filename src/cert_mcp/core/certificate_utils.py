"""Certificate parsing and utility functions."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List
import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from .logging import get_logger


@dataclass
class CertificateInfo:
    """Certificate information container."""

    name: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    domains: List[str] = field(default_factory=list)
    fingerprint_sha256: str = ""
    key_type: str = ""
    key_size: int = 0
    is_ca: bool = False
    days_remaining: int = 0
    status: str = "valid"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_valid_before": self.not_valid_before.isoformat(),
            "not_valid_after": self.not_valid_after.isoformat(),
            "domains": self.domains,
            "fingerprint_sha256": self.fingerprint_sha256,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "is_ca": self.is_ca,
            "days_remaining": self.days_remaining,
            "status": self.status,
        }


class CertificateUtils:
    """Utility class for certificate operations."""

    def __init__(self):
        self.logger = get_logger("certificate_utils")

    def parse_certificate(
        self,
        cert_pem: bytes,
        name: str = "unknown"
    ) -> CertificateInfo:
        """Parse a PEM-encoded certificate.

        Args:
            cert_pem: PEM-encoded certificate
            name: Certificate name/identifier

        Returns:
            CertificateInfo object
        """
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

        # Get SANs
        domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name_entry in san_ext.value:
                if isinstance(name_entry, x509.DNSName):
                    domains.append(name_entry.value)
        except x509.ExtensionNotFound:
            pass

        # Get key info
        public_key = cert.public_key()
        key_type = type(public_key).__name__.replace("_", " ")
        try:
            key_size = public_key.key_size
        except AttributeError:
            key_size = 0

        # Check if CA
        is_ca = False
        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = bc_ext.value.ca
        except x509.ExtensionNotFound:
            pass

        # Calculate days remaining
        now = datetime.now(timezone.utc)
        days_remaining = (cert.not_valid_after_utc - now).days

        # Determine status
        if now < cert.not_valid_before_utc:
            status = "not_yet_valid"
        elif now > cert.not_valid_after_utc:
            status = "expired"
        elif days_remaining <= 30:
            status = "expiring_soon"
        else:
            status = "valid"

        # Fingerprint
        fingerprint = cert.fingerprint(x509.load_der_x509_certificate.__module__.split('.')[0] == 'cryptography' and __import__('cryptography.hazmat.primitives.hashes', fromlist=['SHA256']).SHA256())
        fingerprint_hex = fingerprint.hex().upper()

        return CertificateInfo(
            name=name,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=format(cert.serial_number, 'X'),
            not_valid_before=cert.not_valid_before_utc,
            not_valid_after=cert.not_valid_after_utc,
            domains=domains,
            fingerprint_sha256=fingerprint_hex,
            key_type=key_type,
            key_size=key_size,
            is_ca=is_ca,
            days_remaining=days_remaining,
            status=status,
        )

    def parse_certificate_from_base64(
        self,
        cert_base64: str,
        name: str = "unknown"
    ) -> CertificateInfo:
        """Parse a base64-encoded certificate.

        Args:
            cert_base64: Base64-encoded certificate (DER or PEM)
            name: Certificate name/identifier

        Returns:
            CertificateInfo object
        """
        cert_data = base64.b64decode(cert_base64)

        # Try PEM first
        if b"-----BEGIN CERTIFICATE-----" in cert_data:
            return self.parse_certificate(cert_data, name)

        # Try DER
        cert = x509.load_der_x509_certificate(cert_data, default_backend())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        return self.parse_certificate(cert_pem, name)

    def verify_certificate_chain(
        self,
        cert_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> dict:
        """Verify certificate chain.

        Args:
            cert_pem: PEM-encoded certificate
            chain_pem: PEM-encoded chain certificates

        Returns:
            Verification result dict
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            chain_certs = []
            if chain_pem:
                chain_data = chain_pem
                while b"-----BEGIN CERTIFICATE-----" in chain_data:
                    start = chain_data.find(b"-----BEGIN CERTIFICATE-----")
                    end = chain_data.find(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
                    chain_cert_pem = chain_data[start:end]
                    chain_cert = x509.load_pem_x509_certificate(chain_cert_pem, default_backend())
                    chain_certs.append(chain_cert)
                    chain_data = chain_data[end:]

            # Basic validation
            now = datetime.now(timezone.utc)

            if now < cert.not_valid_before_utc:
                return {
                    "valid": False,
                    "error": "Certificate is not yet valid",
                    "cert_subject": cert.subject.rfc4514_string()
                }

            if now > cert.not_valid_after_utc:
                return {
                    "valid": False,
                    "error": "Certificate has expired",
                    "cert_subject": cert.subject.rfc4514_string()
                }

            # Check chain validity
            for i, chain_cert in enumerate(chain_certs):
                if now < chain_cert.not_valid_before_utc:
                    return {
                        "valid": False,
                        "error": f"Chain certificate {i} is not yet valid",
                        "cert_subject": chain_cert.subject.rfc4514_string()
                    }
                if now > chain_cert.not_valid_after_utc:
                    return {
                        "valid": False,
                        "error": f"Chain certificate {i} has expired",
                        "cert_subject": chain_cert.subject.rfc4514_string()
                    }

            return {
                "valid": True,
                "cert_subject": cert.subject.rfc4514_string(),
                "chain_length": len(chain_certs),
                "days_remaining": (cert.not_valid_after_utc - now).days
            }

        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }

    def check_expiry(
        self,
        cert_pem: bytes,
        days_threshold: int = 30
    ) -> dict:
        """Check certificate expiry status.

        Args:
            cert_pem: PEM-encoded certificate
            days_threshold: Days before expiry to warn

        Returns:
            Expiry status dict
        """
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        now = datetime.now(timezone.utc)
        days_remaining = (cert.not_valid_after_utc - now).days

        if days_remaining < 0:
            status = "expired"
        elif days_remaining <= days_threshold:
            status = "expiring_soon"
        else:
            status = "valid"

        return {
            "status": status,
            "days_remaining": days_remaining,
            "expiry_date": cert.not_valid_after_utc.isoformat(),
            "threshold_days": days_threshold
        }

    def pem_to_der(self, pem_data: bytes) -> bytes:
        """Convert PEM to DER format."""
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return cert.public_bytes(serialization.Encoding.DER)

    def der_to_pem(self, der_data: bytes) -> bytes:
        """Convert DER to PEM format."""
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        return cert.public_bytes(serialization.Encoding.PEM)

    def combine_cert_and_key(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        chain_pem: Optional[bytes] = None
    ) -> bytes:
        """Combine certificate, key, and chain into a single PEM file.

        Args:
            cert_pem: PEM-encoded certificate
            key_pem: PEM-encoded private key
            chain_pem: Optional PEM-encoded chain

        Returns:
            Combined PEM data
        """
        result = cert_pem
        if not result.endswith(b"\n"):
            result += b"\n"

        result += key_pem
        if not result.endswith(b"\n"):
            result += b"\n"

        if chain_pem:
            result += chain_pem
            if not result.endswith(b"\n"):
                result += b"\n"

        return result
