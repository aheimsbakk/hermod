"""
TLS certificate management for the signaling server.

Auto-generates a self-signed X.509 certificate on first run if none exists
(§10). Clients use certificate pinning via SHA-256 fingerprint rather than
trusting the system CA store.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import logging
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    generate_private_key,
)
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

_CERT_VALIDITY_DAYS = 3650  # ~10 years
_KEY_SIZE = 4096


def generate_self_signed(
    cert_path: Path,
    key_path: Path,
    hostname: str = "hermod-signaling",
    key_size: int = _KEY_SIZE,
) -> None:
    """Generate and persist a self-signed RSA certificate.

    Parameters
    ----------
    cert_path:
        Destination path for the PEM-encoded certificate.
    key_path:
        Destination path for the PEM-encoded private key.
    hostname:
        Common Name / SAN hostname for the certificate.
    key_size:
        RSA key size in bits.  Defaults to 4096; use 2048 in tests for speed.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Generating self-signed TLS certificate for %s", hostname)

    # Generate RSA private key
    private_key: RSAPrivateKey = generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Build the certificate
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=_CERT_VALIDITY_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(hostname),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write certificate
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # Write private key (mode 600)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    logger.info("Certificate written to %s", cert_path)


def get_server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` for the signaling server.

    Auto-generates the certificate if it does not exist.

    Parameters
    ----------
    cert_path:
        PEM certificate file.
    key_path:
        PEM private key file.
    """
    if not cert_path.exists() or not key_path.exists():
        generate_self_signed(cert_path, key_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


def get_client_ssl_context(
    cert_path: Path | None = None,
) -> ssl.SSLContext:
    """Build a client SSL context that trusts only the supplied certificate.

    Parameters
    ----------
    cert_path:
        The server's PEM certificate to pin.  When ``None`` the standard CA
        store is used (for testing with ``wss://`` connections).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_path is not None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(cert_path))
    return ctx


def fingerprint_sha256(cert_path: Path) -> str:
    """Return the SHA-256 fingerprint (hex) of a PEM certificate.

    Used by the trust store to pin a server's certificate.
    """
    pem_data = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem_data)
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()
