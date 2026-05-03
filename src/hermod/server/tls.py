"""
TLS certificate management for the signaling server.

Auto-generates a self-signed X.509 certificate on first run if none exists
(§10). Clients use certificate pinning via SHA-256 fingerprint rather than
trusting the system CA store.

Certificates are stored as PEM strings inside ``~/.config/hermod/config.yaml``
so that the config file is the single source of truth — no certificate files
are written to disk.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import logging
import ssl
import tempfile
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
    hostname: str = "hermod-signaling",
    key_size: int = _KEY_SIZE,
) -> tuple[str, str]:
    """Generate a self-signed RSA certificate and return its PEM strings.

    Parameters
    ----------
    hostname:
        Common Name / SAN hostname for the certificate.
    key_size:
        RSA key size in bits.  Defaults to 4096; use 2048 in tests for speed.

    Returns
    -------
    tuple[str, str]
        ``(cert_pem, key_pem)`` — both ASCII PEM strings suitable for
        storing directly in ``config.yaml``.
    """
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

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    return cert_pem, key_pem


def get_server_ssl_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` for the signaling server from PEM strings.

    Parameters
    ----------
    cert_pem:
        PEM-encoded certificate string (stored in ``config.yaml``).
    key_pem:
        PEM-encoded private key string (stored in ``config.yaml``).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # ssl.SSLContext.load_cert_chain only accepts file paths, so we write the
    # PEM strings to temporary files, load them, and delete immediately.
    cert_tmp: str | None = None
    key_tmp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="wb") as f:
            f.write(cert_pem.encode("ascii"))
            cert_tmp = f.name

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="wb") as f:
            f.write(key_pem.encode("ascii"))
            key_tmp = f.name

        ctx.load_cert_chain(certfile=cert_tmp, keyfile=key_tmp)
    finally:
        if cert_tmp:
            Path(cert_tmp).unlink(missing_ok=True)
        if key_tmp:
            Path(key_tmp).unlink(missing_ok=True)

    return ctx


def get_client_ssl_context(
    cert_pem: bytes | str | None = None,
) -> ssl.SSLContext:
    """Build a client SSL context that trusts only the supplied certificate.

    Parameters
    ----------
    cert_pem:
        The server's PEM certificate to pin as bytes or string.  When
        ``None`` the standard CA store is used (for testing with ``wss://``
        connections).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_pem is not None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        pem_str = cert_pem if isinstance(cert_pem, str) else cert_pem.decode("ascii")
        ctx.load_verify_locations(cadata=pem_str)
    return ctx


def fingerprint_sha256(cert_pem: bytes | str) -> str:
    """Return the SHA-256 fingerprint (hex) of a PEM certificate.

    Used by the trust store to pin a server's certificate.

    Parameters
    ----------
    cert_pem:
        PEM-encoded certificate as bytes or string.
    """
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("ascii")
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()
