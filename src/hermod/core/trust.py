"""
Client-side TLS certificate trust store.

Maps server URLs to their SHA-256 public certificate fingerprints and PEM
bytes in ``~/.config/hermod/config.yaml`` under the ``trusted_servers`` key.

The client refuses standard CA validation and instead verifies that the
server's certificate fingerprint matches the pinned value.
"""

from __future__ import annotations

import dataclasses
import logging
import ssl
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Internal store format: {url: {"fingerprint": str, "cert_pem": str}}
_StoreEntry = dict[str, str]


class TrustStore:
    """Persists server URL → SHA-256 fingerprint + PEM certificate mappings.

    Data lives under ``trusted_servers`` in the Hermod config file
    (``~/.config/hermod/config.yaml``), replacing the former
    ``~/.hermod/trust_store.json``.

    Parameters
    ----------
    config_path:
        Explicit path to ``config.yaml``.  ``None`` uses the platform default.
    """

    def __init__(self, config_path: Path | None = None) -> None:
        self._config_path = config_path
        self._store: dict[str, _StoreEntry] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, url: str, fingerprint: str, cert_pem: bytes | None = None) -> None:
        """Pin *fingerprint* (and optionally *cert_pem*) for *url*.

        Parameters
        ----------
        url:
            Server URL (e.g. ``"wss://my-relay.local:8443"``).
        fingerprint:
            Hex-encoded SHA-256 fingerprint of the server's DER certificate.
        cert_pem:
            PEM-encoded server certificate bytes.  Required for clients to
            build a pinned SSL context; omit only if unavailable.
        """
        entry: _StoreEntry = {"fingerprint": fingerprint.lower()}
        if cert_pem is not None:
            # PEM is ASCII; store as plain string
            entry["cert_pem"] = cert_pem.decode("ascii")
        self._store[url] = entry
        self._save()
        logger.info("Pinned certificate for %s", url)

    def get(self, url: str) -> str | None:
        """Return the pinned fingerprint for *url*, or ``None`` if not pinned."""
        entry = self._store.get(url)
        if entry is None:
            return None
        return entry.get("fingerprint")

    def get_cert_pem(self, url: str) -> bytes | None:
        """Return the pinned PEM certificate for *url*, or ``None``."""
        entry = self._store.get(url)
        if entry is None:
            return None
        pem = entry.get("cert_pem")
        return pem.encode("ascii") if pem else None

    def remove(self, url: str) -> bool:
        """Remove the pinned certificate for *url*.

        Returns ``True`` if an entry was removed.
        """
        if url in self._store:
            del self._store[url]
            self._save()
            return True
        return False

    def is_trusted(self, url: str) -> bool:
        """Return ``True`` if a certificate is pinned for *url*."""
        return url in self._store

    def all_entries(self) -> dict[str, str]:
        """Return a copy of all pinned entries as ``{url: fingerprint}``."""
        return {url: entry.get("fingerprint", "") for url, entry in self._store.items()}

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        from hermod.core.config import load_config

        cfg = load_config(config_path=self._config_path)
        raw = cfg.trusted_servers
        if isinstance(raw, dict):
            self._store = {
                str(k): {sk: str(sv) for sk, sv in v.items()}
                for k, v in raw.items()
                if isinstance(v, dict)
            }

    def _save(self) -> None:
        from hermod.core.config import load_config, save_config

        cfg = load_config(config_path=self._config_path)
        updated = dataclasses.replace(cfg, trusted_servers=dict(self._store))
        save_config(updated, path=self._config_path)


# ------------------------------------------------------------------
# SSL context factory with certificate pinning
# ------------------------------------------------------------------


def pinned_ssl_context(fingerprint: str, cert_pem: bytes) -> ssl.SSLContext:
    """Build a client SSL context that accepts only *fingerprint*.

    Parameters
    ----------
    fingerprint:
        Expected SHA-256 hex fingerprint of the server's DER certificate.
    cert_pem:
        PEM bytes of the server's certificate (obtained via ``trust`` command).

    Returns
    -------
    ssl.SSLContext
        Context that validates the certificate fingerprint only.
    """
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    actual = hashlib.sha256(der).hexdigest()

    if actual != fingerprint.lower():
        raise ValueError(
            f"Certificate fingerprint mismatch: "
            f"expected {fingerprint!r}, got {actual!r}"
        )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load the pinned certificate as the only trusted CA
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
        tmp.write(cert_pem)
        tmp_path = tmp.name
    try:
        ctx.load_verify_locations(cafile=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return ctx
