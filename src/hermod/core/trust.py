"""
Client-side TLS certificate trust store.

Maps server URLs to their SHA-256 public certificate fingerprints and PEM
bytes in ``~/.hermod/trust_store.json`` (§10).

The client refuses standard CA validation and instead verifies that the
server's certificate fingerprint matches the pinned value.
"""

from __future__ import annotations

import json
import logging
import ssl
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_STORE_PATH = Path.home() / ".hermod" / "trust_store.json"

# Internal store format: {url: {"fingerprint": str, "cert_pem": str}}
_StoreEntry = dict[str, str]


class TrustStore:
    """Persists server URL → SHA-256 fingerprint + PEM certificate mappings.

    Parameters
    ----------
    path:
        Path to the JSON store file.
    """

    def __init__(self, path: Path = _DEFAULT_STORE_PATH) -> None:
        self._path = path
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
        if self._path.exists():
            try:
                raw: Any = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._store = {
                        str(k): {sk: str(sv) for sk, sv in v.items()}
                        for k, v in raw.items()
                        if isinstance(v, dict)
                    }
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "Failed to load trust store from %s: %s", self._path, exc
                )

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._store, indent=2), encoding="utf-8")
        self._path.chmod(0o600)


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
