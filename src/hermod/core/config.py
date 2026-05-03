"""
Configuration management.

Resolves settings via the strict hierarchy (§3, §19, §22–§24):
  CLI Flags > Environment Variables > config.yaml > Application Defaults

The config file lives at:
  Linux/macOS: ``~/.config/hermod/config.yaml``
  Windows:     ``%APPDATA%\\Hermod\\config.yaml``

This is the **single** config file for Hermod.  It stores:
  - Runtime settings (server URL, listen address, TTL, …)
  - TLS certificate and private key (PEM strings, written as ``|`` scalars)
  - Pinned server certificates (``trusted_servers`` mapping)

No other config or state files are written outside this path
(except ``~/.hermod/signaling.db`` which is a SQLite data file, not config).
"""

from __future__ import annotations

import logging
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Default port used when none is specified in a listen address.
DEFAULT_PORT: int = 8786

# ------------------------------------------------------------------
# Platform-aware config path
# ------------------------------------------------------------------


def _default_config_path() -> Path:
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")
        return Path(appdata) / "Hermod" / "config.yaml"
    return Path.home() / ".config" / "hermod" / "config.yaml"


def _default_db_path() -> str:
    return str(Path.home() / ".hermod" / "signaling.db")


def _default_dest_dir() -> str:
    return str(Path.cwd())


# ------------------------------------------------------------------
# Listen address helpers
# ------------------------------------------------------------------


def parse_listen(listen: str) -> tuple[str, int]:
    """Parse a listen address string into ``(host, port)``.

    Accepted forms:

    * ``"0.0.0.0:8786"`` — IPv4 host and port
    * ``"[::]:8786"`` — IPv6 host and port (RFC 3986 bracket notation)
    * ``"0.0.0.0"`` — host only; :data:`DEFAULT_PORT` is used
    * ``"[::]"`` — IPv6 host only; :data:`DEFAULT_PORT` is used

    Raises
    ------
    ValueError
        If the port portion is present but not a valid integer.
    """
    s = listen.strip()
    if s.startswith("["):
        # IPv6 bracketed form: "[::1]:8786" or "[::]"
        try:
            bracket_end = s.index("]")
        except ValueError:
            raise ValueError(f"Malformed IPv6 listen address (no closing ']'): {s!r}")
        host = s[1:bracket_end]
        rest = s[bracket_end + 1 :]
        if rest.startswith(":"):
            port = int(rest[1:])
        elif not rest:
            port = DEFAULT_PORT
        else:
            raise ValueError(
                f"Unexpected characters after ']' in listen address: {s!r}"
            )
    elif ":" in s:
        left, _, right = s.rpartition(":")
        if right.isdigit():
            host, port = left, int(right)
        else:
            # Bare string without a recognisable port — treat whole value as host.
            host, port = s, DEFAULT_PORT
    else:
        host, port = s, DEFAULT_PORT
    return host, port


def format_listen(host: str, port: int) -> str:
    """Format *host* and *port* as a canonical listen address string.

    IPv6 addresses are wrapped in brackets per RFC 3986:
    ``"[::1]:8786"``.
    """
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


# ------------------------------------------------------------------
# Config dataclass
# ------------------------------------------------------------------


@dataclass
class HermodConfig:
    """Resolved application configuration.

    All fields represent the *final* effective value after merging sources.

    TLS certificate and private key are stored as PEM strings directly in
    ``config.yaml`` so that the file is the single source of truth — no
    separate certificate files are written to disk.

    Pinned server certificates live under ``trusted_servers`` in the same
    file, replacing the old ``~/.hermod/trust_store.json``.

    ``listen`` encodes both the bind host and port in standard
    ``host:port`` / ``[ipv6]:port`` notation.  Use the :attr:`host` and
    :attr:`port` properties to access the parsed components.
    """

    server: str = "wss://localhost:8786"
    listen: str = f"0.0.0.0:{DEFAULT_PORT}"
    db_path: str = field(default_factory=_default_db_path)
    dest_dir: str = field(default_factory=_default_dest_dir)
    tls_cert: str = ""  # PEM-encoded server certificate
    tls_key: str = ""  # PEM-encoded server private key
    ttl: int = 3600
    verbosity: str = "info"
    # Maps server URL → {"fingerprint": <hex>, "cert_pem": <PEM string>}
    trusted_servers: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def host(self) -> str:
        """Bind host extracted from :attr:`listen`."""
        return parse_listen(self.listen)[0]

    @property
    def port(self) -> int:
        """Bind port extracted from :attr:`listen`."""
        return parse_listen(self.listen)[1]


# ------------------------------------------------------------------
# Resolver
# ------------------------------------------------------------------

_ENV_MAP: dict[str, str] = {
    "HERMOD_SERVER": "server",
    "HERMOD_DB_PATH": "db_path",
    "HERMOD_DEST_DIR": "dest_dir",
}


def load_config(
    config_path: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> HermodConfig:
    """Load configuration from all sources and merge them.

    Parameters
    ----------
    config_path:
        Explicit path to ``config.yaml``. When ``None`` the platform default
        is tried, and missing files are silently ignored.
    overrides:
        Dict of field → value pairs representing CLI flag overrides
        (highest priority).

    Returns
    -------
    HermodConfig
        Fully resolved configuration.
    """
    # 1. Start with defaults
    cfg: dict[str, Any] = {
        "server": "wss://localhost:8786",
        "listen": f"0.0.0.0:{DEFAULT_PORT}",
        "db_path": _default_db_path(),
        "dest_dir": _default_dest_dir(),
        "tls_cert": "",
        "tls_key": "",
        "ttl": 3600,
        "verbosity": "info",
        "trusted_servers": {},
    }

    # 2. Load YAML file (if present)
    path = config_path or _default_config_path()
    if path.exists():
        try:
            raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

            # New-style: listen: "host:port"
            if "listen" in raw:
                cfg["listen"] = str(raw["listen"])
            # Backward compat: old separate host/port keys
            elif "host" in raw or "port" in raw:
                cur_host, cur_port = parse_listen(cfg["listen"])
                h = str(raw.get("host", cur_host))
                try:
                    p = int(raw.get("port", cur_port))
                except (TypeError, ValueError):
                    p = cur_port
                cfg["listen"] = format_listen(h, p)

            # Scalar fields
            for key in (
                "server",
                "db_path",
                "dest_dir",
                "tls_cert",
                "tls_key",
                "verbosity",
            ):
                if key in raw:
                    cfg[key] = raw[key]

            if "ttl" in raw:
                try:
                    cfg["ttl"] = int(raw["ttl"])
                except (TypeError, ValueError):
                    logger.warning("Invalid ttl value in %s; ignoring", path)

            # Trusted servers (nested dict)
            ts = raw.get("trusted_servers")
            if isinstance(ts, dict):
                cfg["trusted_servers"] = ts

            # Warn on unrecognised keys
            known = {
                "listen",
                "host",
                "port",
                "server",
                "db_path",
                "dest_dir",
                "tls_cert",
                "tls_key",
                "ttl",
                "verbosity",
                "trusted_servers",
            }
            for key in raw:
                if key not in known:
                    logger.debug("Unknown config key %r in %s; ignoring", key, path)

        except yaml.YAMLError as exc:
            logger.warning("Failed to parse %s: %s", path, exc)

    # 3. Environment variables
    for env_var, field_name in _ENV_MAP.items():
        value = os.environ.get(env_var)
        if value is not None:
            cfg[field_name] = value

    # HERMOD_LISTEN overrides the listen address (new-style)
    listen_env = os.environ.get("HERMOD_LISTEN")
    if listen_env:
        cfg["listen"] = listen_env
    else:
        # Backward compat: HERMOD_HOST / HERMOD_PORT
        host_env = os.environ.get("HERMOD_HOST")
        port_env = os.environ.get("HERMOD_PORT")
        if host_env or port_env:
            cur_host, cur_port = parse_listen(cfg["listen"])
            h = host_env or cur_host
            try:
                p = int(port_env) if port_env else cur_port
            except ValueError:
                logger.warning("Invalid HERMOD_PORT value %r; ignoring", port_env)
                p = cur_port
            cfg["listen"] = format_listen(h, p)

    # 4. CLI overrides (highest priority; None values are skipped)
    if overrides:
        for key, value in overrides.items():
            if value is not None and key in cfg:
                cfg[key] = value

    fields = HermodConfig.__dataclass_fields__
    return HermodConfig(**{k: v for k, v in cfg.items() if k in fields})


def save_config(config: HermodConfig, path: Path | None = None) -> None:
    """Persist *config* to *path* (or the platform default).

    Multiline values (PEM certificate / key strings, pinned cert PEM) are
    written as YAML literal block scalars (``|``) so the file stays compact.

    The file is created with mode ``0o600`` (owner read/write only) because
    it contains a TLS private key and trusted server certificates.
    """
    target = path or _default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    # Only persist dataclass fields (properties like host/port are excluded).
    data = {f: getattr(config, f) for f in HermodConfig.__dataclass_fields__}
    content = yaml.dump(data, Dumper=_HermodDumper, default_flow_style=False)
    target.write_text(content, encoding="utf-8")
    target.chmod(0o600)
    logger.debug("Config saved to %s", target)


class _HermodDumper(yaml.SafeDumper):
    """YAML dumper that writes multiline strings as literal block scalars (``|``).

    This prevents PyYAML from inserting a blank line between every line of the
    PEM certificate / private key when using the default quoted scalar style.
    Applies recursively to all strings in the document, including those nested
    inside the ``trusted_servers`` mapping.
    """


def _str_representer(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_HermodDumper.add_representer(str, _str_representer)
