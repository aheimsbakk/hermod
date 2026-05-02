"""
Configuration management.

Resolves settings via the strict hierarchy (§3, §19, §22–§24):
  CLI Flags > Environment Variables > config.yaml > Application Defaults

The config file lives at:
  Linux/macOS: ``~/.config/hermod/config.yaml``
  Windows:     ``%APPDATA%\\Hermod\\config.yaml``
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
# Config dataclass
# ------------------------------------------------------------------


@dataclass
class HermodConfig:
    """Resolved application configuration.

    All fields represent the *final* effective value after merging sources.
    """

    server: str = "wss://localhost:4430"
    port: int = 4430
    host: str = "0.0.0.0"
    db_path: str = field(default_factory=_default_db_path)
    dest_dir: str = field(default_factory=_default_dest_dir)
    ttl: int = 3600
    verbosity: str = "info"


# ------------------------------------------------------------------
# Resolver
# ------------------------------------------------------------------

_ENV_MAP: dict[str, str] = {
    "HERMOD_SERVER": "server",
    "HERMOD_PORT": "port",
    "HERMOD_HOST": "host",
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
        "server": "wss://localhost:4430",
        "port": 4430,
        "host": "0.0.0.0",
        "db_path": _default_db_path(),
        "dest_dir": _default_dest_dir(),
        "ttl": 3600,
        "verbosity": "info",
    }

    # 2. Load YAML file (if present)
    path = config_path or _default_config_path()
    if path.exists():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for key, value in raw.items():
                if key in cfg:
                    cfg[key] = value
                else:
                    logger.debug("Unknown config key %r in %s; ignoring", key, path)
        except yaml.YAMLError as exc:
            logger.warning("Failed to parse %s: %s", path, exc)

    # 3. Environment variables
    for env_var, field_name in _ENV_MAP.items():
        value = os.environ.get(env_var)
        if value is not None:
            if field_name == "port":
                try:
                    cfg[field_name] = int(value)
                except ValueError:
                    logger.warning("Invalid %s value %r; ignoring", env_var, value)
            else:
                cfg[field_name] = value

    # 4. CLI overrides (highest priority; None values are skipped)
    if overrides:
        for key, value in overrides.items():
            if value is not None and key in cfg:
                cfg[key] = value

    return HermodConfig(
        **{k: v for k, v in cfg.items() if k in HermodConfig.__dataclass_fields__}
    )


def save_config(config: HermodConfig, path: Path | None = None) -> None:
    """Persist *config* to *path* (or the platform default)."""
    target = path or _default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = {f: getattr(config, f) for f in HermodConfig.__dataclass_fields__}
    target.write_text(yaml.safe_dump(data, default_flow_style=False), encoding="utf-8")
    logger.debug("Config saved to %s", target)
