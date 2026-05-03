"""
Config management tests: load_config, save_config.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hermod.core.config import HermodConfig, load_config, save_config


class TestLoadConfig:
    def test_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.server == "wss://localhost:8786"
        assert cfg.port == 8786
        assert cfg.ttl == 3600

    def test_yaml_overrides_defaults(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("server: wss://example.com:443\nttl: 7200\n")
        cfg = load_config(config_path=yaml_file)
        assert cfg.server == "wss://example.com:443"
        assert cfg.ttl == 7200

    def test_cli_overrides_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("server: wss://yaml-server:8786\n")
        cfg = load_config(
            config_path=yaml_file,
            overrides={"server": "wss://cli-server:9000"},
        )
        assert cfg.server == "wss://cli-server:9000"

    def test_env_overrides_yaml(self, tmp_path: Path, monkeypatch) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("server: wss://yaml-server:8786\n")
        monkeypatch.setenv("HERMOD_SERVER", "wss://env-server:1234")
        cfg = load_config(config_path=yaml_file)
        assert cfg.server == "wss://env-server:1234"

    def test_cli_overrides_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("HERMOD_SERVER", "wss://env-server:1234")
        cfg = load_config(
            config_path=tmp_path / "missing.yaml",
            overrides={"server": "wss://cli-server:9000"},
        )
        assert cfg.server == "wss://cli-server:9000"

    def test_none_overrides_ignored(self, tmp_path: Path) -> None:
        cfg = load_config(
            config_path=tmp_path / "missing.yaml",
            overrides={"server": None},
        )
        assert cfg.server == "wss://localhost:8786"

    def test_invalid_yaml_falls_back_to_defaults(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text(": : :")
        cfg = load_config(config_path=yaml_file)
        assert cfg.port == 8786  # default

    def test_port_from_env_int_conversion(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("HERMOD_PORT", "9876")
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.port == 9876

    def test_invalid_port_env_ignored(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("HERMOD_PORT", "not-a-number")
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.port == 8786  # falls back to default

    def test_unknown_yaml_key_ignored(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("unknown_key: something\nttl: 999\n")
        cfg = load_config(config_path=yaml_file)
        assert cfg.ttl == 999


class TestSaveConfig:
    def test_save_and_reload(self, tmp_path: Path) -> None:
        cfg = HermodConfig(server="wss://save-test:8786", ttl=1800)
        path = tmp_path / "hermod" / "config.yaml"
        save_config(cfg, path)
        assert path.exists()
        loaded = load_config(config_path=path)
        assert loaded.server == "wss://save-test:8786"
        assert loaded.ttl == 1800

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        path = tmp_path / "deep" / "nested" / "config.yaml"
        save_config(HermodConfig(), path)
        assert path.exists()

    def test_yaml_no_consecutive_blank_lines(self, tmp_path: Path) -> None:
        """Saved config must not contain consecutive blank lines.

        PyYAML's default quoted-scalar style inserts a blank line between
        every base64 line of a PEM string.  The custom ``_HermodDumper``
        writes multiline values as literal block scalars (``|``) so the
        file stays compact.
        """
        from hermod.server.tls import generate_self_signed

        cert_pem, key_pem = generate_self_signed(hostname="test", key_size=2048)
        path = tmp_path / "config.yaml"
        save_config(HermodConfig(tls_cert=cert_pem, tls_key=key_pem), path)

        lines = path.read_text(encoding="utf-8").splitlines()
        consecutive = [
            i + 1  # 1-indexed for readability
            for i in range(1, len(lines))
            if lines[i].strip() == "" and lines[i - 1].strip() == ""
        ]
        assert not consecutive, (
            f"Config YAML has consecutive blank lines at line(s): {consecutive}"
        )

    def test_yaml_pem_round_trips(self, tmp_path: Path) -> None:
        """PEM strings stored and reloaded from config must be identical."""
        from hermod.server.tls import generate_self_signed

        cert_pem, key_pem = generate_self_signed(hostname="test", key_size=2048)
        path = tmp_path / "config.yaml"
        save_config(HermodConfig(tls_cert=cert_pem, tls_key=key_pem), path)

        reloaded = load_config(config_path=path)
        assert reloaded.tls_cert == cert_pem
        assert reloaded.tls_key == key_pem
