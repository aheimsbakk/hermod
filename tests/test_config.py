"""
Config management tests: load_config, save_config, parse_listen, format_listen.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hermod.core.config import (
    DEFAULT_PORT,
    HermodConfig,
    format_listen,
    load_config,
    parse_listen,
    save_config,
)


class TestParseAndFormatListen:
    def test_host_and_port(self) -> None:
        assert parse_listen("0.0.0.0:8786") == ("0.0.0.0", 8786)

    def test_host_only_uses_default_port(self) -> None:
        host, port = parse_listen("0.0.0.0")
        assert host == "0.0.0.0"
        assert port == DEFAULT_PORT

    def test_ipv6_with_port(self) -> None:
        assert parse_listen("[::1]:9000") == ("::1", 9000)

    def test_ipv6_without_port(self) -> None:
        host, port = parse_listen("[::]")
        assert host == "::"
        assert port == DEFAULT_PORT

    def test_format_ipv4(self) -> None:
        assert format_listen("0.0.0.0", 8786) == "0.0.0.0:8786"

    def test_format_ipv6(self) -> None:
        assert format_listen("::1", 9000) == "[::1]:9000"

    def test_round_trip_ipv4(self) -> None:
        s = format_listen("192.168.1.1", 1234)
        assert parse_listen(s) == ("192.168.1.1", 1234)

    def test_round_trip_ipv6(self) -> None:
        s = format_listen("::", DEFAULT_PORT)
        assert parse_listen(s) == ("::", DEFAULT_PORT)

    def test_malformed_ipv6_raises(self) -> None:
        with pytest.raises(ValueError, match="closing"):
            parse_listen("[::1:9000")


class TestLoadConfig:
    def test_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.server == "wss://localhost:8786"
        assert cfg.listen == f"0.0.0.0:{DEFAULT_PORT}"
        assert cfg.port == DEFAULT_PORT
        assert cfg.ttl == 3600

    def test_yaml_overrides_defaults(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("server: wss://example.com:443\nttl: 7200\n")
        cfg = load_config(config_path=yaml_file)
        assert cfg.server == "wss://example.com:443"
        assert cfg.ttl == 7200

    def test_yaml_listen_field(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("listen: '0.0.0.0:9999'\n")
        cfg = load_config(config_path=yaml_file)
        assert cfg.listen == "0.0.0.0:9999"
        assert cfg.port == 9999

    def test_yaml_old_host_port_keys_backward_compat(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("host: '127.0.0.1'\nport: 9876\n")
        cfg = load_config(config_path=yaml_file)
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 9876

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
        assert cfg.port == DEFAULT_PORT

    def test_hermod_listen_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("HERMOD_LISTEN", "127.0.0.1:9999")
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.listen == "127.0.0.1:9999"
        assert cfg.port == 9999

    def test_port_from_env_int_conversion(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("HERMOD_PORT", "9876")
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.port == 9876

    def test_invalid_port_env_ignored(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("HERMOD_PORT", "not-a-number")
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.port == DEFAULT_PORT

    def test_hermod_host_env_backward_compat(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("HERMOD_HOST", "10.0.0.1")
        cfg = load_config(config_path=tmp_path / "missing.yaml")
        assert cfg.host == "10.0.0.1"
        assert cfg.port == DEFAULT_PORT

    def test_unknown_yaml_key_ignored(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("unknown_key: something\nttl: 999\n")
        cfg = load_config(config_path=yaml_file)
        assert cfg.ttl == 999

    def test_trusted_servers_loaded(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            "trusted_servers:\n"
            "  wss://relay.local:8786:\n"
            "    fingerprint: abc123\n"
            "    cert_pem: ''\n"
        )
        cfg = load_config(config_path=yaml_file)
        assert "wss://relay.local:8786" in cfg.trusted_servers
        assert cfg.trusted_servers["wss://relay.local:8786"]["fingerprint"] == "abc123"


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

    def test_listen_round_trips(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        save_config(HermodConfig(listen="127.0.0.1:9001"), path)
        loaded = load_config(config_path=path)
        assert loaded.listen == "127.0.0.1:9001"
        assert loaded.port == 9001

    def test_trusted_servers_round_trips(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        ts = {"wss://relay.test:8786": {"fingerprint": "deadbeef", "cert_pem": ""}}
        save_config(HermodConfig(trusted_servers=ts), path)
        loaded = load_config(config_path=path)
        assert loaded.trusted_servers == ts

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

    def test_trusted_servers_pem_round_trips(self, tmp_path: Path) -> None:
        """PEM strings inside trusted_servers must survive save/load intact."""
        from hermod.server.tls import generate_self_signed

        cert_pem, _ = generate_self_signed(hostname="relay", key_size=2048)
        path = tmp_path / "config.yaml"
        ts = {"wss://relay.test:8786": {"fingerprint": "aa", "cert_pem": cert_pem}}
        save_config(HermodConfig(trusted_servers=ts), path)
        loaded = load_config(config_path=path)
        assert loaded.trusted_servers["wss://relay.test:8786"]["cert_pem"] == cert_pem
