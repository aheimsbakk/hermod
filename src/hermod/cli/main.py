"""
Hermod CLI entry point.

Implements the commands described in the blueprint (§3, §22):
  hermod serve   – Start the signaling server
  hermod send    – Send a file or text (alias: tx)
  hermod receive – Receive a file or text (alias: rx)
  hermod trust   – Pin a server's certificate

Configuration resolution: CLI Flags > Env Vars > config.yaml > Defaults.
Signal handling for SIGINT/SIGTERM causes a clean async shutdown (§28).

TLS is always required.  Clients must pin the server certificate with
``hermod trust`` before running ``send`` or ``receive``.
"""

from __future__ import annotations

import asyncio
import copy
import importlib.metadata
import logging
import signal
import ssl
import sys
from pathlib import Path
from typing import Annotated, ClassVar, Optional
from urllib.parse import urlparse

import click
import typer
from rich.console import Console
from typer.core import TyperGroup

from hermod.cli.ui import (
    TransferProgress,
    print_error,
    print_info,
    print_sas,
    print_success,
    print_transfer_code,
    print_warning,
)
from hermod.core.config import DEFAULT_PORT, format_listen, load_config, parse_listen
from hermod.core.session import ReceiverSession, SenderSession
from hermod.core.transfer_code import parse_code
from hermod.core.trust import TrustStore

_console = Console(stderr=True)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Aliased command group – shows "send or tx" / "receive or rx" in help
# ---------------------------------------------------------------------------


class _AliasedGroup(TyperGroup):
    """Typer group that collapses alias commands into a single help line.

    Commands listed in ``_ALIAS_MAP`` are hidden from the help listing and
    instead shown next to their primary command as ``primary or alias``.
    The display order is controlled by ``_DISPLAY_ORDER``.
    """

    #: alias name → primary name
    _ALIAS_MAP: ClassVar[dict[str, str]] = {
        "tx": "send",
        "rx": "receive",
    }

    #: Preferred display order for top-level help listing.
    _DISPLAY_ORDER: ClassVar[list[str]] = ["serve", "send", "receive", "trust"]

    def list_commands(self, ctx: click.Context) -> list[str]:
        """Return merged command names (e.g. 'send or tx')."""
        raw = super().list_commands(ctx)

        # Build reverse map: primary → [aliases]
        primary_to_aliases: dict[str, list[str]] = {}
        for alias, primary in self._ALIAS_MAP.items():
            primary_to_aliases.setdefault(primary, []).append(alias)

        merged: list[str] = []
        for name in raw:
            if name in self._ALIAS_MAP:
                continue  # displayed inline with primary
            aliases = primary_to_aliases.get(name, [])
            merged.append(f"{name} or {', '.join(aliases)}" if aliases else name)

        def _sort_key(entry: str) -> int:
            primary = entry.split(" or ")[0]
            try:
                return self._DISPLAY_ORDER.index(primary)
            except ValueError:
                return 999

        return sorted(merged, key=_sort_key)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """Resolve 'primary or alias' display names back to real commands."""
        if " or " in cmd_name:
            actual = cmd_name.split(" or ")[0]
            cmd = super().get_command(ctx, actual)
            if cmd is not None:
                # Return a shallow copy whose .name is the display label so
                # the Rich help panel renders the combined name correctly.
                proxy = copy.copy(cmd)
                proxy.name = cmd_name
                return proxy
        return super().get_command(ctx, cmd_name)


# ---------------------------------------------------------------------------
# Typer application
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="hermod",
    help="Secure peer-to-peer file and text transfer.",
    add_completion=False,
    cls=_AliasedGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# ---------------------------------------------------------------------------
# Verbosity map
# ---------------------------------------------------------------------------

_VERBOSITY_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


# ---------------------------------------------------------------------------
# Global options / callback
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def _global_options(
    ctx: typer.Context,
    verbosity: Annotated[
        str,
        typer.Option(
            "--verbosity",
            help="Logging level (debug, info, warning, error, critical).",
        ),
    ] = "error",
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """Global options applied to all sub-commands."""
    if version:
        v = importlib.metadata.version("hermod-p2p")
        typer.echo(f"hermod {v}")
        raise typer.Exit()

    level = _VERBOSITY_MAP.get(verbosity.lower(), logging.ERROR)
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Show usage when called with no subcommand (on any verbosity).
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()

    # Inject config-sourced defaults so `--help` for each subcommand shows
    # the effective value (configured or application default).
    try:
        _cfg = load_config()

        # Parse the configured server URL to derive a trust target default.
        _parsed = urlparse(_cfg.server)
        _srv_host = _parsed.hostname or "localhost"
        _srv_port = _parsed.port or DEFAULT_PORT
        _trust_default = format_listen(_srv_host, _srv_port)

        # P2P listen defaults: ":PORT" form (empty host = all interfaces).
        _p2p_default = f":{_cfg.p2p_port}"  # ":0" when OS-assigned

        ctx.default_map = {
            "serve": {
                "listen": _cfg.listen,
                "db": _cfg.db_path,
                "ttl": _cfg.ttl,
            },
            # Both the canonical name and the alias need entries so that
            # `hermod send --help` and `hermod tx --help` both show defaults.
            "send": {
                "server": _cfg.server,
                "p2p_listen": _p2p_default,
            },
            "tx": {
                "server": _cfg.server,
                "p2p_listen": _p2p_default,
            },
            "receive": {
                "server": _cfg.server,
                "p2p_listen": _p2p_default,
            },
            "rx": {
                "server": _cfg.server,
                "p2p_listen": _p2p_default,
            },
            "trust": {
                "target": _trust_default,
            },
        }
    except Exception:
        pass  # Config loading failure → subcommands fall back to their own defaults.


# ---------------------------------------------------------------------------
# Trust enforcement helper
# ---------------------------------------------------------------------------


def _require_ssl_context(server_url: str) -> ssl.SSLContext:
    """Return a pinned SSL context for *server_url*, or exit with an error.

    Clients must run ``hermod trust <host:port>`` before sending or receiving.
    """
    from hermod.core.trust import TrustStore, pinned_ssl_context

    store = TrustStore()
    if not store.is_trusted(server_url):
        print_error(
            f"Server {server_url!r} is not trusted.\nRun: hermod trust <host:port>"
        )
        raise typer.Exit(code=1)

    fingerprint = store.get(server_url)
    cert_pem = store.get_cert_pem(server_url)
    if fingerprint is None or cert_pem is None:
        print_error(
            f"Trust entry for {server_url!r} is incomplete (missing cert PEM).\n"
            "Re-run: hermod trust <host:port>"
        )
        raise typer.Exit(code=1)

    return pinned_ssl_context(fingerprint, cert_pem)


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@app.command()
def serve(
    listen: Annotated[
        Optional[str],
        typer.Option(
            "--listen",
            "-l",
            help="Bind address (host:port or [ipv6]:port).",
        ),
    ] = None,
    db: Annotated[
        Optional[str],
        typer.Option("--db", "-d", help="SQLite database path."),
    ] = None,
    ttl: Annotated[
        int,
        typer.Option("--ttl", "-T", help="Channel TTL in seconds."),
    ] = 3600,
) -> None:
    """Start the signaling and NAT helper service (TLS always enabled)."""
    from hermod.core.config import save_config
    from hermod.server.signaling import run_server
    from hermod.server.tls import get_server_ssl_context

    cfg = load_config(overrides={"listen": listen, "ttl": ttl})
    db_path = db if db is not None else cfg.db_path

    # Generate TLS certificate on first run and persist it to config.yaml.
    if not cfg.tls_cert or not cfg.tls_key:
        from hermod.server.tls import generate_self_signed as _gen

        tls_cert, tls_key = _gen()
        from dataclasses import replace as _replace

        cfg = _replace(cfg, tls_cert=tls_cert, tls_key=tls_key)
        save_config(cfg)
        print_info("Generated new TLS certificate — stored in config.yaml")
    else:
        save_config(cfg)

    ssl_context = get_server_ssl_context(cfg.tls_cert, cfg.tls_key)
    print_info("TLS enabled")
    print_info(f"Starting signaling server on {cfg.host}:{cfg.port}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _main() -> None:
        # Wrap run_server in a Task so the signal handler can cancel it cleanly.
        # Calling loop.stop() instead would abort run_until_complete mid-flight
        # and raise RuntimeError, leaving the sweep task pending.
        task: asyncio.Task[None] = asyncio.create_task(
            run_server(
                host=cfg.host,
                port=cfg.port,
                db_path=db_path,
                ttl=ttl,
                ssl_context=ssl_context,
            )
        )

        def _shutdown(sig_name: str) -> None:
            print_info(f"Received {sig_name}; shutting down...")
            task.cancel()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _shutdown, sig.name)

        try:
            await task
        except asyncio.CancelledError:
            pass  # clean shutdown — run_server's finally blocks already ran

    try:
        loop.run_until_complete(_main())
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# send / tx
# ---------------------------------------------------------------------------


def _parse_p2p_listen(value: str) -> tuple[str, int]:
    """Parse a P2P listen string into ``(host, port)``.

    Accepts the same forms as ``--listen`` for serve, plus a bare ``:port``
    shorthand (empty host ≡ all interfaces → ``"0.0.0.0"``).
    """
    host, port = parse_listen(value)
    if not host:
        host = "0.0.0.0"
    return host, port


@app.command(name="send")
def transmit(
    file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="Path to local file."),
    ] = None,
    text: Annotated[
        Optional[str],
        typer.Option("--text", "-t", help="Literal text. Use '-' to read stdin."),
    ] = None,
    server: Annotated[
        Optional[str],
        typer.Option(
            "--server",
            "-s",
            help="Signaling server URL (e.g. wss://host:port).",
        ),
    ] = None,
    verify: Annotated[
        bool,
        typer.Option("--verify", "-v", help="Enforce SAS out-of-band verification."),
    ] = False,
    p2p_listen: Annotated[
        str,
        typer.Option(
            "--listen",
            "-l",
            help="P2P bind address (host:port, \\[ipv6]:port, or :port). :0 = OS-assigned.",
        ),
    ] = ":0",
) -> None:
    """Send a file or text to a peer."""
    cfg = load_config(overrides={"server": server})
    ssl_context = _require_ssl_context(cfg.server)

    # Resolve payload
    resolved_text: str | None = None
    resolved_file: Path | None = None

    if text == "-":
        resolved_text = sys.stdin.read()
    elif text is not None:
        resolved_text = text
    elif file is not None:
        if not file.exists():
            print_error(f"File not found: {file}")
            raise typer.Exit(code=1)
        resolved_file = file
    else:
        if not sys.stdin.isatty():
            resolved_text = sys.stdin.read()
        else:
            print_error("Provide --file or --text (or pipe via stdin).")
            raise typer.Exit(code=1)

    p2p_host, p2p_port = _parse_p2p_listen(p2p_listen)
    # CLI flag takes precedence over config value for the port.
    if p2p_port == 0 and cfg.p2p_port:
        p2p_port = cfg.p2p_port

    total_bytes = (
        resolved_file.stat().st_size
        if resolved_file
        else len((resolved_text or "").encode())
    )
    label = resolved_file.name if resolved_file else "text message"

    progress = TransferProgress(f"Sending [cyan]{label}[/cyan]", total_bytes)

    def _on_progress(sent: int, total: int) -> None:
        progress.update(sent, total)

    session = SenderSession(
        server_url=cfg.server,
        file_path=resolved_file,
        text=resolved_text,
        ssl_context=ssl_context,
        verify_sas=verify,
        progress_callback=_on_progress,
        peer_wait_timeout=float(cfg.ttl),
        p2p_port=p2p_port,
        p2p_host=p2p_host,
    )

    # Display the transfer code as soon as the channel is registered,
    # before the progress bar starts (the sender waits for the receiver).
    def _on_code(code: str) -> None:
        print_transfer_code(code)

    session.code_callback = _on_code

    async def _run() -> None:
        with progress:
            result = await session.run()

        if result.success:
            print_success(f"Sent {result.bytes_transferred:,} bytes")
            if result.sas and verify:
                print_sas(result.sas)
        else:
            print_error(f"Transfer failed: {result.error}")
            raise typer.Exit(code=1)

    try:
        asyncio.run(_run())
    except (KeyboardInterrupt, SystemExit):
        print_warning("Transfer interrupted.")
        raise typer.Exit(code=130)
    except (ConnectionError, ValueError, OSError) as exc:
        # Expected user-facing conditions (wrong channel, refused connection,
        # invalid code, …).  Print the message cleanly — no traceback.
        print_error(str(exc))
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        logger.exception("send command failed")
        raise typer.Exit(code=1)


# Alias: `hermod tx` → same as `hermod send`
app.command(name="tx")(transmit)


# ---------------------------------------------------------------------------
# receive / rx
# ---------------------------------------------------------------------------


@app.command(name="receive")
def receive(
    code: Annotated[str, typer.Argument(help="Transfer code from sender.")],
    destination: Annotated[
        Path,
        typer.Option("--destination", "-d", help="Output directory or file path."),
    ] = Path("."),
    server: Annotated[
        Optional[str],
        typer.Option(
            "--server",
            "-s",
            help="Signaling server URL (e.g. wss://host:port).",
        ),
    ] = None,
    verify: Annotated[
        bool,
        typer.Option("--verify", "-v", help="Enforce SAS out-of-band verification."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Auto-accept all prompts."),
    ] = False,
    p2p_listen: Annotated[
        str,
        typer.Option(
            "--listen",
            "-l",
            help="P2P bind address (host:port, \\[ipv6]:port, or :port). :0 = OS-assigned.",
        ),
    ] = ":0",
) -> None:
    """Receive a file or text from a peer."""
    cfg = load_config(overrides={"server": server, "dest_dir": str(destination)})
    ssl_context = _require_ssl_context(cfg.server)

    try:
        parse_code(code)
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)

    dest = destination if destination != Path(".") else Path(cfg.dest_dir)

    p2p_host, p2p_port = _parse_p2p_listen(p2p_listen)
    # CLI flag takes precedence over config value for the port.
    if p2p_port == 0 and cfg.p2p_port:
        p2p_port = cfg.p2p_port

    progress = TransferProgress("Receiving", total=0)

    def _on_progress(received: int, total: int) -> None:
        # Update total dynamically when metadata arrives
        if progress._total != total and total > 0:
            progress._total = total
            if progress._task_id is not None:
                progress._progress.update(progress._task_id, total=total)
        progress.update(received, total)

    session = ReceiverSession(
        server_url=cfg.server,
        code=code,
        destination=dest,
        ssl_context=ssl_context,
        verify_sas=verify,
        auto_accept=yes,
        progress_callback=_on_progress,
        p2p_port=p2p_port,
        p2p_host=p2p_host,
    )

    async def _run() -> None:
        print_info(f"Connecting to {cfg.server}...")
        with progress:
            result = await session.run()

        if result.success:
            if result.text_content is not None:
                sys.stdout.write(result.text_content)
                if not result.text_content.endswith("\n"):
                    sys.stdout.write("\n")
                sys.stdout.flush()
            else:
                msg = (
                    f"Saved to [cyan]{result.output_path}[/cyan] "
                    f"({result.bytes_transferred:,} bytes)"
                )
                print_success(msg)
            if result.sas and verify:
                print_sas(result.sas)
        else:
            print_error(f"Transfer failed: {result.error}")
            raise typer.Exit(code=1)

    try:
        asyncio.run(_run())
    except (KeyboardInterrupt, SystemExit):
        print_warning("Transfer interrupted.")
        raise typer.Exit(code=130)
    except (ConnectionError, ValueError, OSError) as exc:
        # Expected user-facing conditions (wrong channel, refused connection,
        # invalid code, …).  Print the message cleanly — no traceback.
        print_error(str(exc))
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        logger.exception("receive command failed")
        raise typer.Exit(code=1)


# Alias: `hermod rx` → same as `hermod receive`
app.command(name="rx")(receive)


# ---------------------------------------------------------------------------
# trust
# ---------------------------------------------------------------------------


@app.command()
def trust(
    target: Annotated[
        Optional[str],
        typer.Argument(help="Server hostname or host:port (e.g. my-relay.local:8443)."),
    ] = None,
) -> None:
    """Fetch and pin the public certificate of a signaling server."""
    import hashlib
    import socket as _socket

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from hermod.core.config import save_config

    if target is None:
        print_error(
            "No target specified and no server configured.\n"
            "Usage: hermod trust <host:port>"
        )
        raise typer.Exit(code=1)

    try:
        host, port = parse_listen(target)
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)

    url = f"wss://{format_listen(host, port)}"
    print_info(f"Fetching certificate from {host}:{port}...")

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with _socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)

        if der is None:
            raise ValueError("No certificate returned by server")

        fingerprint = hashlib.sha256(der).hexdigest()

        # Convert DER → PEM so clients can build a pinned SSL context
        cert_obj = x509.load_der_x509_certificate(der)
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)

        store = TrustStore()
        store.add(url, fingerprint, cert_pem)

        # Also persist this server as the default so send/receive work without --server.
        from dataclasses import replace as _replace

        _cfg = load_config()
        if _cfg.server != url:
            save_config(_replace(_cfg, server=url))

        print_success(f"Certificate pinned for {url}")
        _console.print(f"  SHA-256: [dim]{fingerprint}[/dim]")

    except Exception as exc:
        print_error(f"Failed to fetch certificate: {exc}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Package entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
