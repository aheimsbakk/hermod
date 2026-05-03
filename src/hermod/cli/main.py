"""
Hermod CLI entry point.

Implements the commands described in the blueprint (§3, §22):
  hermod serve   – Start the signaling server
  hermod tx      – Send a file or text
  hermod rx      – Receive a file or text
  hermod trust   – Pin a server's certificate

Configuration resolution: CLI Flags > Env Vars > config.yaml > Defaults.
Signal handling for SIGINT/SIGTERM causes a clean async shutdown (§28).

TLS is always required.  Clients must pin the server certificate with
``hermod trust`` before running ``tx`` or ``rx``.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import ssl
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from hermod.cli.ui import (
    TransferProgress,
    print_error,
    print_info,
    print_sas,
    print_success,
    print_transfer_code,
    print_warning,
)
from hermod.core.config import load_config
from hermod.core.session import ReceiverSession, SenderSession
from hermod.core.transfer_code import parse_code
from hermod.core.trust import TrustStore

_console = Console(stderr=True)
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="hermod",
    help="Secure peer-to-peer file and text transfer.",
    add_completion=False,
)

# ---------------------------------------------------------------------------
# Global verbosity option
# ---------------------------------------------------------------------------

_VERBOSITY_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


@app.callback()
def _global_options(
    verbosity: Annotated[
        str,
        typer.Option(
            "--verbosity",
            help="Logging level (debug, info, warning, error, critical).",
        ),
    ] = "warning",
) -> None:
    """Global options applied to all sub-commands."""
    level = _VERBOSITY_MAP.get(verbosity.lower(), logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


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
    port: Annotated[int, typer.Option("--port", "-p", help="Bind port.")] = 8786,
    host: Annotated[
        str, typer.Option("--host", "-h", help="Bind interface.")
    ] = "0.0.0.0",
    db: Annotated[
        str,
        typer.Option("--db", "-d", help="SQLite database path."),
    ] = "",
    ttl: Annotated[
        int,
        typer.Option("--ttl", "-T", help="Channel TTL in seconds."),
    ] = 3600,
) -> None:
    """Start the signaling and NAT helper service (TLS always enabled)."""
    from hermod.core.config import save_config
    from hermod.server.signaling import run_server
    from hermod.server.tls import get_server_ssl_context

    cfg = load_config(overrides={"port": port, "host": host, "ttl": ttl})
    db_path = db or cfg.db_path

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
    print_info(f"Starting signaling server on {host}:{port}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _shutdown(sig_name: str) -> None:
        print_info(f"Received {sig_name}; shutting down...")
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown, sig.name)

    try:
        loop.run_until_complete(
            run_server(
                host=host,
                port=port,
                db_path=db_path,
                ttl=ttl,
                ssl_context=ssl_context,
            )
        )
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# tx / send
# ---------------------------------------------------------------------------


@app.command(name="tx")
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
        typer.Option("--server", "-s", help="Signaling server URL."),
    ] = None,
    verify: Annotated[
        bool,
        typer.Option("--verify", "-v", help="Enforce SAS out-of-band verification."),
    ] = False,
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
    except Exception as exc:
        print_error(str(exc))
        logger.exception("tx command failed")
        raise typer.Exit(code=1)


# Alias: `hermod send` → same as `hermod tx`
app.command(name="send")(transmit)


# ---------------------------------------------------------------------------
# rx / receive
# ---------------------------------------------------------------------------


@app.command(name="rx")
def receive(
    code: Annotated[str, typer.Argument(help="Transfer code from sender.")],
    destination: Annotated[
        Path,
        typer.Option("--destination", "-d", help="Output directory or file path."),
    ] = Path("."),
    server: Annotated[
        Optional[str],
        typer.Option("--server", "-s", help="Signaling server URL."),
    ] = None,
    verify: Annotated[
        bool,
        typer.Option("--verify", "-v", help="Enforce SAS out-of-band verification."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Auto-accept all prompts."),
    ] = False,
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
    )

    async def _run() -> None:
        print_info(f"Connecting to {cfg.server}...")
        with progress:
            result = await session.run()

        if result.success:
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
    except Exception as exc:
        print_error(str(exc))
        logger.exception("rx command failed")
        raise typer.Exit(code=1)


# Alias: `hermod receive` → same as `hermod rx`
app.command(name="receive")(receive)


# ---------------------------------------------------------------------------
# trust
# ---------------------------------------------------------------------------


@app.command()
def trust(
    target: Annotated[
        str,
        typer.Argument(help="Server hostname or host:port (e.g. my-relay.local:8443)."),
    ],
) -> None:
    """Fetch and pin the public certificate of a signaling server."""
    import hashlib
    import socket as _socket

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    if ":" in target:
        host, _, port_str = target.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            print_error(f"Invalid port in target: {port_str!r}")
            raise typer.Exit(code=1)
    else:
        host = target
        port = 443

    url = f"wss://{host}:{port}"
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
