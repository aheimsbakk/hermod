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

import argparse
import asyncio
import importlib.metadata
import logging
import signal
import ssl
import sys
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

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
from hermod.core.config import DEFAULT_PORT, format_listen, load_config, parse_listen
from hermod.core.session import ReceiverSession, SenderSession
from hermod.core.transfer_code import parse_code
from hermod.core.trust import TrustStore

_console = Console(stderr=True)
logger = logging.getLogger(__name__)

_VERBOSITY_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


# ---------------------------------------------------------------------------
# Custom help formatter – shows "send, tx" style aliases cleanly
# ---------------------------------------------------------------------------


class _CompactHelpFormatter(RawDescriptionHelpFormatter):
    """Formatter that widens the option column slightly for readability."""

    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        kwargs.setdefault("max_help_position", 32)
        kwargs.setdefault("width", 90)
        super().__init__(*args, **kwargs)


# ---------------------------------------------------------------------------
# Argument parser construction
# ---------------------------------------------------------------------------


def _build_parser() -> ArgumentParser:
    """Build and return the top-level argument parser."""
    # Load config upfront so we can show effective defaults in help text.
    try:
        _cfg = load_config()
        _default_server = _cfg.server
        _default_listen = _cfg.listen
        _default_db = _cfg.db_path
        _default_ttl = _cfg.ttl
        _default_p2p = f":{_cfg.p2p_port}"
        _parsed = urlparse(_cfg.server)
        _srv_host = _parsed.hostname or "localhost"
        _srv_port = _parsed.port or DEFAULT_PORT
        _default_trust_target = format_listen(_srv_host, _srv_port)
    except Exception:
        _default_server = "wss://localhost:8786"
        _default_listen = "0.0.0.0:8786"
        _default_db = "~/.hermod/signaling.db"
        _default_ttl = 3600
        _default_p2p = ":0"
        _default_trust_target = "localhost:8786"

    parser = ArgumentParser(
        prog="hermod",
        description="Secure peer-to-peer file and text transfer.",
        formatter_class=_CompactHelpFormatter,
        add_help=True,
    )
    parser.add_argument(
        "--verbosity",
        metavar="LEVEL",
        default="error",
        choices=list(_VERBOSITY_MAP),
        help="Logging level (debug, info, warning, error, critical). Default: error.",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"hermod {importlib.metadata.version('hermod-p2p')}",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ------------------------------------------------------------------ serve
    p_serve = sub.add_parser(
        "serve",
        help="Start the signaling and NAT helper service.",
        description="Start the signaling and NAT helper service (TLS always enabled).",
        formatter_class=_CompactHelpFormatter,
    )
    p_serve.add_argument(
        "--listen",
        "-l",
        metavar="ADDR",
        default=_default_listen,
        help=f"Bind address (host:port or [ipv6]:port). Default: {_default_listen}",
    )
    p_serve.add_argument(
        "--db",
        "-d",
        metavar="PATH",
        default=_default_db,
        help=f"SQLite database path. Default: {_default_db}",
    )
    p_serve.add_argument(
        "--ttl",
        "-T",
        metavar="SECONDS",
        type=int,
        default=_default_ttl,
        help=f"Channel TTL in seconds. Default: {_default_ttl}",
    )

    # ------------------------------------------------------------------ send
    _send_epilog = """\
examples:
  hermod send myfile.bin          # existing file -> sent as file
  hermod send "hello world"       # non-path string -> sent as text
  hermod send -                   # read stdin
  echo "text" | hermod send       # stdin auto-detected when piped
  hermod send < myfile.bin        # binary stdin -> sent as file named 'stdin'
"""
    p_send = sub.add_parser(
        "send",
        aliases=["tx"],
        help="Send a file or text to a peer.  (alias: tx)",
        description="Send a file or text to a peer.",
        epilog=_send_epilog,
        formatter_class=_CompactHelpFormatter,
    )
    p_send.add_argument(
        "source",
        nargs="?",
        metavar="INPUT",
        default=None,
        help=(
            "File path, text string, or '-' for stdin. "
            "Omit to read stdin when data is piped."
        ),
    )
    p_send.add_argument(
        "--server",
        "-s",
        metavar="URL",
        default=_default_server,
        help=f"Signaling server URL. Default: {_default_server}",
    )
    p_send.add_argument(
        "--verify",
        "-v",
        action="store_true",
        default=False,
        help="Enforce SAS out-of-band verification.",
    )
    p_send.add_argument(
        "--listen",
        "-l",
        dest="p2p_listen",
        metavar="ADDR",
        default=_default_p2p,
        help=f"P2P bind address (host:port, [ipv6]:port, or :port). Default: {_default_p2p}",
    )

    # --------------------------------------------------------------- receive
    _recv_epilog = """\
examples:
  hermod receive <code>           # text printed; file saved with original name
  hermod receive <code> > out     # entire payload streamed to stdout
  hermod receive <code> -d /tmp   # always save to /tmp
"""
    p_recv = sub.add_parser(
        "receive",
        aliases=["rx"],
        help="Receive a file or text from a peer.  (alias: rx)",
        description="Receive a file or text from a peer.",
        epilog=_recv_epilog,
        formatter_class=_CompactHelpFormatter,
    )
    p_recv.add_argument(
        "code",
        metavar="CODE",
        help="Transfer code from the sender.",
    )
    p_recv.add_argument(
        "--destination",
        "-d",
        metavar="PATH",
        default=None,
        type=Path,
        help=(
            "Directory or file path for output. "
            "Omit to auto-stream: text printed, file saved (or streamed to stdout when "
            "stdout is redirected)."
        ),
    )
    p_recv.add_argument(
        "--server",
        "-s",
        metavar="URL",
        default=_default_server,
        help=f"Signaling server URL. Default: {_default_server}",
    )
    p_recv.add_argument(
        "--verify",
        "-v",
        action="store_true",
        default=False,
        help="Enforce SAS out-of-band verification.",
    )
    p_recv.add_argument(
        "--yes",
        "-y",
        action="store_true",
        default=False,
        help="Auto-accept all prompts.",
    )
    p_recv.add_argument(
        "--listen",
        "-l",
        dest="p2p_listen",
        metavar="ADDR",
        default=_default_p2p,
        help=f"P2P bind address (host:port, [ipv6]:port, or :port). Default: {_default_p2p}",
    )

    # ----------------------------------------------------------------- trust
    p_trust = sub.add_parser(
        "trust",
        help="Fetch and pin a server's TLS certificate.",
        description="Fetch and pin the public certificate of a signaling server.",
        formatter_class=_CompactHelpFormatter,
    )
    p_trust.add_argument(
        "target",
        nargs="?",
        metavar="HOST[:PORT]",
        default=_default_trust_target,
        help=f"Server hostname or host:port. Default: {_default_trust_target}",
    )

    return parser


# ---------------------------------------------------------------------------
# SSL / trust helper
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
        sys.exit(1)

    fingerprint = store.get(server_url)
    cert_pem = store.get_cert_pem(server_url)
    if fingerprint is None or cert_pem is None:
        print_error(
            f"Trust entry for {server_url!r} is incomplete (missing cert PEM).\n"
            "Re-run: hermod trust <host:port>"
        )
        sys.exit(1)

    return pinned_ssl_context(fingerprint, cert_pem)


# ---------------------------------------------------------------------------
# P2P listen helper
# ---------------------------------------------------------------------------


def _parse_p2p_listen(value: str) -> tuple[str, int]:
    """Parse a P2P listen string into ``(host, port)``.

    Accepts ``host:port``, ``[ipv6]:port``, or bare ``:port``
    (empty host ≡ all interfaces → ``"0.0.0.0"``).
    """
    host, port = parse_listen(value)
    if not host:
        host = "0.0.0.0"
    return host, port


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _cmd_serve(args: Namespace) -> None:
    """Start the signaling server."""
    from hermod.core.config import save_config
    from hermod.server.signaling import run_server
    from hermod.server.tls import get_server_ssl_context

    cfg = load_config(overrides={"listen": args.listen, "ttl": args.ttl})
    db_path: str = args.db

    if not cfg.tls_cert or not cfg.tls_key:
        from dataclasses import replace as _replace
        from hermod.server.tls import generate_self_signed as _gen

        tls_cert, tls_key = _gen()
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
        task: asyncio.Task[None] = asyncio.create_task(
            run_server(
                host=cfg.host,
                port=cfg.port,
                db_path=db_path,
                ttl=args.ttl,
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


def _cmd_send(args: Namespace) -> None:
    """Send a file or text to a peer."""
    cfg = load_config(overrides={"server": args.server})
    ssl_context = _require_ssl_context(cfg.server)

    # --- Payload resolution -------------------------------------------
    resolved_text: Optional[str] = None
    resolved_file: Optional[Path] = None
    resolved_raw_bytes: Optional[bytes] = None

    read_stdin = args.source == "-" or (args.source is None and not sys.stdin.isatty())

    if read_stdin:
        raw_data = sys.stdin.buffer.read()
        try:
            resolved_text = raw_data.decode("utf-8")
        except UnicodeDecodeError:
            resolved_raw_bytes = raw_data
    elif args.source is not None:
        candidate = Path(args.source)
        if candidate.exists():
            resolved_file = candidate
        else:
            resolved_text = args.source
    else:
        print_error(
            "Provide a file path, a text string, or pipe data via stdin.\n"
            "Examples:\n"
            "  hermod send myfile.bin\n"
            '  hermod send "hello world"\n'
            "  echo text | hermod send"
        )
        sys.exit(1)

    if resolved_file is not None and not resolved_file.exists():
        print_error(f"File not found: {resolved_file}")
        sys.exit(1)

    p2p_host, p2p_port = _parse_p2p_listen(args.p2p_listen)
    if p2p_port == 0 and cfg.p2p_port:
        p2p_port = cfg.p2p_port

    if resolved_file is not None:
        total_bytes = resolved_file.stat().st_size
        label = resolved_file.name
    elif resolved_raw_bytes is not None:
        total_bytes = len(resolved_raw_bytes)
        label = "stdin"
    else:
        total_bytes = len((resolved_text or "").encode())
        label = "text message"

    progress = TransferProgress(f"Sending [cyan]{label}[/cyan]", total_bytes)

    session = SenderSession(
        server_url=cfg.server,
        file_path=resolved_file,
        text=resolved_text,
        raw_bytes=resolved_raw_bytes,
        ssl_context=ssl_context,
        verify_sas=args.verify,
        progress_callback=lambda sent, total: progress.update(sent, total),
        peer_wait_timeout=float(cfg.ttl),
        p2p_port=p2p_port,
        p2p_host=p2p_host,
    )
    session.code_callback = lambda code: print_transfer_code(code)

    try:
        with progress:
            result = asyncio.run(session.run())
    except KeyboardInterrupt:
        print_warning("Transfer interrupted.")
        sys.exit(130)
    except (ConnectionError, ValueError, OSError) as exc:
        print_error(str(exc))
        sys.exit(1)
    except Exception as exc:
        print_error(str(exc))
        logger.exception("send command failed")
        sys.exit(1)

    if result.success:
        print_success(f"Sent {result.bytes_transferred:,} bytes")
        if result.sas and args.verify:
            print_sas(result.sas)
    else:
        print_error(f"Transfer failed: {result.error}")
        sys.exit(1)


def _cmd_receive(args: Namespace) -> None:
    """Receive a file or text from a peer."""
    cfg = load_config(
        overrides={"server": args.server, "dest_dir": str(args.destination or ".")}
    )
    ssl_context = _require_ssl_context(cfg.server)

    try:
        parse_code(args.code)
    except ValueError as exc:
        print_error(str(exc))
        sys.exit(1)

    dest = args.destination if args.destination is not None else Path(cfg.dest_dir)
    use_stdout = args.destination is None and not sys.stdout.isatty()
    output_sink = sys.stdout.buffer if use_stdout else None

    p2p_host, p2p_port = _parse_p2p_listen(args.p2p_listen)
    if p2p_port == 0 and cfg.p2p_port:
        p2p_port = cfg.p2p_port

    progress = TransferProgress("Receiving", total=0)

    def _on_progress(received: int, total: int) -> None:
        if progress._total != total and total > 0:
            progress._total = total
            if progress._task_id is not None:
                progress._progress.update(progress._task_id, total=total)
        progress.update(received, total)

    session = ReceiverSession(
        server_url=cfg.server,
        code=args.code,
        destination=dest,
        ssl_context=ssl_context,
        verify_sas=args.verify,
        auto_accept=args.yes,
        progress_callback=_on_progress,
        p2p_port=p2p_port,
        p2p_host=p2p_host,
        output_sink=output_sink,
    )

    print_info(f"Connecting to {cfg.server}...")

    try:
        with progress:
            result = asyncio.run(session.run())
    except KeyboardInterrupt:
        print_warning("Transfer interrupted.")
        sys.exit(130)
    except (ConnectionError, ValueError, OSError) as exc:
        print_error(str(exc))
        sys.exit(1)
    except Exception as exc:
        print_error(str(exc))
        logger.exception("receive command failed")
        sys.exit(1)

    if result.success:
        if use_stdout:
            pass  # payload already written directly to sys.stdout.buffer
        elif result.text_content is not None:
            sys.stdout.write(result.text_content)
            if not result.text_content.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            print_success(
                f"Saved to [cyan]{result.output_path}[/cyan] "
                f"({result.bytes_transferred:,} bytes)"
            )
        if result.sas and args.verify:
            print_sas(result.sas)
    else:
        print_error(f"Transfer failed: {result.error}")
        sys.exit(1)


def _cmd_trust(args: Namespace) -> None:
    """Fetch and pin a server certificate."""
    import hashlib
    import socket as _socket

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from hermod.core.config import save_config

    target: Optional[str] = args.target
    if not target:
        print_error(
            "No target specified and no server configured.\n"
            "Usage: hermod trust <host:port>"
        )
        sys.exit(1)

    try:
        host, port = parse_listen(target)
    except ValueError as exc:
        print_error(str(exc))
        sys.exit(1)

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

        cert_obj = x509.load_der_x509_certificate(der)
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)

        store = TrustStore()
        store.add(url, fingerprint, cert_pem)

        from dataclasses import replace as _replace

        _cfg = load_config()
        if _cfg.server != url:
            save_config(_replace(_cfg, server=url))

        print_success(f"Certificate pinned for {url}")
        _console.print(f"  SHA-256: [dim]{fingerprint}[/dim]")

    except Exception as exc:
        print_error(f"Failed to fetch certificate: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_HANDLERS = {
    "serve": _cmd_serve,
    "send": _cmd_send,
    "tx": _cmd_send,
    "receive": _cmd_receive,
    "rx": _cmd_receive,
    "trust": _cmd_trust,
}


def main() -> None:
    """Parse arguments and dispatch to the appropriate command handler."""
    parser = _build_parser()
    args = parser.parse_args()

    # Configure logging from the global --verbosity flag.
    level = _VERBOSITY_MAP.get((args.verbosity or "error").lower(), logging.ERROR)
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handler = _HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(args)


if __name__ == "__main__":
    main()
