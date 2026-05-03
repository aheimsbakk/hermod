"""
Rich-based UI helpers for the Hermod CLI.

Provides progress bars, status spinners, transfer result display, and
styled console output. All output goes to ``stderr`` to keep ``stdout``
clean for piping.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

# All UI output to stderr so stdout remains scriptable
_console = Console(stderr=True)
_err_console = Console(stderr=True, style="bold red")


def print_info(msg: str) -> None:
    """Print an informational message."""
    _console.print(f"[cyan]ℹ[/cyan]  {msg}")


def print_success(msg: str) -> None:
    """Print a success message."""
    _console.print(f"[green]✔[/green]  {msg}")


def print_warning(msg: str) -> None:
    """Print a warning message."""
    _console.print(f"[yellow]⚠[/yellow]  {msg}")


def print_error(msg: str) -> None:
    """Print an error message."""
    _err_console.print(f"✘  {msg}")


def print_transfer_code(code: str) -> None:
    """Display the transfer code prominently."""
    _console.print()
    _console.rule("[bold cyan]Transfer Code")
    _console.print(f"\n  [bold white on blue]  {code}  [/bold white on blue]\n")
    _console.print("  Share this code with the receiver. Waiting for connection...\n")


def print_sas(sas: str) -> None:
    """Display the Short Authentication String."""
    _console.print()
    _console.rule("[bold yellow]Security Verification")
    _console.print(
        f"\n  Verification code: [bold yellow]{sas}[/bold yellow]\n\n"
        "  Read this code aloud to your peer. "
        "If they see the same string, the connection is secure.\n"
    )


def make_progress() -> Progress:
    """Create a Rich :class:`Progress` instance for file transfer display."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=_console,
        transient=True,
    )


class TransferProgress:
    """Context manager wrapping Rich progress for a single transfer task.

    Parameters
    ----------
    description:
        Short label shown next to the progress bar.
    total:
        Total byte count (file size).
    """

    def __init__(self, description: str, total: int) -> None:
        self._desc = description
        self._total = total
        self._progress = make_progress()
        self._task_id: TaskID | None = None

    def __enter__(self) -> "TransferProgress":
        self._progress.__enter__()
        self._task_id = self._progress.add_task(self._desc, total=self._total)
        return self

    def __exit__(self, *_: Any) -> None:
        self._progress.__exit__(None, None, None)

    def update(self, bytes_done: int, _total: int | None = None) -> None:
        """Advance the progress bar to *bytes_done*."""
        if self._task_id is not None:
            self._progress.update(self._task_id, completed=bytes_done)

    def finish(self) -> None:
        """Mark the task as complete."""
        if self._task_id is not None:
            self._progress.update(self._task_id, completed=self._total)
