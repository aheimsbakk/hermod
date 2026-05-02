"""
PAKE (Password-Authenticated Key Exchange) abstraction.

Implements the Strategy / Adapter pattern described in the blueprint (§12).
The ``PAKEEngine`` Protocol defines the interface; ``SPAKE2Adapter`` wraps the
``spake2`` library so it is completely isolated from the rest of the codebase.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class PAKEEngine(Protocol):
    """Interface that every PAKE implementation must satisfy."""

    def start(self) -> bytes:
        """Return the outbound PAKE message to send to the peer."""
        ...

    def finish(self, inbound: bytes) -> bytes:
        """Consume the peer's message and return the derived shared key."""
        ...


class SPAKE2Adapter:
    """Adapter that wraps the ``spake2`` library behind :class:`PAKEEngine`.

    The ``spake2`` library is *only* imported inside this class, so it can
    be substituted or mocked without touching any other module.

    Parameters
    ----------
    password:
        The shared passphrase (transfer code words), UTF-8 encoded.
    is_sender:
        ``True`` → use SPAKE2_A (sender role).
        ``False`` → use SPAKE2_B (receiver role).
    """

    def __init__(self, password: bytes, *, is_sender: bool) -> None:
        try:
            from spake2 import SPAKE2_A, SPAKE2_B
        except ImportError as exc:
            raise ImportError(
                "spake2 package is required. Install it: pip install spake2"
            ) from exc

        self._impl = SPAKE2_A(password) if is_sender else SPAKE2_B(password)
        self._started = False
        self._finished = False

    # ------------------------------------------------------------------
    # PAKEEngine implementation
    # ------------------------------------------------------------------

    def start(self) -> bytes:
        """Generate and return the outbound PAKE message."""
        if self._started:
            raise RuntimeError("start() may only be called once")
        msg = self._impl.start()
        self._started = True
        return msg

    def finish(self, inbound: bytes) -> bytes:
        """Complete the PAKE exchange and return the derived key.

        Raises
        ------
        RuntimeError
            If called before :meth:`start` or called more than once.
        """
        if not self._started:
            raise RuntimeError("Must call start() before finish()")
        if self._finished:
            raise RuntimeError("finish() may only be called once")
        key = self._impl.finish(inbound)
        self._finished = True
        return key
