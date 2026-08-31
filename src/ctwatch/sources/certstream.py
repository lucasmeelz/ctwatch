"""The live feed of newly issued certificates.

CertStream relays every certificate as the logs receive it. That is a great
deal of traffic — several hundred a second at busy times — and almost none of
it is relevant. Nothing is stored on the way past: a message is parsed, offered
to the matcher, and dropped unless it hit something. Only the messages that
matched are archived, which is what keeps a monitor that runs for weeks from
filling a disk with other people's certificates.

The public server is a single point of failure and is regularly unavailable.
This client reconnects with growing delays and, after a configured number of
consecutive failures, gives up loudly so the caller can fall back to polling
rather than sit silently on a dead socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from ctwatch.timeutil import parse_iso, utc_now

DEFAULT_URL = "wss://certstream.calidog.io/"


class StreamUnavailableError(RuntimeError):
    """Raised when the feed could not be kept open."""

    def __init__(self, message: str, *, failures: int) -> None:
        super().__init__(message)
        self.failures = failures


@dataclass(frozen=True, slots=True)
class StreamedCertificate:
    """One certificate as the feed described it."""

    names: tuple[str, ...]
    raw_message: bytes
    seen_at: datetime
    not_before: datetime | None = None
    not_after: datetime | None = None
    fingerprint: str | None = None
    issuer: str | None = None
    log_name: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class WebSocketLike(Protocol):
    """Just enough of a websocket connection to read messages from it."""

    def __aiter__(self) -> AsyncIterator[str | bytes]: ...


class ConnectLike(Protocol):
    """The shape of ``websockets.connect``, so a test can supply its own."""

    def __call__(self, url: str, /, *args: Any, **kwargs: Any) -> Any: ...


def _moment(raw: Any) -> datetime | None:
    if raw in (None, ""):
        return None
    if isinstance(raw, int | float):
        try:
            return datetime.fromtimestamp(float(raw), tz=utc_now().tzinfo)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        return parse_iso(str(raw))
    except ValueError:
        return None


def parse_message(payload: str | bytes) -> StreamedCertificate | None:
    """Read one feed message, or return ``None`` if it carries no certificate.

    The feed mixes heartbeats and the occasional malformed frame in with the
    certificates. None of that is worth an exception.
    """

    raw_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    try:
        message: Any = json.loads(raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(message, dict):
        return None

    if message.get("message_type") == "heartbeat":
        return None

    data = message.get("data")
    if not isinstance(data, dict):
        return None

    leaf = data.get("leaf_cert")
    if not isinstance(leaf, dict):
        return None

    names = tuple(
        str(name) for name in leaf.get("all_domains", []) if isinstance(name, str) and name.strip()
    )
    if not names:
        return None

    issuer = leaf.get("issuer")
    issuer_name = None
    if isinstance(issuer, dict):
        issuer_name = issuer.get("aggregated") or issuer.get("O") or issuer.get("CN")

    source = data.get("source")
    log_name = source.get("name") if isinstance(source, dict) else None

    return StreamedCertificate(
        names=names,
        raw_message=raw_bytes,
        seen_at=_moment(data.get("seen")) or utc_now(),
        not_before=_moment(leaf.get("not_before")),
        not_after=_moment(leaf.get("not_after")),
        fingerprint=(
            str(leaf["fingerprint"]).replace(":", "").lower() if leaf.get("fingerprint") else None
        ),
        issuer=None if issuer_name is None else str(issuer_name),
        log_name=None if log_name is None else str(log_name),
        raw=message,
    )


class CertStreamClient:
    """Keeps a feed open, reconnecting until it is told to stop trying."""

    def __init__(
        self,
        *,
        url: str = DEFAULT_URL,
        connect: ConnectLike | None = None,
        reconnect_delay: float = 5.0,
        max_reconnect_delay: float = 300.0,
        max_consecutive_failures: int = 5,
        on_disconnect: Callable[[int, str], None] | None = None,
    ) -> None:
        self._url = url
        self._connect = connect
        self._reconnect_delay = max(0.0, reconnect_delay)
        self._max_reconnect_delay = max(self._reconnect_delay, max_reconnect_delay)
        self._max_failures = max(1, max_consecutive_failures)
        self._on_disconnect = on_disconnect

    def _connector(self) -> ConnectLike:
        if self._connect is not None:
            return self._connect
        import websockets  # imported here so the module is usable without it

        return websockets.connect

    def _delay(self, failures: int) -> float:
        ceiling = min(self._reconnect_delay * (2 ** (failures - 1)), self._max_reconnect_delay)
        return random.uniform(0.0, ceiling) if ceiling > 0 else 0.0

    async def stream(self) -> AsyncIterator[StreamedCertificate]:
        """Yield certificates until the feed stays down past its budget."""

        connect = self._connector()
        failures = 0

        while failures < self._max_failures:
            try:
                async with connect(self._url) as socket:
                    failures = 0
                    async for payload in socket:
                        certificate = parse_message(payload)
                        if certificate is not None:
                            yield certificate
            except asyncio.CancelledError:
                raise
            # Any transport failure is a disconnect; the feed is not a
            # service whose error taxonomy is worth modelling.
            except Exception as exc:
                failures += 1
                if self._on_disconnect is not None:
                    self._on_disconnect(failures, f"{type(exc).__name__}: {exc}")
                if failures >= self._max_failures:
                    break
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.sleep(self._delay(failures))
                continue

            # A clean close is still a disconnect: the feed ended on us.
            failures += 1
            if self._on_disconnect is not None:
                self._on_disconnect(failures, "the feed closed the connection")
            if failures < self._max_failures:
                await asyncio.sleep(self._delay(failures))

        msg = (
            f"the certificate feed at {self._url} could not be kept open "
            f"after {failures} attempt(s)"
        )
        raise StreamUnavailableError(msg, failures=failures)
