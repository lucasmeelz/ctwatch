"""The only outbound HTTP path in the project.

ctwatch never contacts a domain it is investigating. Rendering a suspicious
page is delegated to a third party (urlscan.io) precisely so that the analyst's
address never appears in the target's logs, and so that looking is not itself a
signal that someone is looking.

That promise is enforced here rather than left to discipline: every request
passes through :class:`HostAllowlistTransport`, which rejects any host that was
not explicitly declared in the configuration. Redirects go through the same
transport, so a service cannot bounce us somewhere we did not agree to go.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType

import httpx

from ctwatch.timeutil import utc_now

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_BACKOFF_SECONDS = 60.0


class NetworkPolicyError(RuntimeError):
    """Base class for refusals coming from the network policy."""


class HostNotAllowedError(NetworkPolicyError):
    """Raised when a request targets a host that was never authorised.

    Seeing this exception usually means a bug is about to make the tool
    interact with something it must not touch. It is deliberately loud.
    """


class InsecureSchemeError(NetworkPolicyError):
    """Raised for anything that is not HTTPS."""


class HostAllowlist:
    """Exact hostnames, plus ``*.example.com`` style subdomain wildcards."""

    def __init__(self, patterns: Iterable[str]) -> None:
        exact: set[str] = set()
        suffixes: set[str] = set()
        for pattern in patterns:
            cleaned = pattern.strip().lower().rstrip(".")
            if not cleaned:
                continue
            if cleaned.startswith("*."):
                suffixes.add(cleaned[1:])
            else:
                exact.add(cleaned)
        self._exact = frozenset(exact)
        self._suffixes = frozenset(suffixes)

    def permits(self, host: str | None) -> bool:
        if not host:
            return False
        candidate = host.strip().lower().rstrip(".")
        if candidate in self._exact:
            return True
        return any(candidate.endswith(suffix) for suffix in self._suffixes)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        entries = sorted(self._exact | {f"*{suffix}" for suffix in self._suffixes})
        return f"HostAllowlist({entries!r})"


class HostAllowlistTransport(httpx.AsyncBaseTransport):
    """Wraps another transport and refuses anything outside the allowlist."""

    def __init__(self, inner: httpx.AsyncBaseTransport, allowlist: HostAllowlist) -> None:
        self._inner = inner
        self._allowlist = allowlist

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme != "https":
            msg = f"refusing a non-HTTPS request to {request.url}"
            raise InsecureSchemeError(msg)
        if not self._allowlist.permits(request.url.host):
            msg = (
                f"refusing to contact {request.url.host!r}: it is not in the allowed-host list. "
                "ctwatch only talks to the Certificate Transparency and enrichment services "
                "declared in the configuration, never to a watched domain."
            )
            raise HostNotAllowedError(msg)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


class RateLimiter:
    """Serialises calls to one service, spacing them by a minimum interval."""

    def __init__(self, requests_per_second: float) -> None:
        self._interval = 0.0 if requests_per_second <= 0 else 1.0 / requests_per_second
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next_allowed - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = time.monotonic()
            self._next_allowed = now + self._interval


@dataclass(frozen=True, slots=True)
class FetchResult:
    """What a source needs to both parse a response and prove it retrieved it."""

    url: str
    status_code: int
    content: bytes
    requested_at: datetime
    attempts: int = 1
    headers: dict[str, str] = field(default_factory=dict)


class UpstreamError(RuntimeError):
    """Raised when a service could not be reached within the retry budget."""

    def __init__(self, message: str, *, url: str, attempts: int) -> None:
        super().__init__(message)
        self.url = url
        self.attempts = attempts


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:
        # The date form is legal but rare here; falling back to normal backoff
        # is better than parsing dates we cannot trust.
        return None


class PassiveHttpClient:
    """An HTTPS client that can only reach explicitly authorised services."""

    def __init__(
        self,
        *,
        allowlist: HostAllowlist,
        user_agent: str,
        timeout: float = 30.0,
        max_attempts: int = 4,
        requests_per_second: float = 0.0,
        backoff_base_seconds: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._allowlist = allowlist
        self._max_attempts = max(1, max_attempts)
        self._backoff_base = backoff_base_seconds
        self._limiter = RateLimiter(requests_per_second)
        self._client = httpx.AsyncClient(
            transport=HostAllowlistTransport(transport or httpx.AsyncHTTPTransport(), allowlist),
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": user_agent, "Accept-Encoding": "gzip"},
        )

    @property
    def allowlist(self) -> HostAllowlist:
        return self._allowlist

    async def __aenter__(self) -> PassiveHttpClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _backoff(self, attempt: int, hinted: float | None) -> float:
        if hinted is not None:
            return min(hinted, MAX_BACKOFF_SECONDS)
        # Exponential with full jitter: crt.sh in particular responds badly to
        # a fleet of clients retrying in lockstep.
        ceiling = min(self._backoff_base * (2 ** (attempt - 1)), MAX_BACKOFF_SECONDS)
        return random.uniform(0.0, ceiling)

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, str | int] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> FetchResult:
        """Fetch a URL, retrying transient failures with jittered backoff."""

        last_error: str = "no attempt was made"
        for attempt in range(1, self._max_attempts + 1):
            await self._limiter.wait()
            requested_at = utc_now()
            try:
                response = await self._client.get(url, params=params, headers=headers)
            except NetworkPolicyError:
                raise
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                if response.status_code not in RETRYABLE_STATUS:
                    return FetchResult(
                        url=str(response.url),
                        status_code=response.status_code,
                        content=response.content,
                        requested_at=requested_at,
                        attempts=attempt,
                        headers=dict(response.headers),
                    )
                last_error = f"HTTP {response.status_code}"
                hinted = _retry_after_seconds(response)
                if attempt < self._max_attempts:
                    await asyncio.sleep(self._backoff(attempt, hinted))
                continue

            if attempt < self._max_attempts:
                await asyncio.sleep(self._backoff(attempt, None))

        msg = f"giving up on {url} after {self._max_attempts} attempts ({last_error})"
        raise UpstreamError(msg, url=url, attempts=self._max_attempts)
