"""Common shape for Certificate Transparency sources.

A source turns a query into a stream of :class:`CertObservation`. Every
observation carries the id of the archived response it came from, so nothing
downstream can produce a claim that is not traceable to bytes on disk.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, ClassVar

from ctwatch.names import DomainName
from ctwatch.net.client import PassiveHttpClient
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import EvidenceRecord
from ctwatch.store.repository import Repository
from ctwatch.timeutil import utc_now


class SourceError(RuntimeError):
    """Raised when a source answered, but not with something usable."""


@dataclass(frozen=True, slots=True)
class SourceQuery:
    """What to ask a source for.

    ``exact`` distinguishes a lookup for one precise name from a substring
    search. Substring search is convenient but structurally blind to homoglyph
    variants, which is why the scan pipeline generates candidate names first
    and looks each of them up.
    """

    pattern: str
    exact: bool = True
    since: datetime | None = None
    include_subdomains: bool = True

    @property
    def cache_key(self) -> str:
        parts = [self.pattern, "exact" if self.exact else "wildcard"]
        if self.include_subdomains:
            parts.append("subdomains")
        return "|".join(parts)


@dataclass(frozen=True, slots=True)
class CertObservation:
    """One certificate, as seen by one source, at one point in time."""

    source: str
    names: tuple[DomainName, ...]
    evidence_id: int
    retrieved_at: datetime
    query: str
    issuer: str | None = None
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    entry_timestamp: datetime | None = None
    fingerprint_sha256: str | None = None
    source_ref: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def age(self) -> timedelta | None:
        """How long ago the certificate was issued.

        A certificate minted hours ago for a name that resembles a newsroom is
        the signal worth waking up for; one issued three years ago rarely is.
        """

        if self.not_before is None:
            return None
        return utc_now() - self.not_before


@dataclass(frozen=True, slots=True)
class Fetched:
    """A response, whether it came from the network or from the local cache."""

    evidence: EvidenceRecord
    content: bytes
    from_cache: bool


class Source(ABC):
    """Base class for anything that can answer a :class:`SourceQuery`."""

    name: ClassVar[str] = "source"

    def __init__(
        self,
        *,
        http: PassiveHttpClient,
        evidence: EvidenceStore,
        repository: Repository,
        cache_ttl_seconds: int = 3600,
    ) -> None:
        self._http = http
        self._evidence = evidence
        self._repository = repository
        self._cache_ttl = max(0, cache_ttl_seconds)

    @abstractmethod
    def search(self, query: SourceQuery) -> AsyncIterator[CertObservation]:
        """Yield every certificate the source knows about for this query."""

    async def fetch(
        self,
        *,
        url: str,
        params: dict[str, str | int] | None = None,
        cache_key: str,
        headers: dict[str, str] | None = None,
    ) -> Fetched:
        """Retrieve a response, replaying a fresh cached one when available.

        crt.sh in particular answers in anything from three to thirty seconds
        and is regularly unavailable; re-running a scan should not mean asking
        it again for something retrieved minutes ago.
        """

        if self._cache_ttl > 0:
            cached = self._repository.cached_evidence(source=self.name, cache_key=cache_key)
            if cached is not None:
                return Fetched(
                    evidence=cached, content=self._evidence.read(cached), from_cache=True
                )

        result = await self._http.get(url, params=params, headers=headers)
        if result.status_code >= 400:
            # Services explain themselves in the body far more usefully than in
            # the status line; Cert Spotter in particular says exactly why a
            # query was refused.
            detail = result.content[:200].decode("utf-8", errors="replace").strip()
            msg = f"{self.name} returned HTTP {result.status_code} for {result.url}"
            if detail:
                msg = f"{msg}: {detail}"
            raise SourceError(msg)

        record = self._evidence.capture(
            source=self.name,
            endpoint=result.url,
            content=result.content,
            requested_at=result.requested_at,
            status_code=result.status_code,
            meta={"cache_key": cache_key, "attempts": result.attempts},
        )
        if self._cache_ttl > 0:
            self._repository.store_cache_entry(
                source=self.name,
                cache_key=cache_key,
                evidence_id=record.id,
                expires_at=result.requested_at + timedelta(seconds=self._cache_ttl),
                fetched_at=result.requested_at,
            )
        return Fetched(evidence=record, content=result.content, from_cache=False)
