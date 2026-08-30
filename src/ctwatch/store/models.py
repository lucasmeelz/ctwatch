"""Row objects returned by the repository.

These are deliberately plain and immutable: they cross module boundaries into
scoring and reporting, and nothing downstream should be able to mutate what was
read from the database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class WatchTarget:
    id: int
    brand: str
    canonical_domain: str
    keywords: tuple[str, ...] = ()
    allowlist: tuple[str, ...] = ()
    active: bool = True
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """A single retrieved response, archived and addressable by digest."""

    id: int
    source: str
    endpoint: str
    requested_at: datetime
    status_code: int | None
    content_sha256: str
    content_length: int
    blob_path: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DomainRecord:
    id: int
    name: str
    unicode_name: str | None = None
    registrable_domain: str | None = None
    tld: str | None = None
    is_wildcard: bool = False
    is_idn: bool = False
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None

    @property
    def display_name(self) -> str:
        """What a reader of the report should see.

        For an internationalised domain the ASCII form hides the attack, so the
        unicode form is shown; callers that need the wire form use ``name``.
        """

        return self.unicode_name or self.name


@dataclass(frozen=True, slots=True)
class CertificateRecord:
    id: int
    source: str
    fingerprint_sha256: str | None = None
    source_ref: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    entry_timestamp: datetime | None = None
    first_seen_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ObservationRecord:
    id: int
    domain_id: int
    evidence_id: int
    source: str
    observed_at: datetime
    certificate_id: int | None = None
    target_id: int | None = None
    query: str | None = None
