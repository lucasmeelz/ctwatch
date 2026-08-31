"""What a monitor emits when a certificate matches the watchlist."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from ctwatch.matching.matcher import Match
from ctwatch.sources.certstream import StreamedCertificate
from ctwatch.timeutil import to_iso


@dataclass(frozen=True, slots=True)
class Alert:
    """One matched name, with everything a reader needs to judge it."""

    match: Match
    certificate: StreamedCertificate
    score: float
    confidence: str
    summary: str
    evidence_id: int
    finding_id: int | None = None
    detected_at: datetime | None = None

    @property
    def domain(self) -> str:
        return self.match.name.ascii_name

    @property
    def display_name(self) -> str:
        return self.match.name.unicode_name

    def as_dict(self) -> dict[str, Any]:
        return {
            "detected_at": None if self.detected_at is None else to_iso(self.detected_at),
            "domain": self.domain,
            "display_name": self.display_name,
            "idn": self.match.name.is_idn,
            "brand": self.match.target.brand,
            "target": self.match.target.canonical_domain,
            "tier": self.match.tier.value,
            "technique": None if self.match.kind is None else self.match.kind.value,
            "why": self.match.detail,
            "score": round(self.score, 4),
            "confidence": self.confidence,
            "summary": self.summary,
            "issuer": self.certificate.issuer,
            "fingerprint": self.certificate.fingerprint,
            "not_before": (
                None if self.certificate.not_before is None else to_iso(self.certificate.not_before)
            ),
            "evidence_id": self.evidence_id,
            "finding_id": self.finding_id,
        }


class Notifier(Protocol):
    """Somewhere an alert can be sent."""

    @property
    def name(self) -> str: ...

    async def publish(self, alert: Alert) -> None: ...

    async def aclose(self) -> None: ...
