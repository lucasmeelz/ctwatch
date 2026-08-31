"""Everything known about one finding, gathered in one place.

Both the written report and the evidence bundle need the same material: the
assessment, the certificates it rests on, what enrichment added, which other
domains share its attributes, and the archived responses all of it came from.
Collecting it once means the report and the bundle can never disagree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ctwatch.enrich.pivot import Pivot, pivots_for
from ctwatch.store.models import (
    CertificateRecord,
    DomainRecord,
    EvidenceRecord,
    WatchTarget,
)
from ctwatch.store.repository import Repository


@dataclass(frozen=True, slots=True)
class Registration:
    """The registry's view, as stored."""

    registrar: str | None = None
    registered_at: str | None = None
    expires_at: str | None = None
    rdap_server: str | None = None
    statuses: tuple[str, ...] = ()
    nameservers: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not any((self.registrar, self.registered_at, self.statuses, self.nameservers))


@dataclass(frozen=True, slots=True)
class Scan:
    """One rendering a third party made of the page."""

    result_url: str | None = None
    screenshot_url: str | None = None
    ip: str | None = None
    asn: str | None = None
    asn_name: str | None = None
    server: str | None = None
    title: str | None = None
    scanned_at: str | None = None


@dataclass(slots=True)
class Dossier:
    """One finding and everything behind it."""

    finding_id: int
    target: WatchTarget
    domain: DomainRecord
    score: float
    confidence: str | None
    status: str
    breakdown: dict[str, Any]
    certificates: list[CertificateRecord] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    dns: list[tuple[str, str]] = field(default_factory=list)
    scans: list[Scan] = field(default_factory=list)
    pivots: list[Pivot] = field(default_factory=list)
    registration: Registration = field(default_factory=Registration)

    @property
    def contributions(self) -> list[dict[str, Any]]:
        found = self.breakdown.get("contributions", [])
        return found if isinstance(found, list) else []

    @property
    def summary(self) -> str:
        return str(self.breakdown.get("summary", ""))

    @property
    def suppressed(self) -> bool:
        return bool(self.breakdown.get("suppressed", False))

    @property
    def suppression_reason(self) -> str | None:
        reason = self.breakdown.get("suppression_reason")
        return None if reason is None else str(reason)

    def confidence_detail(self) -> dict[str, Any]:
        detail = self.breakdown.get("confidence")
        return detail if isinstance(detail, dict) else {}

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "brand": self.target.brand,
            "target": self.target.canonical_domain,
            "domain": self.domain.name,
            "display_name": self.domain.display_name,
            "idn": self.domain.is_idn,
            "score": round(self.score, 4),
            "confidence": self.confidence,
            "status": self.status,
            "breakdown": self.breakdown,
            "certificates": [
                {
                    "fingerprint_sha256": certificate.fingerprint_sha256,
                    "issuer": certificate.issuer,
                    "serial_number": certificate.serial_number,
                    "not_before": (
                        None
                        if certificate.not_before is None
                        else certificate.not_before.isoformat()
                    ),
                    "not_after": (
                        None if certificate.not_after is None else certificate.not_after.isoformat()
                    ),
                    "source": certificate.source,
                    "source_ref": certificate.source_ref,
                }
                for certificate in self.certificates
            ],
            "registration": {
                "registrar": self.registration.registrar,
                "registered_at": self.registration.registered_at,
                "expires_at": self.registration.expires_at,
                "rdap_server": self.registration.rdap_server,
                "statuses": list(self.registration.statuses),
                "nameservers": list(self.registration.nameservers),
            },
            "dns": [{"type": kind, "value": value} for kind, value in self.dns],
            "scans": [
                {
                    "result_url": scan.result_url,
                    "screenshot_url": scan.screenshot_url,
                    "ip": scan.ip,
                    "asn": scan.asn,
                    "asn_name": scan.asn_name,
                    "server": scan.server,
                    "title": scan.title,
                    "scanned_at": scan.scanned_at,
                }
                for scan in self.scans
            ],
            "pivots": [pivot.as_dict() for pivot in self.pivots],
            "evidence": [
                {
                    "id": record.id,
                    "source": record.source,
                    "endpoint": record.endpoint,
                    "requested_at": record.requested_at.isoformat(),
                    "status_code": record.status_code,
                    "content_sha256": record.content_sha256,
                    "content_length": record.content_length,
                }
                for record in self.evidence
            ],
        }


def _json_list(raw: Any) -> tuple[str, ...]:
    if not raw:
        return ()
    decoded: Any = json.loads(str(raw))
    if not isinstance(decoded, list):
        return ()
    return tuple(str(item) for item in decoded)


def build_dossier(repository: Repository, *, finding_id: int) -> Dossier | None:
    """Gather everything stored about one finding."""

    row = repository.get_finding(finding_id)
    if row is None:
        return None

    domain = repository.get_domain_by_id(int(row["domain_id"]))
    target = repository.get_target_by_id(int(row["target_id"]))
    if domain is None or target is None:  # pragma: no cover - foreign keys prevent it
        return None

    breakdown_raw: Any = json.loads(str(row["breakdown"] or "{}"))
    dossier = Dossier(
        finding_id=int(row["id"]),
        target=target,
        domain=domain,
        score=float(row["score"]),
        confidence=None if row["confidence"] is None else str(row["confidence"]),
        status=str(row["status"]),
        breakdown=breakdown_raw if isinstance(breakdown_raw, dict) else {},
        certificates=repository.certificates_for_domain(domain.id),
        evidence=repository.evidence_for_domain(domain.id),
        dns=[
            (str(record["record_type"]), str(record["value"]))
            for record in repository.dns_records_for(domain.id)
        ],
        scans=[
            Scan(
                result_url=scan["result_url"],
                screenshot_url=scan["screenshot_url"],
                ip=scan["page_ip"],
                asn=scan["page_asn"],
                asn_name=scan["page_asn_name"],
                server=scan["page_server"],
                title=scan["page_title"],
                scanned_at=scan["scanned_at"],
            )
            for scan in repository.url_scans_for(domain.id)
        ],
        pivots=pivots_for(repository, domain_id=domain.id, name=domain.name),
    )

    stored = repository.get_registration(domain.id)
    if stored is not None:
        dossier.registration = Registration(
            registrar=stored["registrar"],
            registered_at=stored["registered_at"],
            expires_at=stored["expires_at"],
            rdap_server=stored["rdap_server"],
            statuses=_json_list(stored["statuses"]),
            nameservers=_json_list(stored["nameservers"]),
        )

    return dossier


def dossiers_for_target(
    repository: Repository,
    *,
    target_id: int | None = None,
    min_score: float = 0.0,
    include_allowlisted: bool = False,
    limit: int | None = None,
) -> list[Dossier]:
    """Build a dossier for every finding worth reporting, highest score first."""

    rows = repository.list_findings(
        target_id=target_id,
        min_score=min_score,
        include_allowlisted=include_allowlisted,
        limit=limit,
    )
    dossiers: list[Dossier] = []
    for row in rows:
        dossier = build_dossier(repository, finding_id=int(row["id"]))
        if dossier is not None:
            dossiers.append(dossier)
    return dossiers
