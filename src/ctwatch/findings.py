"""Turning observations into assessed, storable findings.

A finding is one watched brand, one domain, a score, the breakdown that
produced it, and a confidence rating. It is written to the database so that it
can be reviewed, exported, and — crucially — re-derived later from the archived
responses it was built on.

Assessment is offline. It reads what previous scans stored and contacts
nothing, so re-scoring a corpus after changing a weight costs no requests.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ctwatch.config import Config
from ctwatch.matching.allowlist import Allowlist, AllowlistDecision, OwnershipIndex
from ctwatch.matching.confidence import Confidence, rate
from ctwatch.matching.scoring import Score, Scorer, Subject
from ctwatch.names import DomainName
from ctwatch.store.models import DomainRecord, WatchTarget
from ctwatch.store.repository import Repository

STATUS_NEW = "new"
STATUS_ALLOWLISTED = "allowlisted"


@dataclass(frozen=True, slots=True)
class Assessment:
    """One domain, assessed against one watched brand."""

    target: WatchTarget
    domain: DomainRecord
    score: Score
    confidence: Confidence
    decision: AllowlistDecision
    finding_id: int | None = None

    @property
    def suppressed(self) -> bool:
        return self.decision.allowed

    @property
    def status(self) -> str:
        return STATUS_ALLOWLISTED if self.suppressed else STATUS_NEW

    def breakdown(self) -> dict[str, Any]:
        payload = self.score.as_dict()
        payload["confidence"] = self.confidence.as_dict()
        payload["suppressed"] = self.suppressed
        payload["suppression_reason"] = self.decision.reason if self.suppressed else None
        payload["suppression_rule"] = self.decision.rule if self.suppressed else None
        return payload

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "brand": self.target.brand,
            "target": self.target.canonical_domain,
            "domain": self.domain.name,
            "display_name": self.domain.display_name,
            "idn": self.domain.is_idn,
            "score": round(self.score.value, 4),
            "confidence": self.confidence.code,
            "status": self.status,
            "summary": self.score.summary,
            "breakdown": self.breakdown(),
        }


@dataclass(slots=True)
class AssessmentReport:
    """What one pass of the assessment produced for one target."""

    target: WatchTarget
    assessed: int = 0
    reported: int = 0
    suppressed: int = 0
    above_threshold: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "brand": self.target.brand,
            "target": self.target.canonical_domain,
            "assessed": self.assessed,
            "reported": self.reported,
            "suppressed": self.suppressed,
            "above_threshold": self.above_threshold,
        }


def _domain_name(record: DomainRecord) -> DomainName:
    return DomainName(
        ascii_name=record.name,
        unicode_name=record.unicode_name or record.name,
        is_wildcard=record.is_wildcard,
    )


def assess_target(
    *,
    repository: Repository,
    config: Config,
    target: WatchTarget,
    now: datetime | None = None,
) -> tuple[AssessmentReport, list[Assessment]]:
    """Score every domain observed for one target and store the findings."""

    scorer = Scorer(config.scoring)
    allowlist = Allowlist.for_target(target)
    ownership = OwnershipIndex(repository, target)
    threshold = config.scoring.review_threshold

    report = AssessmentReport(target=target)
    assessments: list[Assessment] = []

    for record in repository.domains_for_target(target.id):
        name = _domain_name(record)

        decision = allowlist.decide(name)
        if not decision.allowed:
            decision = ownership.decide(name)

        certificate = repository.newest_certificate_for_domain(record.id)
        subject = Subject(
            name=name,
            not_before=None if certificate is None else certificate.not_before,
            issuer=None if certificate is None else certificate.issuer,
        )
        score = scorer.score(subject, target=target, now=now)

        confidence = rate(
            score=score.value,
            allowlisted=decision.allowed,
            any_signal=any(c.value > 0 for c in score.contributions),
            has_evidence=bool(repository.evidence_ids_for_domain(record.id)),
            has_fingerprint=certificate is not None and certificate.fingerprint_sha256 is not None,
        )

        assessment = Assessment(
            target=target,
            domain=record,
            score=score,
            confidence=confidence,
            decision=decision,
        )
        finding_id = repository.upsert_finding(
            target_id=target.id,
            domain_id=record.id,
            score=score.value,
            breakdown=assessment.breakdown(),
            confidence=confidence.code,
            status=assessment.status,
            notes=decision.reason if decision.allowed else None,
        )
        assessment = Assessment(
            target=target,
            domain=record,
            score=score,
            confidence=confidence,
            decision=decision,
            finding_id=finding_id,
        )
        assessments.append(assessment)

        report.assessed += 1
        if assessment.suppressed:
            report.suppressed += 1
        else:
            report.reported += 1
            if score.value >= threshold:
                report.above_threshold += 1

    return report, assessments


def assess_targets(
    *,
    repository: Repository,
    config: Config,
    targets: list[WatchTarget],
    now: datetime | None = None,
) -> list[AssessmentReport]:
    reports: list[AssessmentReport] = []
    for target in targets:
        report, _ = assess_target(repository=repository, config=config, target=target, now=now)
        reports.append(report)
    return reports
