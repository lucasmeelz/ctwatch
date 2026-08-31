"""End-to-end expectations for assessment: observations in, findings out."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctwatch.config import Config
from ctwatch.findings import assess_target
from ctwatch.matching.confidence import rate
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository

NOW = datetime(2026, 3, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
def config() -> Config:
    return Config.model_validate(
        {"targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}]}
    )


@pytest.fixture
def target(repository: Repository) -> WatchTarget:
    return repository.upsert_target(
        brand="Le Monde",
        canonical_domain="lemonde.fr",
        keywords=["actu", "info"],
        allowlist=["lemonde-abonnements.fr"],
    )


@pytest.fixture
def store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


def observe(
    repository: Repository,
    store: EvidenceStore,
    target: WatchTarget,
    name: str,
    *,
    not_before: datetime | None = None,
    fingerprint: str | None = None,
    certificate_ref: str | None = None,
    also: list[str] | None = None,
) -> None:
    evidence = store.capture(
        source="certspotter",
        endpoint="https://api.certspotter.com/v1/issuances",
        content=f'[{{"dns_names": ["{name}"]}}]'.encode(),
    )
    certificate = repository.upsert_certificate(
        source="certspotter",
        source_ref=certificate_ref or name,
        fingerprint_sha256=fingerprint,
        not_before=not_before,
    )
    for entry in [name, *(also or [])]:
        domain = repository.upsert_domain(name=entry)
        repository.record_observation(
            domain_id=domain.id,
            evidence_id=evidence.id,
            source="certspotter",
            certificate_id=certificate.id,
            target_id=target.id,
        )


def test_a_lookalike_becomes_a_reported_finding(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    observe(
        repository,
        store,
        target,
        "lemonde-actu.info",
        not_before=NOW - timedelta(days=2),
        fingerprint="a" * 64,
    )
    report, assessments = assess_target(
        repository=repository, config=config, target=target, now=NOW
    )

    assert report.assessed == 1
    assert report.reported == 1
    assert report.suppressed == 0
    assert report.above_threshold == 1

    finding = assessments[0]
    assert finding.finding_id is not None
    assert finding.score.value > 0.6
    assert finding.confidence.code == "B2"
    assert finding.suppressed is False


def test_the_watched_domain_itself_is_suppressed(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    observe(repository, store, target, "lemonde.fr", not_before=NOW)
    report, assessments = assess_target(
        repository=repository, config=config, target=target, now=NOW
    )

    assert report.suppressed == 1
    assert report.reported == 0
    assert assessments[0].confidence.credibility == "5"
    assert assessments[0].status == "allowlisted"


def test_a_declared_defensive_registration_is_suppressed(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    observe(repository, store, target, "lemonde-abonnements.fr", not_before=NOW)
    report, _ = assess_target(repository=repository, config=config, target=target, now=NOW)
    assert report.suppressed == 1


def test_a_domain_sharing_a_certificate_with_the_brand_is_suppressed(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    """No configuration needed: the certificate settles it."""

    observe(
        repository,
        store,
        target,
        "lemonde.fr",
        not_before=NOW,
        also=["lemonde-lecteurs.fr"],
    )
    report, assessments = assess_target(
        repository=repository, config=config, target=target, now=NOW
    )

    assert report.suppressed == 2
    grouped = next(a for a in assessments if a.domain.name == "lemonde-lecteurs.fr")
    assert grouped.decision.rule == "shared_certificate"
    assert "lemonde.fr" in grouped.decision.reason


def test_findings_are_stored_and_re_readable(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    observe(repository, store, target, "lemonde-actu.info", not_before=NOW)
    assess_target(repository=repository, config=config, target=target, now=NOW)

    rows = repository.list_findings()
    assert len(rows) == 1
    assert rows[0]["domain_name"] == "lemonde-actu.info"
    assert rows[0]["confidence"]
    assert rows[0]["breakdown"]


def test_reassessment_does_not_overwrite_a_human_verdict(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    observe(repository, store, target, "lemonde-actu.info", not_before=NOW)
    _, assessments = assess_target(repository=repository, config=config, target=target, now=NOW)
    finding_id = assessments[0].finding_id
    assert finding_id is not None
    assert repository.set_finding_status(finding_id, "confirmed", notes="published")

    assess_target(repository=repository, config=config, target=target, now=NOW)
    rows = repository.list_findings()
    assert rows[0]["status"] == "confirmed"
    assert rows[0]["notes"] == "published"


def test_suppressed_findings_are_kept_but_hidden(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    """A suppression a user cannot inspect is a suppression they cannot trust."""

    observe(repository, store, target, "lemonde.fr", not_before=NOW)
    assess_target(repository=repository, config=config, target=target, now=NOW)

    assert repository.list_findings() == []
    kept = repository.list_findings(include_allowlisted=True)
    assert len(kept) == 1
    assert kept[0]["status"] == "allowlisted"
    assert kept[0]["notes"]


def test_confidence_reflects_what_backs_the_observation() -> None:
    with_fingerprint = rate(
        score=0.8, allowlisted=False, any_signal=True, has_evidence=True, has_fingerprint=True
    )
    without = rate(
        score=0.8, allowlisted=False, any_signal=True, has_evidence=True, has_fingerprint=False
    )
    unbacked = rate(
        score=0.8, allowlisted=False, any_signal=True, has_evidence=False, has_fingerprint=False
    )

    assert with_fingerprint.code == "B2"
    assert without.code == "C2"
    assert unbacked.code == "F2"
    assert all(part.reliability_reason for part in (with_fingerprint, without, unbacked))


def test_confidence_never_claims_corroboration_on_its_own() -> None:
    """A and 1 mean corroborated. Nothing here corroborates anything."""

    best = rate(
        score=1.0, allowlisted=False, any_signal=True, has_evidence=True, has_fingerprint=True
    )
    assert best.reliability != "A"
    assert best.credibility != "1"
