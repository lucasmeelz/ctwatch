"""Expectations for false-positive suppression.

Large newsrooms register dozens of lookalike domains themselves, defensively.
Without a way to recognise them, the tool produces a list dominated by the
brand it is supposed to protect, and nobody reads the second page. This is not
a refinement to add later; it is what makes the output usable at all.
"""

from __future__ import annotations

from ctwatch.matching.allowlist import Allowlist, OwnershipIndex
from ctwatch.names import normalize
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository

TARGET = WatchTarget(
    id=1,
    brand="Le Monde",
    canonical_domain="lemonde.fr",
    allowlist=("lemonde-abonnements.fr", "*.lemonde.io"),
)


def test_the_watched_domain_itself_is_not_a_finding() -> None:
    decision = Allowlist.for_target(TARGET).decide(normalize("lemonde.fr"))
    assert decision.allowed is True
    assert decision.reason


def test_a_subdomain_of_the_watched_domain_is_not_a_finding() -> None:
    decision = Allowlist.for_target(TARGET).decide(normalize("abonnes.lemonde.fr"))
    assert decision.allowed is True


def test_a_declared_defensive_registration_is_not_a_finding() -> None:
    decision = Allowlist.for_target(TARGET).decide(normalize("lemonde-abonnements.fr"))
    assert decision.allowed is True
    assert "allowlist" in decision.reason


def test_a_subdomain_of_a_declared_entry_is_covered() -> None:
    allowlist = Allowlist.for_target(TARGET)
    assert allowlist.decide(normalize("www.lemonde-abonnements.fr")).allowed is True


def test_a_wildcard_entry_covers_subdomains_only() -> None:
    allowlist = Allowlist.for_target(TARGET)
    assert allowlist.decide(normalize("shop.lemonde.io")).allowed is True


def test_a_lookalike_is_still_a_finding() -> None:
    decision = Allowlist.for_target(TARGET).decide(normalize("lemonde-actu.info"))
    assert decision.allowed is False
    assert decision.reason


def test_matching_ignores_case_and_trailing_dots() -> None:
    allowlist = Allowlist.for_target(TARGET)
    assert allowlist.decide(normalize("LEMONDE-ABONNEMENTS.FR.")).allowed is True


def test_a_domain_sharing_a_certificate_with_the_brand_is_treated_as_the_brand(
    repository: Repository, tmp_path: object
) -> None:
    """The cheapest reliable ownership signal there is.

    A certificate covering both lemonde.fr and lemonde-abonnes.fr was issued to
    whoever controls lemonde.fr. That is not an impersonation, it is the brand.
    """

    store = EvidenceStore(tmp_path / "evidence", repository)  # type: ignore[operator]
    evidence = store.capture(
        source="certspotter", endpoint="https://api.certspotter.com/", content=b"[]"
    )
    certificate = repository.upsert_certificate(source="certspotter", source_ref="1")

    for name in ("lemonde.fr", "lemonde-abonnes.fr"):
        domain = repository.upsert_domain(name=name)
        repository.record_observation(
            domain_id=domain.id,
            evidence_id=evidence.id,
            source="certspotter",
            certificate_id=certificate.id,
        )

    index = OwnershipIndex(repository, TARGET)
    decision = index.decide(normalize("lemonde-abonnes.fr"))
    assert decision.allowed is True
    assert "lemonde.fr" in decision.reason
    assert "certificate" in decision.reason


def test_an_unrelated_domain_is_not_grouped_with_the_brand(
    repository: Repository, tmp_path: object
) -> None:
    store = EvidenceStore(tmp_path / "evidence", repository)  # type: ignore[operator]
    evidence = store.capture(
        source="certspotter", endpoint="https://api.certspotter.com/", content=b"[]"
    )
    certificate = repository.upsert_certificate(source="certspotter", source_ref="2")
    domain = repository.upsert_domain(name="lemonde-actu.info")
    repository.record_observation(
        domain_id=domain.id,
        evidence_id=evidence.id,
        source="certspotter",
        certificate_id=certificate.id,
    )

    index = OwnershipIndex(repository, TARGET)
    assert index.decide(normalize("lemonde-actu.info")).allowed is False


def test_an_unseen_domain_is_not_grouped(repository: Repository) -> None:
    index = OwnershipIndex(repository, TARGET)
    decision = index.decide(normalize("never-observed.example"))
    assert decision.allowed is False
    assert decision.reason
