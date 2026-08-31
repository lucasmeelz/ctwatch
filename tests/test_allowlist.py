"""Expectations for false-positive suppression.

Large newsrooms register dozens of lookalike domains themselves, defensively.
Without a way to recognise them, the tool produces a list dominated by the
brand it is supposed to protect, and nobody reads the second page. This is not
a refinement to add later; it is what makes the output usable at all.
"""

from __future__ import annotations

from pathlib import Path

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


def certificate(
    repository: Repository, store: EvidenceStore, *, ref: str, names: list[str]
) -> None:
    """Record one certificate covering a set of names."""

    evidence = store.capture(
        source="certspotter", endpoint="https://api.certspotter.com/", content=b"[]"
    )
    record = repository.upsert_certificate(source="certspotter", source_ref=ref)
    for entry in names:
        domain = repository.upsert_domain(name=entry)
        repository.record_observation(
            domain_id=domain.id,
            evidence_id=evidence.id,
            source="certspotter",
            certificate_id=record.id,
        )


def test_a_provider_certificate_does_not_prove_ownership(
    repository: Repository, tmp_path: Path
) -> None:
    """The failure that made ninety-nine strangers into Le Monde's property.

    One certificate observed in the wild carried a hundred names, of which
    exactly one belonged to the brand. Read naively it declares the other
    ninety-nine to be the brand's — and would silently suppress a genuine
    impersonation that happened to sit behind the same provider.
    """

    store = EvidenceStore(tmp_path / "evidence", repository)
    tenants = [f"tenant-{index}.example{index}.com" for index in range(99)]
    certificate(repository, store, ref="provider", names=["amplifico.lemonde.fr", *tenants])

    index = OwnershipIndex(repository, TARGET)
    decision = index.decide(normalize("tenant-0.example0.com"))
    assert decision.allowed is False


def test_an_affiliate_certificate_does_not_prove_ownership(
    repository: Repository, tmp_path: Path
) -> None:
    """One host per registration is what a shared platform looks like."""

    store = EvidenceStore(tmp_path / "evidence", repository)
    partners = [f"partner.merchant{index}.com" for index in range(19)]
    certificate(repository, store, ref="affiliate", names=["partner.lemonde.fr", *partners])

    index = OwnershipIndex(repository, TARGET)
    assert index.decide(normalize("partner.merchant0.com")).allowed is False


def test_a_group_certificate_still_proves_ownership(repository: Repository, tmp_path: Path) -> None:
    """Many hosts of a few names is what one organisation's certificate looks like."""

    store = EvidenceStore(tmp_path / "evidence", repository)
    names = [
        "lemonde.fr",
        "abonnes.lemonde.fr",
        "emploi.lemonde.fr",
        "forum.lemonde.fr",
        "www.lemonde-lecteurs.fr",
        "abonnes.lemonde-lecteurs.fr",
        "emploi.lemonde-lecteurs.fr",
        "shop.lemonde-boutique.fr",
        "www.lemonde-boutique.fr",
        "static.lemonde-boutique.fr",
    ]
    certificate(repository, store, ref="group", names=names)

    index = OwnershipIndex(repository, TARGET)
    decision = index.decide(normalize("shop.lemonde-boutique.fr"))
    assert decision.allowed is True
    assert "registration(s)" in decision.reason


def test_a_declared_defensive_registration_can_anchor_an_inference(
    repository: Repository, tmp_path: Path
) -> None:
    store = EvidenceStore(tmp_path / "evidence", repository)
    certificate(
        repository,
        store,
        ref="declared",
        names=["lemonde-abonnements.fr", "www.lemonde-abonnements.fr", "shop.lemonde-shop.fr"],
    )
    index = OwnershipIndex(repository, TARGET)
    assert index.decide(normalize("shop.lemonde-shop.fr")).allowed is True
