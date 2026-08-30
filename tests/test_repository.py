from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ctwatch.store.repository import Repository
from ctwatch.timeutil import utc_now

MOMENT = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def add_evidence(repository: Repository, *, digest: str = "a" * 64) -> int:
    return repository.insert_evidence(
        source="crtsh",
        endpoint="https://crt.sh/?q=lemonde.fr&output=json",
        requested_at=MOMENT,
        status_code=200,
        content_sha256=digest,
        content_length=12,
        blob_path=f"2026/03/{digest[:2]}/{digest}.gz",
    ).id


def test_target_upsert_is_idempotent(repository: Repository) -> None:
    first = repository.upsert_target(
        brand="Le Monde", canonical_domain="LeMonde.FR.", keywords=["Actu", "actu"]
    )
    second = repository.upsert_target(
        brand="Le Monde", canonical_domain="lemonde.fr", keywords=["actu", "info"]
    )
    assert first.id == second.id
    assert first.canonical_domain == "lemonde.fr"
    assert second.keywords == ("actu", "info")
    assert len(repository.list_targets()) == 1


def test_deactivated_target_is_hidden_but_kept(repository: Repository) -> None:
    repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    assert repository.deactivate_target("lemonde.fr") is True
    assert repository.list_targets() == []
    assert len(repository.list_targets(active_only=False)) == 1


def test_evidence_round_trip(repository: Repository) -> None:
    record = repository.insert_evidence(
        source="crtsh",
        endpoint="https://crt.sh/?q=lemonde.fr&output=json",
        requested_at=MOMENT,
        status_code=200,
        content_sha256="b" * 64,
        content_length=42,
        blob_path="2026/03/bb/blob.gz",
        meta={"query": "lemonde.fr"},
    )
    stored = repository.get_evidence(record.id)
    assert stored is not None
    assert stored.requested_at == MOMENT
    assert stored.meta == {"query": "lemonde.fr"}


def test_domain_upsert_widens_the_seen_window(repository: Repository) -> None:
    early = MOMENT
    late = MOMENT + timedelta(days=10)
    repository.upsert_domain(name="lemonde-actu.info", seen_at=late)
    repository.upsert_domain(name="lemonde-actu.info", seen_at=early, unicode_name=None)
    record = repository.get_domain("lemonde-actu.info")
    assert record is not None
    assert record.first_seen_at == early
    assert record.last_seen_at == late
    assert repository.count_domains() == 1


def test_domain_upsert_keeps_known_unicode_name(repository: Repository) -> None:
    repository.upsert_domain(name="xn--lemnde-cua.fr", unicode_name="lemоnde.fr", is_idn=True)
    repository.upsert_domain(name="xn--lemnde-cua.fr")
    record = repository.get_domain("xn--lemnde-cua.fr")
    assert record is not None
    assert record.unicode_name == "lemоnde.fr"
    assert record.is_idn is True
    assert record.display_name == "lemоnde.fr"


def test_certificate_is_reconciled_on_source_reference(repository: Repository) -> None:
    first = repository.upsert_certificate(
        source="crtsh", source_ref="123456", issuer="Let's Encrypt"
    )
    second = repository.upsert_certificate(
        source="crtsh", source_ref="123456", serial_number="0a1b"
    )
    assert first.id == second.id
    assert second.issuer == "Let's Encrypt"
    assert second.serial_number == "0a1b"


def test_certificate_is_reconciled_on_fingerprint_across_sources(repository: Repository) -> None:
    fingerprint = "c" * 64
    first = repository.upsert_certificate(
        source="certspotter", fingerprint_sha256=fingerprint, source_ref="cs-1"
    )
    second = repository.upsert_certificate(
        source="crtsh", fingerprint_sha256=fingerprint, source_ref="crt-1"
    )
    assert first.id == second.id


def test_repeated_observation_is_not_duplicated(repository: Repository) -> None:
    evidence_id = add_evidence(repository)
    domain = repository.upsert_domain(name="lemonde-actu.info")
    certificate = repository.upsert_certificate(source="crtsh", source_ref="1")

    first = repository.record_observation(
        domain_id=domain.id,
        evidence_id=evidence_id,
        source="crtsh",
        certificate_id=certificate.id,
    )
    second = repository.record_observation(
        domain_id=domain.id,
        evidence_id=evidence_id,
        source="crtsh",
        certificate_id=certificate.id,
    )
    assert first is not None
    assert second is None
    assert repository.count_observations() == 1


def test_cache_hit_and_expiry(repository: Repository) -> None:
    evidence_id = add_evidence(repository)
    repository.store_cache_entry(
        source="crtsh",
        cache_key="lemonde.fr",
        evidence_id=evidence_id,
        expires_at=utc_now() + timedelta(hours=1),
    )
    assert repository.cached_evidence(source="crtsh", cache_key="lemonde.fr") is not None

    repository.store_cache_entry(
        source="crtsh",
        cache_key="lemonde.fr",
        evidence_id=evidence_id,
        expires_at=utc_now() - timedelta(seconds=1),
    )
    assert repository.cached_evidence(source="crtsh", cache_key="lemonde.fr") is None
    assert repository.purge_expired_cache() == 1
