from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from ctwatch.config import Config
from ctwatch.names import normalize
from ctwatch.scan import run_scan
from ctwatch.sources.base import SourceError
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.repository import Repository

FIXTURES = Path(__file__).parent / "fixtures"
LISTING = (FIXTURES / "crtsh_lemonde.json").read_bytes()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.model_validate(
        {
            "targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}],
            "sources": {"crtsh": {"rate_limit_rps": 0}},
            "storage": {
                "database": str(tmp_path / "ctwatch.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
        }
    )


@pytest.fixture
def evidence_store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


def responder(body: bytes = LISTING, status: int = 200) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, content=body))


async def test_scan_persists_domains_certificates_and_observations(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=responder(),
    )

    summary = summaries[0]
    assert summary.certificates == 3
    assert summary.domains_seen == 5
    # Four distinct names: `*.lemonde-actu.info` and `lemonde-actu.info` are
    # the same domain seen twice, once as a wildcard.
    assert summary.new_domains == 4
    assert summary.observations == 5
    assert summary.errors == []

    stored = repository.get_domain("lemonde-actu.info")
    assert stored is not None
    assert stored.tld == "info"


async def test_rescanning_records_no_duplicate_observations(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    kwargs = {
        "config": config,
        "repository": repository,
        "evidence": evidence_store,
        "targets": [target],
        "transport": responder(),
    }
    await run_scan(**kwargs)  # type: ignore[arg-type]
    second = await run_scan(**kwargs)  # type: ignore[arg-type]

    assert second[0].new_domains == 0
    assert second[0].observations == 0
    assert repository.count_observations() == 5


async def test_idn_domain_is_stored_with_both_forms(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    await run_scan(
        config=config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=responder(),
    )
    stored = repository.get_domain("xn--lemnde-yqf.fr")
    assert stored is not None
    assert stored.is_idn is True
    assert stored.display_name == "lemоnde.fr"


async def test_since_is_passed_through_to_the_source(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        since=datetime(2026, 2, 1, tzinfo=UTC),
        transport=responder(),
    )
    assert summaries[0].certificates == 2


async def test_a_failing_source_is_reported_without_aborting_the_scan(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=responder(body=b"<html>overloaded</html>"),
    )
    assert summaries[0].certificates == 0
    assert "did not return JSON" in summaries[0].errors[0]


async def test_scan_without_an_enabled_source_is_refused(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    config.sources.crtsh.enabled = False
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    with pytest.raises(SourceError, match="no source is enabled"):
        await run_scan(
            config=config,
            repository=repository,
            evidence=evidence_store,
            targets=[target],
            transport=responder(),
        )


async def test_scan_never_reaches_a_watched_domain(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    """A source that tried to fetch the target itself would be stopped here."""

    contacted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        contacted.append(request.url.host)
        return httpx.Response(200, content=LISTING)

    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    await run_scan(
        config=config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=httpx.MockTransport(handler),
    )
    assert contacted == ["crt.sh"]
    assert normalize("lemonde.fr").ascii_name not in contacted
