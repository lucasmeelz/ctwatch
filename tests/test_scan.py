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
CERTSPOTTER_PAGE = (FIXTURES / "certspotter_page1.json").read_bytes()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.model_validate(
        {
            "targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}],
            # These cases exercise the crt.sh source specifically.
            "sources": {
                "order": ["crtsh"],
                "certspotter": {"enabled": False},
                "crtsh": {"rate_limit_rps": 0, "max_attempts": 1, "retry_backoff_seconds": 0},
            },
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
        variants=20,
        transport=httpx.MockTransport(handler),
    )
    assert set(contacted) == {"crt.sh"}
    assert normalize("lemonde.fr").ascii_name not in contacted


# ---------------------------------------------------------------------------
# Failover between sources


@pytest.fixture
def two_source_config(tmp_path: Path) -> Config:
    return Config.model_validate(
        {
            "targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}],
            "sources": {
                "order": ["certspotter", "crtsh"],
                "certspotter": {
                    "rate_limit_rps": 0,
                    "max_attempts": 1,
                    "retry_backoff_seconds": 0,
                },
                "crtsh": {"rate_limit_rps": 0, "max_attempts": 1, "retry_backoff_seconds": 0},
            },
            "storage": {
                "database": str(tmp_path / "ctwatch.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
        }
    )


def by_host(**bodies: tuple[int, bytes]) -> tuple[httpx.MockTransport, list[str]]:
    contacted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        contacted.append(host)
        status, body = bodies.get(host.replace(".", "_"), (200, b"[]"))
        if status == 200 and request.url.params.get("after"):
            # Cert Spotter pages with a cursor; the run ends on an empty page.
            return httpx.Response(200, content=b"[]")
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler), contacted


async def test_the_first_source_that_answers_wins(
    two_source_config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    transport, contacted = by_host(
        api_certspotter_com=(200, CERTSPOTTER_PAGE), crt_sh=(200, LISTING)
    )
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=two_source_config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=transport,
    )

    assert "crt.sh" not in contacted
    assert summaries[0].by_source == {"certspotter": 2}


async def test_scan_falls_back_when_the_first_source_is_down(
    two_source_config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    """The situation crt.sh spends a good deal of its time in, reversed."""

    transport, contacted = by_host(
        api_certspotter_com=(502, b"<html>bad gateway</html>"), crt_sh=(200, LISTING)
    )
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=two_source_config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=transport,
    )

    assert "crt.sh" in contacted
    assert summaries[0].certificates == 3
    assert summaries[0].by_source == {"crtsh": 3}
    assert summaries[0].failed_queries == 1
    assert "certspotter" in summaries[0].errors[0]


async def test_every_source_is_asked_under_the_all_strategy(
    two_source_config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    two_source_config.sources.strategy = "all"
    transport, contacted = by_host(
        api_certspotter_com=(200, CERTSPOTTER_PAGE), crt_sh=(200, LISTING)
    )
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=two_source_config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=transport,
    )

    assert set(contacted) == {"api.certspotter.com", "crt.sh"}
    assert set(summaries[0].by_source) == {"certspotter", "crtsh"}


async def test_repeated_failures_are_summarised_not_repeated(
    two_source_config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    """A scan of five hundred variants must not emit five hundred error lines."""

    transport, _ = by_host(api_certspotter_com=(502, b"down"), crt_sh=(502, b"down"))
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=two_source_config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        variants=15,
        transport=transport,
    )

    assert summaries[0].failed_queries == 32
    assert len(summaries[0].errors) <= 5
