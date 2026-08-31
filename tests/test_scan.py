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


async def test_a_rate_limited_source_is_asked_only_once(
    two_source_config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    """A free tier saying "you have exceeded the limit" has answered fully.

    Asking it five hundred more times is useless and a poor way to treat a
    service that costs nothing to use.
    """

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        if request.url.host == "api.certspotter.com":
            return httpx.Response(429, content=b'{"code": "rate_limited"}')
        return httpx.Response(200, content=LISTING)

    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    summaries = await run_scan(
        config=two_source_config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        variants=20,
        transport=httpx.MockTransport(handler),
    )

    # One attempt against Cert Spotter, then it is left alone for the run.
    assert calls.count("api.certspotter.com") == 1
    assert calls.count("crt.sh") == 21
    assert any("rate limiting us" in message for message in summaries[0].errors)


async def test_an_ordinary_failure_does_not_disable_a_source(
    two_source_config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    """A gateway error is a bad moment, not a refusal."""

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        if request.url.host == "api.certspotter.com":
            return httpx.Response(502, content=b"bad gateway")
        return httpx.Response(200, content=LISTING)

    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    await run_scan(
        config=two_source_config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        variants=5,
        transport=httpx.MockTransport(handler),
    )
    assert calls.count("api.certspotter.com") == 6


# ---------------------------------------------------------------------------
# What a certificate's names are allowed to say about a brand


def use_certspotter(config: Config) -> None:
    """The fixture pins these cases to crt.sh; this listing is Cert Spotter's."""

    config.sources.order = ["certspotter"]
    config.sources.certspotter.enabled = True
    config.sources.certspotter.rate_limit_rps = 0
    config.sources.crtsh.enabled = False


def certificate_listing(*names: str) -> bytes:
    entries = ", ".join(
        f'{{"id": "{index}", "cert_sha256": "{index:064d}", '
        f'"dns_names": ["{name}"], "not_before": "2026-03-08T03:12:52Z"}}'
        for index, name in enumerate(names, start=1)
    )
    return f"[{entries}]".encode()


async def scan_names(
    config: Config,
    repository: Repository,
    evidence_store: EvidenceStore,
    *names: str,
) -> None:
    target = repository.upsert_target(
        brand="Le Monde", canonical_domain="lemonde.fr", keywords=["actu", "info"]
    )
    body = certificate_listing(*names)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("after"):
            return httpx.Response(200, content=b"[]")
        return httpx.Response(200, content=body)

    await run_scan(
        config=config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=httpx.MockTransport(handler),
    )


async def test_a_strangers_name_on_the_brands_certificate_is_not_the_brands_problem(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    """The defect that produced ninety-nine findings about Le Figaro.

    A certificate lists whatever its requester asked for. Storing every name on
    it as "observed for this brand" is how unrelated businesses around the world
    became findings about a newspaper.
    """

    use_certspotter(config)
    await scan_names(
        config,
        repository,
        evidence_store,
        "lemonde.fr",
        "backgammon-in-muenchen.de",
        "aidanfieldpreschool.org.nz",
        "quotebook.online",
    )

    # Everything is kept: the neighbourhood is what later proves ownership.
    assert repository.count_domains() == 4
    for stranger in ("quotebook.online", "backgammon-in-muenchen.de"):
        record = repository.get_domain(stranger)
        assert record is not None

    # But only the brand's own name is attributed to the brand.
    attributed = {record.name for record in repository.domains_for_target(1)}
    assert attributed == {"lemonde.fr"}


async def test_a_lookalike_on_the_certificate_is_still_attributed(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    """Filtering must not throw away the thing the tool exists to find."""

    use_certspotter(config)
    await scan_names(
        config,
        repository,
        evidence_store,
        "lemonde.fr",
        "lemonde-actu.info",
        "unrelated-shop.de",
    )

    attributed = {record.name for record in repository.domains_for_target(1)}
    assert "lemonde-actu.info" in attributed
    assert "unrelated-shop.de" not in attributed


async def test_the_scan_reports_what_it_declined_to_attribute(
    config: Config, repository: Repository, evidence_store: EvidenceStore
) -> None:
    use_certspotter(config)
    target = repository.upsert_target(brand="Le Monde", canonical_domain="lemonde.fr")
    body = certificate_listing("lemonde.fr", "stranger-one.de", "stranger-two.example")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("after"):
            return httpx.Response(200, content=b"[]")
        return httpx.Response(200, content=body)

    summaries = await run_scan(
        config=config,
        repository=repository,
        evidence=evidence_store,
        targets=[target],
        transport=httpx.MockTransport(handler),
    )
    assert summaries[0].unattributed == 2
    assert summaries[0].as_dict()["unattributed"] == 2
