from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from ctwatch.net.client import HostAllowlist, PassiveHttpClient
from ctwatch.sources.base import CertObservation, SourceError, SourceQuery
from ctwatch.sources.crtsh import CrtShSource
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.repository import Repository

FIXTURES = Path(__file__).parent / "fixtures"
LISTING = (FIXTURES / "crtsh_lemonde.json").read_bytes()


@pytest.fixture
def evidence_store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


def build_source(
    transport: httpx.MockTransport,
    repository: Repository,
    evidence_store: EvidenceStore,
    *,
    cache_ttl_seconds: int = 3600,
) -> CrtShSource:
    http = PassiveHttpClient(
        allowlist=HostAllowlist(["crt.sh"]),
        user_agent="ctwatch/test",
        backoff_base_seconds=0.0,
        transport=transport,
    )
    return CrtShSource(
        http=http,
        evidence=evidence_store,
        repository=repository,
        cache_ttl_seconds=cache_ttl_seconds,
    )


def serving(
    body: bytes, status: int = 200, calls: list[httpx.Request] | None = None
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


async def collect(source: CrtShSource, query: SourceQuery) -> list[CertObservation]:
    return [observation async for observation in source.search(query)]


async def test_listing_is_parsed_into_observations(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(LISTING), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))

    # The fourth fixture row carries no usable name and is dropped.
    assert len(observations) == 3
    first = observations[0]
    assert [name.ascii_name for name in first.names] == [
        "lemonde-actu.info",
        "www.lemonde-actu.info",
    ]
    assert first.issuer == "C=US, O=Let's Encrypt, CN=R11"
    assert first.source_ref == "18453729001"
    assert first.not_before == datetime(2026, 3, 8, 3, 12, 52, tzinfo=UTC)


async def test_wildcard_name_is_kept_as_a_wildcard(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(LISTING), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))
    assert observations[1].names[0].is_wildcard is True


async def test_punycode_name_is_decoded_for_the_reader(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(LISTING), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))
    idn = observations[2].names[0]
    assert idn.ascii_name == "xn--lemnde-yqf.fr"
    assert idn.unicode_name == "lemоnde.fr"
    assert idn.is_idn is True


async def test_every_observation_points_at_archived_evidence(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(LISTING), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))

    evidence_ids = {observation.evidence_id for observation in observations}
    assert len(evidence_ids) == 1
    record = repository.get_evidence(evidence_ids.pop())
    assert record is not None
    assert evidence_store.read(record) == LISTING
    assert record.endpoint.startswith("https://crt.sh/")


async def test_exact_query_asks_for_subdomains_too(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(serving(LISTING, calls=calls), repository, evidence_store)
    await collect(source, SourceQuery(pattern="lemonde.fr"))
    assert calls[0].url.params["q"] == "%.lemonde.fr"
    assert calls[0].url.params["output"] == "json"


async def test_since_filters_out_older_entries(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(LISTING), repository, evidence_store)
    observations = await collect(
        source,
        SourceQuery(pattern="lemonde.fr", since=datetime(2026, 2, 1, tzinfo=UTC)),
    )
    assert len(observations) == 2


async def test_second_identical_query_is_served_from_cache(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(serving(LISTING, calls=calls), repository, evidence_store)
    query = SourceQuery(pattern="lemonde.fr")
    first = await collect(source, query)
    second = await collect(source, query)

    assert len(calls) == 1
    assert [o.source_ref for o in first] == [o.source_ref for o in second]


async def test_cache_can_be_disabled(repository: Repository, evidence_store: EvidenceStore) -> None:
    calls: list[httpx.Request] = []
    source = build_source(
        serving(LISTING, calls=calls), repository, evidence_store, cache_ttl_seconds=0
    )
    query = SourceQuery(pattern="lemonde.fr")
    await collect(source, query)
    await collect(source, query)
    assert len(calls) == 2


async def test_html_error_page_is_reported_clearly(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    body = b"<html><body><h1>503 Service Temporarily Unavailable</h1></body></html>"
    source = build_source(serving(body), repository, evidence_store)
    with pytest.raises(SourceError, match="did not return JSON"):
        await collect(source, SourceQuery(pattern="lemonde.fr"))


async def test_empty_listing_yields_nothing(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(b"[]"), repository, evidence_store)
    assert await collect(source, SourceQuery(pattern="lemonde.fr")) == []


async def test_error_status_is_surfaced(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(b"nope", status=404), repository, evidence_store)
    with pytest.raises(SourceError, match="HTTP 404"):
        await collect(source, SourceQuery(pattern="lemonde.fr"))
