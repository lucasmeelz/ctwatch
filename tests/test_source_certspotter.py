from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from ctwatch.net.client import HostAllowlist, PassiveHttpClient
from ctwatch.sources.base import CertObservation, SourceError, SourceQuery
from ctwatch.sources.certspotter import CertSpotterSource
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.repository import Repository

FIXTURES = Path(__file__).parent / "fixtures"
PAGE1 = (FIXTURES / "certspotter_page1.json").read_bytes()
PAGE2 = (FIXTURES / "certspotter_page2.json").read_bytes()


@pytest.fixture
def evidence_store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


def build_source(
    transport: httpx.MockTransport,
    repository: Repository,
    evidence_store: EvidenceStore,
    **kwargs: object,
) -> CertSpotterSource:
    http = PassiveHttpClient(
        allowlist=HostAllowlist(["api.certspotter.com"]),
        user_agent="ctwatch/test",
        backoff_base_seconds=0.0,
        transport=transport,
    )
    return CertSpotterSource(
        http=http,
        evidence=evidence_store,
        repository=repository,
        **kwargs,  # type: ignore[arg-type]
    )


def paging(calls: list[httpx.Request] | None = None) -> httpx.MockTransport:
    """Serves page 1, then page 2, then an empty page — as the API does."""

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        after = request.url.params.get("after")
        if after is None:
            return httpx.Response(200, content=PAGE1)
        if after == "16504649787":
            return httpx.Response(200, content=PAGE2)
        return httpx.Response(200, content=b"[]")

    return httpx.MockTransport(handler)


def serving(body: bytes, status: int = 200) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, content=body))


async def collect(source: CertSpotterSource, query: SourceQuery) -> list[CertObservation]:
    return [observation async for observation in source.search(query)]


async def test_issuances_are_parsed(repository: Repository, evidence_store: EvidenceStore) -> None:
    source = build_source(paging(), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))

    assert len(observations) == 3
    first = observations[0]
    assert [name.ascii_name for name in first.names] == [
        "lemonde-actu.info",
        "www.lemonde-actu.info",
    ]
    assert first.issuer == "C=US, O=Let's Encrypt, CN=R11"
    assert first.not_before == datetime(2026, 3, 8, 3, 12, 52, tzinfo=UTC)


async def test_certificate_fingerprint_is_captured(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    """The field crt.sh does not provide, and the one pivots depend on."""

    source = build_source(paging(), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))
    assert observations[0].fingerprint_sha256 == (
        "1a927566e4ae1e21426b431d3bcf4cc2b9752a1e53a8d2f3047e974413fea147"
    )


async def test_pagination_follows_the_cursor(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(paging(calls), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))

    assert [call.url.params.get("after") for call in calls] == [
        None,
        "16504649787",
        "17110044553",
    ]
    assert observations[2].names[0].ascii_name == "xn--lemnde-yqf.fr"


async def test_page_limit_is_respected(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(paging(calls), repository, evidence_store, max_pages=1)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))
    assert len(calls) == 1
    assert len(observations) == 2


async def test_each_page_is_archived_separately(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(paging(), repository, evidence_store)
    observations = await collect(source, SourceQuery(pattern="lemonde.fr"))

    evidence_ids = {observation.evidence_id for observation in observations}
    assert len(evidence_ids) == 2
    for evidence_id in evidence_ids:
        record = repository.get_evidence(evidence_id)
        assert record is not None
        assert evidence_store.verify(record)


async def test_api_key_is_sent_when_configured(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(paging(calls), repository, evidence_store, api_key="secret-token")
    await collect(source, SourceQuery(pattern="lemonde.fr"))
    assert calls[0].headers["authorization"] == "Bearer secret-token"


async def test_no_authorization_header_without_a_key(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(paging(calls), repository, evidence_store)
    await collect(source, SourceQuery(pattern="lemonde.fr"))
    assert "authorization" not in calls[0].headers


async def test_exact_lookup_disables_subdomains(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(paging(calls), repository, evidence_store)
    await collect(source, SourceQuery(pattern="lemonde-actu.info", include_subdomains=False))
    assert calls[0].url.params["include_subdomains"] == "false"
    assert calls[0].url.params["domain"] == "lemonde-actu.info"


async def test_since_filters_older_certificates(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(paging(), repository, evidence_store)
    observations = await collect(
        source, SourceQuery(pattern="lemonde.fr", since=datetime(2026, 2, 1, tzinfo=UTC))
    )
    assert len(observations) == 2


async def test_refusal_message_from_the_api_is_surfaced(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    body = json.dumps(
        {
            "code": "not_allowed_by_plan",
            "message": "Cannot search example.invalid because it is not beneath an eTLD",
        }
    ).encode()
    source = build_source(serving(body, status=403), repository, evidence_store)
    with pytest.raises(SourceError, match="not beneath an eTLD"):
        await collect(source, SourceQuery(pattern="example.invalid"))


async def test_error_payload_with_a_200_is_still_an_error(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    body = json.dumps({"code": "rate_limited", "message": "too many requests"}).encode()
    source = build_source(serving(body), repository, evidence_store)
    with pytest.raises(SourceError, match="too many requests"):
        await collect(source, SourceQuery(pattern="lemonde.fr"))


async def test_html_instead_of_json_is_reported(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    source = build_source(serving(b"<html>gateway</html>"), repository, evidence_store)
    with pytest.raises(SourceError, match="did not return JSON"):
        await collect(source, SourceQuery(pattern="lemonde.fr"))


async def test_repeated_query_is_served_from_cache(
    repository: Repository, evidence_store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []
    source = build_source(paging(calls), repository, evidence_store)
    query = SourceQuery(pattern="lemonde.fr")
    first = await collect(source, query)
    before = len(calls)
    second = await collect(source, query)

    assert len(calls) == before
    assert [o.source_ref for o in first] == [o.source_ref for o in second]
