"""Expectations for passive enrichment.

The recurring requirement across every case here: each step asks a third party
*about* the domain, and no step ever contacts the domain. The RDAP case is the
one that could have quietly broken that, since registry servers cannot be
listed in a configuration file, so it is checked explicitly.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from ctwatch.config import Config
from ctwatch.enrich.dns import DnsError, DohResolver
from ctwatch.enrich.pivot import pivots_for
from ctwatch.enrich.rdap import BOOTSTRAP_ORIGIN, RdapClient, RdapError
from ctwatch.enrich.urlscan import UrlscanClient, UrlscanError
from ctwatch.enrichment import enrich_domains
from ctwatch.names import normalize
from ctwatch.net.client import (
    HostAllowlist,
    HostNotAllowedError,
    PassiveHttpClient,
    UpstreamError,
)
from ctwatch.net.policy import build_allowlist
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import DomainRecord
from ctwatch.store.repository import Repository

FIXTURES = Path(__file__).parent / "fixtures"
BOOTSTRAP = (FIXTURES / "rdap_bootstrap.json").read_bytes()
RDAP_DOMAIN = (FIXTURES / "rdap_domain.json").read_bytes()
DOH_A = (FIXTURES / "doh_a.json").read_bytes()
DOH_NS = (FIXTURES / "doh_ns.json").read_bytes()
DOH_NXDOMAIN = (FIXTURES / "doh_nxdomain.json").read_bytes()
URLSCAN = (FIXTURES / "urlscan_search.json").read_bytes()

SUSPECT = "lemonde-actu.info"


@pytest.fixture
def store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.model_validate(
        {
            "targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}],
            "enrich": {
                "dns": {"rate_limit_rps": 0, "record_types": ["A", "NS"]},
                "rdap": {"rate_limit_rps": 0},
                "urlscan": {"rate_limit_rps": 0},
            },
            "storage": {
                "database": str(tmp_path / "ctwatch.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
        }
    )


def enrichment_transport(
    contacted: list[str] | None = None,
    *,
    rdap_status: int = 200,
) -> httpx.MockTransport:
    """Serves each enrichment service its own recorded response."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if contacted is not None:
            contacted.append(host)

        if host == "data.iana.org":
            return httpx.Response(200, content=BOOTSTRAP)
        if host == "rdap.identitydigital.services":
            return httpx.Response(rdap_status, content=RDAP_DOMAIN)
        if host == "cloudflare-dns.com":
            record_type = request.url.params.get("type")
            if record_type == "NS":
                return httpx.Response(200, content=DOH_NS)
            return httpx.Response(200, content=DOH_A)
        if host == "urlscan.io":
            return httpx.Response(200, content=URLSCAN)
        return httpx.Response(404, content=b"{}")

    return httpx.MockTransport(handler)


def client(transport: httpx.MockTransport, allowlist: HostAllowlist) -> PassiveHttpClient:
    return PassiveHttpClient(
        allowlist=allowlist,
        user_agent="ctwatch/test",
        backoff_base_seconds=0.0,
        transport=transport,
    )


# ----------------------------------------------------------------------------
# RDAP


async def test_bootstrap_permits_exactly_the_hosts_iana_names(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["data.iana.org"])
    rdap = RdapClient(
        http=client(enrichment_transport(), allowlist), evidence=store, allowlist=allowlist
    )

    assert allowlist.permits("rdap.nic.fr") is False
    bootstrap = await rdap.bootstrap()

    assert allowlist.permits("rdap.nic.fr") is True
    assert allowlist.permits("rdap.verisign.com") is True
    assert bootstrap.servers_for("fr") == ("https://rdap.nic.fr",)


async def test_bootstrap_records_where_each_host_came_from(
    repository: Repository, store: EvidenceStore
) -> None:
    """A permitted host with no stated origin is an unverifiable claim."""

    allowlist = HostAllowlist(["data.iana.org"])
    rdap = RdapClient(
        http=client(enrichment_transport(), allowlist), evidence=store, allowlist=allowlist
    )
    await rdap.bootstrap()

    provenance = allowlist.provenance()
    assert provenance["data.iana.org"] == "configuration"
    assert provenance["rdap.nic.fr"] == BOOTSTRAP_ORIGIN


async def test_bootstrap_ignores_non_https_servers(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["data.iana.org"])
    rdap = RdapClient(
        http=client(enrichment_transport(), allowlist), evidence=store, allowlist=allowlist
    )
    bootstrap = await rdap.bootstrap()
    assert "insecure.example" not in bootstrap.hosts()


async def test_registration_facts_are_read(repository: Repository, store: EvidenceStore) -> None:
    allowlist = HostAllowlist(["data.iana.org"])
    rdap = RdapClient(
        http=client(enrichment_transport(), allowlist), evidence=store, allowlist=allowlist
    )
    registration = await rdap.lookup(normalize(SUSPECT))

    assert registration is not None
    assert registration.registrar == "Budget Registrar Ltd"
    assert registration.registered_at == datetime(2026, 3, 1, 9, 14, tzinfo=UTC)
    assert registration.statuses == ("client transfer prohibited",)
    assert registration.nameservers == (
        "ns1.cheap-hosting.example",
        "ns2.cheap-hosting.example",
    )
    assert repository.get_evidence(registration.evidence_id) is not None


async def test_an_unregistered_domain_is_an_answer_not_a_failure(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["data.iana.org"])
    rdap = RdapClient(
        http=client(enrichment_transport(rdap_status=404), allowlist),
        evidence=store,
        allowlist=allowlist,
    )
    assert await rdap.lookup(normalize(SUSPECT)) is None


async def test_a_suffix_with_no_rdap_server_is_reported(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["data.iana.org"])
    rdap = RdapClient(
        http=client(enrichment_transport(), allowlist), evidence=store, allowlist=allowlist
    )
    with pytest.raises(RdapError, match="no RDAP server"):
        await rdap.lookup(normalize("something.xyz"))


# ----------------------------------------------------------------------------
# DNS over HTTPS


async def test_resolution_reads_addresses_and_nameservers(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["cloudflare-dns.com"])
    resolver = DohResolver(
        http=client(enrichment_transport(), allowlist),
        evidence=store,
        endpoint="https://cloudflare-dns.com/dns-query",
        record_types=("A", "NS"),
    )
    resolution = await resolver.resolve(normalize(SUSPECT))

    assert resolution.addresses == ("203.0.113.42",)
    assert resolution.of_type("NS") == (
        "ns1.cheap-hosting.example",
        "ns2.cheap-hosting.example",
    )
    assert resolution.exists is True
    assert len(resolution.evidence_ids) == 2


async def test_a_name_that_does_not_exist_is_recorded_as_such(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["cloudflare-dns.com"])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=DOH_NXDOMAIN))
    resolver = DohResolver(
        http=client(transport, allowlist),
        evidence=store,
        endpoint="https://cloudflare-dns.com/dns-query",
        record_types=("A",),
    )
    resolution = await resolver.resolve(normalize("nothing-here.example"))
    assert resolution.exists is False
    assert resolution.records == ()


async def test_a_resolver_returning_html_is_reported(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["cloudflare-dns.com"])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"<html>"))
    resolver = DohResolver(
        http=client(transport, allowlist),
        evidence=store,
        endpoint="https://cloudflare-dns.com/dns-query",
        record_types=("A",),
    )
    with pytest.raises(DnsError, match="did not return JSON"):
        await resolver.resolve(normalize(SUSPECT))


# ----------------------------------------------------------------------------
# urlscan


async def test_urlscan_search_reads_what_was_already_rendered(
    repository: Repository, store: EvidenceStore
) -> None:
    allowlist = HostAllowlist(["urlscan.io"])
    urlscan = UrlscanClient(http=client(enrichment_transport(), allowlist), evidence=store)
    scans = await urlscan.search(normalize(SUSPECT))

    assert len(scans) == 1
    assert scans[0].page_ip == "203.0.113.42"
    assert scans[0].page_asn == "AS64500"
    assert scans[0].screenshot_url


async def test_urlscan_search_sends_no_key_when_none_is_configured(
    repository: Repository, store: EvidenceStore
) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, content=URLSCAN)

    allowlist = HostAllowlist(["urlscan.io"])
    urlscan = UrlscanClient(http=client(httpx.MockTransport(handler), allowlist), evidence=store)
    await urlscan.search(normalize(SUSPECT))

    assert "api-key" not in calls[0].headers
    assert calls[0].url.params["q"] == f"domain:{SUSPECT}"


async def test_urlscan_refusal_is_surfaced(repository: Repository, store: EvidenceStore) -> None:
    allowlist = HostAllowlist(["urlscan.io"])
    transport = httpx.MockTransport(
        lambda request: httpx.Response(403, content=b'{"message": "quota exceeded"}')
    )
    urlscan = UrlscanClient(http=client(transport, allowlist), evidence=store)
    with pytest.raises(UrlscanError, match="quota exceeded"):
        await urlscan.search(normalize(SUSPECT))


async def test_urlscan_throttling_is_retried_then_given_up_on(
    repository: Repository, store: EvidenceStore
) -> None:
    """429 is a "come back later", not a refusal, so it goes through retries."""

    allowlist = HostAllowlist(["urlscan.io"])
    transport = httpx.MockTransport(lambda request: httpx.Response(429, content=b"slow down"))
    http = PassiveHttpClient(
        allowlist=allowlist,
        user_agent="ctwatch/test",
        backoff_base_seconds=0.0,
        max_attempts=2,
        transport=transport,
    )
    urlscan = UrlscanClient(http=http, evidence=store)
    with pytest.raises(UpstreamError, match="after 2 attempts"):
        await urlscan.search(normalize(SUSPECT))
    await http.aclose()


# ----------------------------------------------------------------------------
# The whole enrichment pass


async def observe(repository: Repository, store: EvidenceStore, name: str) -> DomainRecord:
    evidence = store.capture(
        source="certspotter", endpoint="https://api.certspotter.com/", content=b"[]"
    )
    certificate = repository.upsert_certificate(source="certspotter", source_ref=name)
    domain = repository.upsert_domain(name=name)
    repository.record_observation(
        domain_id=domain.id,
        evidence_id=evidence.id,
        source="certspotter",
        certificate_id=certificate.id,
    )
    return domain


async def test_enrichment_stores_everything_it_learned(
    config: Config, repository: Repository, store: EvidenceStore
) -> None:
    domain = await observe(repository, store, SUSPECT)
    results = await enrich_domains(
        config=config,
        repository=repository,
        evidence=store,
        domains=[domain],
        transport=enrichment_transport(),
    )

    assert results[0].errors == []
    registration = repository.get_registration(domain.id)
    assert registration is not None
    assert registration["registrar"] == "Budget Registrar Ltd"

    records = {(row["record_type"], row["value"]) for row in repository.dns_records_for(domain.id)}
    assert ("A", "203.0.113.42") in records
    assert ("NS", "ns1.cheap-hosting.example") in records
    assert repository.url_scans_for(domain.id)


async def test_enrichment_never_contacts_the_domain_it_investigates(
    config: Config, repository: Repository, store: EvidenceStore
) -> None:
    contacted: list[str] = []
    domain = await observe(repository, store, SUSPECT)
    await enrich_domains(
        config=config,
        repository=repository,
        evidence=store,
        domains=[domain],
        transport=enrichment_transport(contacted),
    )

    assert SUSPECT not in contacted
    assert set(contacted) <= {
        "data.iana.org",
        "rdap.identitydigital.services",
        "cloudflare-dns.com",
        "urlscan.io",
    }


async def test_the_allowlist_still_refuses_the_watched_domain_after_bootstrap(
    config: Config, repository: Repository, store: EvidenceStore
) -> None:
    """Widening the allowlist for RDAP must not widen it for anything else."""

    allowlist = build_allowlist(config)
    rdap = RdapClient(
        http=client(enrichment_transport(), allowlist), evidence=store, allowlist=allowlist
    )
    await rdap.bootstrap()

    assert allowlist.permits(SUSPECT) is False
    assert allowlist.permits("lemonde.fr") is False

    http = client(enrichment_transport(), allowlist)
    with pytest.raises(HostNotAllowedError):
        await http.get(f"https://{SUSPECT}/")
    await http.aclose()


async def test_a_failing_service_does_not_stop_the_others(
    config: Config, repository: Repository, store: EvidenceStore
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "urlscan.io":
            return httpx.Response(403, content=b'{"message": "no"}')
        if request.url.host == "data.iana.org":
            return httpx.Response(200, content=BOOTSTRAP)
        if request.url.host == "rdap.identitydigital.services":
            return httpx.Response(200, content=RDAP_DOMAIN)
        if request.url.params.get("type") == "NS":
            return httpx.Response(200, content=DOH_NS)
        return httpx.Response(200, content=DOH_A)

    domain = await observe(repository, store, SUSPECT)
    results = await enrich_domains(
        config=config,
        repository=repository,
        evidence=store,
        domains=[domain],
        transport=httpx.MockTransport(handler),
    )

    assert results[0].registration is not None
    assert results[0].resolution is not None
    assert any("urlscan" in message for message in results[0].errors)


# ----------------------------------------------------------------------------
# Pivots


async def test_domains_on_the_same_address_are_grouped(
    config: Config, repository: Repository, store: EvidenceStore
) -> None:
    """One lookalike is a nuisance. A dozen on one address is a campaign."""

    domains = []
    for name in (SUSPECT, "lemonde-live.info", "lefigaro-actu.info"):
        domains.append(await observe(repository, store, name))

    await enrich_domains(
        config=config,
        repository=repository,
        evidence=store,
        domains=domains,
        transport=enrichment_transport(),
    )

    pivots = pivots_for(repository, domain_id=domains[0].id, name=SUSPECT)
    by_kind = {pivot.kind: pivot for pivot in pivots}

    assert set(by_kind["address"].domains) == {"lemonde-live.info", "lefigaro-actu.info"}
    assert set(by_kind["nameserver"].domains) == {"lemonde-live.info", "lefigaro-actu.info"}
    assert by_kind["registrar"].domains
    assert by_kind["address"].description.startswith("resolves to")


async def test_a_domain_alone_produces_no_pivot(
    config: Config, repository: Repository, store: EvidenceStore
) -> None:
    domain = await observe(repository, store, SUSPECT)
    await enrich_domains(
        config=config,
        repository=repository,
        evidence=store,
        domains=[domain],
        transport=enrichment_transport(),
    )
    assert pivots_for(repository, domain_id=domain.id, name=SUSPECT) == []
