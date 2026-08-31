"""Running the passive enrichment steps over a set of domains.

Enrichment answers the questions a certificate alone cannot: who registered the
name and when, where it resolves, what the page looked like when a third party
rendered it, and — the part that turns a finding into a story — which other
domains share those attributes.

Every step here talks to somebody *about* the domain. None of them talks to the
domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from ctwatch.config import Config
from ctwatch.enrich.dns import DnsError, DohResolver, Resolution
from ctwatch.enrich.pivot import Pivot, pivots_for
from ctwatch.enrich.rdap import RdapClient, RdapError, Registration
from ctwatch.enrich.urlscan import ScanResult, UrlscanClient, UrlscanError
from ctwatch.names import DomainName
from ctwatch.net.client import PassiveHttpClient, UpstreamError
from ctwatch.net.policy import build_allowlist
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import DomainRecord
from ctwatch.store.repository import Repository


@dataclass(slots=True)
class Enrichment:
    """What the enrichment steps produced for one domain."""

    domain: DomainRecord
    registration: Registration | None = None
    resolution: Resolution | None = None
    scans: list[ScanResult] = field(default_factory=list)
    pivots: list[Pivot] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain.name,
            "display_name": self.domain.display_name,
            "registration": None if self.registration is None else self.registration.as_dict(),
            "dns": None if self.resolution is None else self.resolution.as_dict(),
            "scans": [scan.as_dict() for scan in self.scans],
            "pivots": [pivot.as_dict() for pivot in self.pivots],
            "errors": list(self.errors),
        }


def _domain_name(record: DomainRecord) -> DomainName:
    return DomainName(
        ascii_name=record.name,
        unicode_name=record.unicode_name or record.name,
        is_wildcard=record.is_wildcard,
    )


def _enrichment_rate(config: Config) -> float:
    """The most conservative rate among the enabled enrichment services."""

    rates = [
        service.rate_limit_rps
        for service in (config.enrich.dns, config.enrich.rdap, config.enrich.urlscan)
        if service.enabled
    ]
    return min(rates) if rates else 1.0


async def enrich_domains(
    *,
    config: Config,
    repository: Repository,
    evidence: EvidenceStore,
    domains: list[DomainRecord],
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[Enrichment]:
    """Enrich each domain, storing what each service said."""

    allowlist = build_allowlist(config)
    http = PassiveHttpClient(
        allowlist=allowlist,
        user_agent=config.network.user_agent,
        requests_per_second=_enrichment_rate(config),
        transport=transport,
    )

    rdap = RdapClient(
        http=http,
        evidence=evidence,
        allowlist=allowlist,
        bootstrap_url=config.enrich.rdap.bootstrap_url,
    )
    resolver = DohResolver(
        http=http,
        evidence=evidence,
        endpoint=config.enrich.dns.resolver_url,
        record_types=tuple(config.enrich.dns.record_types),
    )
    urlscan = UrlscanClient(
        http=http,
        evidence=evidence,
        api_key=config.enrich.urlscan.api_key(),
        limit=config.enrich.urlscan.limit,
    )

    results: list[Enrichment] = []
    try:
        for record in domains:
            name = _domain_name(record)
            enrichment = Enrichment(domain=record)

            if config.enrich.rdap.enabled:
                try:
                    registration = await rdap.lookup(name)
                except (RdapError, UpstreamError) as exc:
                    enrichment.errors.append(f"rdap: {exc}")
                else:
                    enrichment.registration = registration
                    if registration is not None:
                        repository.upsert_registration(
                            domain_id=record.id,
                            evidence_id=registration.evidence_id,
                            rdap_server=registration.rdap_server,
                            registrar=registration.registrar,
                            registered_at=registration.registered_at,
                            expires_at=registration.expires_at,
                            last_changed_at=registration.last_changed_at,
                            statuses=list(registration.statuses),
                            nameservers=list(registration.nameservers),
                            retrieved_at=registration.retrieved_at,
                        )

            if config.enrich.dns.enabled:
                try:
                    resolution = await resolver.resolve(name)
                except (DnsError, UpstreamError) as exc:
                    enrichment.errors.append(f"dns: {exc}")
                else:
                    enrichment.resolution = resolution
                    evidence_id = resolution.evidence_ids[0] if resolution.evidence_ids else None
                    if evidence_id is not None:
                        for entry in resolution.records:
                            repository.record_dns_record(
                                domain_id=record.id,
                                evidence_id=evidence_id,
                                record_type=entry.record_type,
                                value=entry.value,
                                ttl=entry.ttl,
                                observed_at=resolution.resolved_at,
                            )

            if config.enrich.urlscan.enabled:
                try:
                    scans = await urlscan.search(name)
                except (UrlscanError, UpstreamError) as exc:
                    enrichment.errors.append(f"urlscan: {exc}")
                else:
                    enrichment.scans = scans
                    for scan in scans:
                        repository.upsert_url_scan(
                            domain_id=record.id,
                            evidence_id=scan.evidence_id,
                            scan_uuid=scan.scan_uuid,
                            result_url=scan.result_url,
                            screenshot_url=scan.screenshot_url,
                            page_ip=scan.page_ip,
                            page_asn=scan.page_asn,
                            page_asn_name=scan.page_asn_name,
                            page_server=scan.page_server,
                            page_title=scan.page_title,
                            scanned_at=scan.scanned_at,
                            retrieved_at=scan.retrieved_at,
                        )

            enrichment.pivots = pivots_for(repository, domain_id=record.id, name=record.name)
            results.append(enrichment)
    finally:
        await http.aclose()

    return results
