"""Scan orchestration: ask the sources, persist what comes back.

At this stage a scan looks up each watched domain directly. Generated
variants — typos, homoglyphs, keyword combinations — are what make the tool
actually useful against impersonation, and they plug in here once the
permutation engine exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from ctwatch.config import Config
from ctwatch.net.client import PassiveHttpClient, UpstreamError
from ctwatch.net.policy import build_allowlist
from ctwatch.sources.base import CertObservation, Source, SourceError, SourceQuery
from ctwatch.sources.crtsh import CrtShSource
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository


@dataclass(slots=True)
class ScanSummary:
    """What one target's scan produced, in terms a report can quote."""

    brand: str
    canonical_domain: str
    queries: int = 0
    certificates: int = 0
    domains_seen: int = 0
    new_domains: int = 0
    observations: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "brand": self.brand,
            "canonical_domain": self.canonical_domain,
            "queries": self.queries,
            "certificates": self.certificates,
            "domains_seen": self.domains_seen,
            "new_domains": self.new_domains,
            "observations": self.observations,
            "errors": list(self.errors),
        }


def build_sources(
    config: Config,
    *,
    http: PassiveHttpClient,
    evidence: EvidenceStore,
    repository: Repository,
    only: list[str] | None = None,
) -> list[Source]:
    """Instantiate the sources enabled in the configuration."""

    wanted = {name.lower() for name in only} if only else None
    sources: list[Source] = []

    crtsh = config.sources.crtsh
    if crtsh.enabled and (wanted is None or CrtShSource.name in wanted):
        sources.append(
            CrtShSource(
                base_url=crtsh.base_url,
                http=http,
                evidence=evidence,
                repository=repository,
                cache_ttl_seconds=crtsh.cache_ttl_seconds,
            )
        )
    return sources


def persist_observation(
    repository: Repository,
    observation: CertObservation,
    *,
    target: WatchTarget | None,
    summary: ScanSummary,
) -> None:
    """Write one certificate and its names, counting what was new."""

    certificate = repository.upsert_certificate(
        source=observation.source,
        fingerprint_sha256=observation.fingerprint_sha256,
        source_ref=observation.source_ref,
        issuer=observation.issuer,
        serial_number=observation.serial_number,
        not_before=observation.not_before,
        not_after=observation.not_after,
        entry_timestamp=observation.entry_timestamp,
    )
    summary.certificates += 1

    for name in observation.names:
        was_known = repository.get_domain(name.ascii_name) is not None
        domain = repository.upsert_domain(
            name=name.ascii_name,
            unicode_name=name.unicode_name if name.is_idn else None,
            tld=name.tld,
            is_wildcard=name.is_wildcard,
            is_idn=name.is_idn,
            seen_at=observation.entry_timestamp or observation.retrieved_at,
        )
        summary.domains_seen += 1
        if not was_known:
            summary.new_domains += 1

        recorded = repository.record_observation(
            domain_id=domain.id,
            evidence_id=observation.evidence_id,
            source=observation.source,
            observed_at=observation.retrieved_at,
            certificate_id=certificate.id,
            target_id=None if target is None else target.id,
            query=observation.query,
        )
        if recorded is not None:
            summary.observations += 1


async def scan_target(
    *,
    target: WatchTarget,
    sources: list[Source],
    repository: Repository,
    since: datetime | None = None,
) -> ScanSummary:
    """Run every source against one target and persist the results."""

    summary = ScanSummary(brand=target.brand, canonical_domain=target.canonical_domain)
    query = SourceQuery(pattern=target.canonical_domain, exact=True, since=since)

    for source in sources:
        summary.queries += 1
        try:
            async for observation in source.search(query):
                persist_observation(repository, observation, target=target, summary=summary)
        except (SourceError, UpstreamError) as exc:
            # One source failing is normal — crt.sh alone is unavailable often
            # enough that aborting the whole scan would make the tool useless.
            summary.errors.append(f"{source.name}: {exc}")

    return summary


async def run_scan(
    *,
    config: Config,
    repository: Repository,
    evidence: EvidenceStore,
    targets: list[WatchTarget],
    since: datetime | None = None,
    only_sources: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[ScanSummary]:
    """Scan every requested target, then close the network client.

    ``transport`` exists so the test suite can replay recorded responses. It
    does not bypass the host allowlist: the policy transport still wraps it.
    """

    crtsh = config.sources.crtsh
    http = PassiveHttpClient(
        allowlist=build_allowlist(config),
        user_agent=config.network.user_agent,
        timeout=crtsh.timeout_seconds,
        max_attempts=crtsh.max_attempts,
        requests_per_second=crtsh.rate_limit_rps,
        transport=transport,
    )
    try:
        sources = build_sources(
            config, http=http, evidence=evidence, repository=repository, only=only_sources
        )
        if not sources:
            msg = "no source is enabled; check the `sources` section of the configuration"
            raise SourceError(msg)

        return [
            await scan_target(target=target, sources=sources, repository=repository, since=since)
            for target in targets
        ]
    finally:
        await http.aclose()
