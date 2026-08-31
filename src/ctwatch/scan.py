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
from ctwatch.matching.matcher import VariantMatcher
from ctwatch.names import DomainName
from ctwatch.net.client import PassiveHttpClient, UpstreamError
from ctwatch.net.policy import build_allowlist
from ctwatch.permutations.generator import PermutationGenerator
from ctwatch.permutations.model import PermutationKind
from ctwatch.publicsuffix import split
from ctwatch.sources.base import CertObservation, Source, SourceError, SourceQuery
from ctwatch.sources.certspotter import CertSpotterSource
from ctwatch.sources.crtsh import CrtShSource
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository

MAX_REPORTED_ERRORS = 5

# Candidates held while deciding whether a certificate's names concern the
# brand. This costs memory once per target, never a request.
RELEVANCE_VARIANTS = 500


@dataclass(slots=True)
class ScanSummary:
    """What one target's scan produced, in terms a report can quote."""

    brand: str
    canonical_domain: str
    queries: int = 0
    variants_queried: int = 0
    certificates: int = 0
    domains_seen: int = 0
    new_domains: int = 0
    observations: int = 0
    failed_queries: int = 0
    unattributed: int = 0
    by_source: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def record_failure(self, message: str) -> None:
        """Keep a few distinct failures, not one line per query.

        A scan with five hundred variants against an unavailable service would
        otherwise produce five hundred identical error strings.
        """

        self.failed_queries += 1
        if message not in self.errors and len(self.errors) < MAX_REPORTED_ERRORS:
            self.errors.append(message)

    def as_dict(self) -> dict[str, Any]:
        return {
            "brand": self.brand,
            "canonical_domain": self.canonical_domain,
            "queries": self.queries,
            "variants_queried": self.variants_queried,
            "certificates": self.certificates,
            "domains_seen": self.domains_seen,
            "new_domains": self.new_domains,
            "observations": self.observations,
            "failed_queries": self.failed_queries,
            "unattributed": self.unattributed,
            "by_source": dict(self.by_source),
            "errors": list(self.errors),
        }


def build_permutation_generator(config: Config, target: WatchTarget) -> PermutationGenerator:
    """A generator configured for one target, using that target's keywords."""

    kinds = set(PermutationKind)
    if not config.permutations.include_homoglyphs:
        kinds.discard(PermutationKind.HOMOGLYPH)
    return PermutationGenerator(
        layouts=tuple(config.permutations.keyboard_layouts),
        extra_tlds=config.permutations.extra_tlds,
        keywords=target.keywords,
        kinds=kinds,
    )


def build_sources(
    config: Config,
    *,
    http: PassiveHttpClient,
    evidence: EvidenceStore,
    repository: Repository,
    only: list[str] | None = None,
) -> list[Source]:
    """Instantiate the enabled sources, in the configured order."""

    wanted = {name.strip().lower() for name in only} if only else None
    sources: list[Source] = []

    for name in config.sources.order:
        if wanted is not None and name not in wanted:
            continue

        if name == CertSpotterSource.name and config.sources.certspotter.enabled:
            certspotter = config.sources.certspotter
            sources.append(
                CertSpotterSource(
                    base_url=certspotter.base_url,
                    api_key=certspotter.api_key(),
                    max_pages=certspotter.max_pages,
                    http=http,
                    evidence=evidence,
                    repository=repository,
                    cache_ttl_seconds=certspotter.cache_ttl_seconds,
                )
            )
        elif name == CrtShSource.name and config.sources.crtsh.enabled:
            crtsh = config.sources.crtsh
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


def is_relevant(name: DomainName, *, target: WatchTarget, matcher: VariantMatcher) -> bool:
    """Does this name have anything to do with the brand?

    A source returns whole certificates, and a certificate lists whatever its
    requester asked for. One observed here carried a hundred names, of which one
    was the brand's; attributing the other ninety-nine to the brand — as simply
    storing every name does — is how ninety-nine unrelated businesses became
    findings about Le Figaro.

    Two things make a name relevant: it belongs to the brand's own registration,
    or it resembles it. Everything else is stored without a target, so the
    certificate neighbourhood remains available for ownership inference while
    nothing is attributed to a brand it has no connection to.
    """

    parts = split(name.ascii_name)
    if parts.registrable_domain == split(target.canonical_domain).registrable_domain:
        return True
    return matcher.match(name.ascii_name) is not None


def persist_observation(
    repository: Repository,
    observation: CertObservation,
    *,
    target: WatchTarget | None,
    summary: ScanSummary,
    matcher: VariantMatcher | None = None,
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
        parts = split(name.ascii_name)
        domain = repository.upsert_domain(
            name=name.ascii_name,
            unicode_name=name.unicode_name if name.is_idn else None,
            registrable_domain=parts.registrable_domain,
            tld=parts.tld or name.tld,
            is_wildcard=name.is_wildcard,
            is_idn=name.is_idn,
            seen_at=observation.entry_timestamp or observation.retrieved_at,
        )
        summary.domains_seen += 1
        if not was_known:
            summary.new_domains += 1

        attributed = target
        if (
            target is not None
            and matcher is not None
            and not is_relevant(name, target=target, matcher=matcher)
        ):
            # Kept, but not attributed: the certificate neighbourhood is what
            # later proves which lookalikes the brand owns.
            attributed = None
            summary.unattributed += 1

        recorded = repository.record_observation(
            domain_id=domain.id,
            evidence_id=observation.evidence_id,
            source=observation.source,
            observed_at=observation.retrieved_at,
            certificate_id=certificate.id,
            target_id=None if attributed is None else attributed.id,
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
    queries: list[SourceQuery] | None = None,
    strategy: str = "failover",
) -> ScanSummary:
    """Run the planned queries against the sources and persist the results.

    Under the default failover strategy, each query stops at the first source
    that answers. crt.sh is unavailable often enough that a scan which gave up
    on the first failure would be useless, and asking every source for every
    name doubles the request budget for little gain.
    """

    summary = ScanSummary(brand=target.brand, canonical_domain=target.canonical_domain)
    planned = queries or [SourceQuery(pattern=target.canonical_domain, exact=True, since=since)]
    matcher = VariantMatcher.build([target], variants=RELEVANCE_VARIANTS)

    for query in planned:
        for source in sources:
            if not source.available:
                continue
            summary.queries += 1
            try:
                found = 0
                async for observation in source.search(query):
                    persist_observation(
                        repository,
                        observation,
                        target=target,
                        summary=summary,
                        matcher=matcher,
                    )
                    found += 1
            except (SourceError, UpstreamError) as exc:
                summary.record_failure(f"{source.name}: {exc}")
                if source.unavailable_reason is not None:
                    summary.record_failure(source.unavailable_reason)
                continue

            summary.by_source[source.name] = summary.by_source.get(source.name, 0) + found
            if strategy == "failover":
                break

    return summary


def plan_queries(
    *,
    config: Config,
    target: WatchTarget,
    since: datetime | None,
    variants: int,
) -> list[SourceQuery]:
    """The canonical domain, plus the generated candidates worth looking up.

    Each candidate costs one request against a rate-limited service, so how
    many to look up is a deliberate choice rather than a hidden default.
    Matching the whole candidate set at once is what the live feed is for.
    """

    planned = [SourceQuery(pattern=target.canonical_domain, exact=True, since=since)]
    if variants <= 0:
        return planned

    generator = build_permutation_generator(config, target)
    planned.extend(
        SourceQuery(
            pattern=permutation.name.ascii_name,
            exact=True,
            since=since,
            include_subdomains=False,
        )
        for permutation in generator.generate(target.canonical_domain, limit=variants)
    )
    return planned


async def run_scan(
    *,
    config: Config,
    repository: Repository,
    evidence: EvidenceStore,
    targets: list[WatchTarget],
    since: datetime | None = None,
    only_sources: list[str] | None = None,
    variants: int = 0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[ScanSummary]:
    """Scan every requested target, then close the network client.

    ``transport`` exists so the test suite can replay recorded responses. It
    does not bypass the host allowlist: the policy transport still wraps it.
    """

    # One client is shared by every source, so its throttle has to be the most
    # conservative of the enabled ones: crt.sh tolerates far less than Cert
    # Spotter, and exceeding what it accepts is how a scan turns into a wall of
    # 502s.
    limits = [
        source
        for source, enabled in (
            (config.sources.certspotter, config.sources.certspotter.enabled),
            (config.sources.crtsh, config.sources.crtsh.enabled),
        )
        if enabled
    ]
    rate = min((source.rate_limit_rps for source in limits), default=0.5)
    timeout = max((source.timeout_seconds for source in limits), default=45.0)
    attempts = max((source.max_attempts for source in limits), default=4)
    backoff = max((source.retry_backoff_seconds for source in limits), default=1.0)

    http = PassiveHttpClient(
        allowlist=build_allowlist(config),
        user_agent=config.network.user_agent,
        timeout=timeout,
        max_attempts=attempts,
        requests_per_second=rate,
        backoff_base_seconds=backoff,
        transport=transport,
    )
    try:
        sources = build_sources(
            config, http=http, evidence=evidence, repository=repository, only=only_sources
        )
        if not sources:
            msg = "no source is enabled; check the `sources` section of the configuration"
            raise SourceError(msg)

        summaries: list[ScanSummary] = []
        for target in targets:
            planned = plan_queries(config=config, target=target, since=since, variants=variants)
            summary = await scan_target(
                target=target,
                sources=sources,
                repository=repository,
                since=since,
                queries=planned,
                strategy=config.sources.strategy,
            )
            summary.variants_queried = max(0, len(planned) - 1)
            summaries.append(summary)
        return summaries
    finally:
        await http.aclose()
