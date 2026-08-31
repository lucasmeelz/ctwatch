"""Watching the live feed.

This is the answer to the cost problem the scan path has. Looking a candidate
up costs one request, so five hundred candidates across six brands is an hour
of polling. The feed inverts it: certificates arrive on their own and every one
of them is checked against the whole candidate set in a single dictionary
lookup. Coverage stops being something you pay for by the name.

Nothing is stored on the way past. A message that matches nothing is parsed and
dropped; only matches are archived, scored and announced.

When the feed cannot be kept open — the public server is a single point of
failure and is regularly down — the monitor falls back to polling the watched
domains through the ordinary sources rather than sitting silently on a dead
socket.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from ctwatch.config import Config
from ctwatch.findings import assess_target
from ctwatch.matching.matcher import Match, VariantMatcher
from ctwatch.names import DomainName
from ctwatch.net.client import PassiveHttpClient
from ctwatch.net.policy import build_allowlist
from ctwatch.notify.base import Alert, Notifier
from ctwatch.notify.console import ConsoleNotifier
from ctwatch.notify.jsonl import JsonlNotifier
from ctwatch.notify.webhook import WebhookNotifier
from ctwatch.scan import run_scan
from ctwatch.sources.certstream import (
    CertStreamClient,
    ConnectLike,
    StreamedCertificate,
    StreamUnavailableError,
)
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository
from ctwatch.timeutil import utc_now


@dataclass(slots=True)
class MonitorReport:
    """What a monitoring run did, in terms an operator can check."""

    certificates_seen: int = 0
    names_seen: int = 0
    matches: int = 0
    alerts: int = 0
    archived: int = 0
    disconnections: int = 0
    polling_rounds: int = 0
    polling_timeouts: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "certificates_seen": self.certificates_seen,
            "names_seen": self.names_seen,
            "matches": self.matches,
            "alerts": self.alerts,
            "archived": self.archived,
            "disconnections": self.disconnections,
            "polling_rounds": self.polling_rounds,
            "polling_timeouts": self.polling_timeouts,
            "errors": list(self.errors),
        }


def build_notifiers(config: Config, *, http: PassiveHttpClient | None = None) -> list[Notifier]:
    """Instantiate the notifiers the configuration turned on."""

    notifiers: list[Notifier] = []
    if config.notify.console.enabled:
        notifiers.append(ConsoleNotifier())
    if config.notify.jsonl.enabled:
        notifiers.append(JsonlNotifier(config.notify.jsonl.path))
    if config.notify.webhook.enabled and http is not None:
        notifiers.append(
            WebhookNotifier(
                http=http,
                url=config.notify.webhook.url,
                min_score=config.notify.webhook.min_score,
            )
        )
    return notifiers


def _persist_match(
    *,
    repository: Repository,
    evidence: EvidenceStore,
    certificate: StreamedCertificate,
    match: Match,
) -> tuple[int, int]:
    """Archive the message that matched and record what it showed.

    Returns the evidence id and the domain id. Only matching messages reach
    here: the rest of the feed is never written down.
    """

    record = evidence.capture(
        source="certstream",
        endpoint=f"certstream:{certificate.log_name or 'unknown-log'}",
        content=certificate.raw_message,
        requested_at=certificate.seen_at,
        meta={"matched": match.name.ascii_name, "target": match.target.canonical_domain},
    )

    stored = repository.upsert_certificate(
        source="certstream",
        fingerprint_sha256=certificate.fingerprint,
        source_ref=certificate.fingerprint,
        issuer=certificate.issuer,
        not_before=certificate.not_before,
        not_after=certificate.not_after,
        entry_timestamp=certificate.seen_at,
    )

    name: DomainName = match.name
    domain = repository.upsert_domain(
        name=name.ascii_name,
        unicode_name=name.unicode_name if name.is_idn else None,
        tld=name.tld,
        is_wildcard=name.is_wildcard,
        is_idn=name.is_idn,
        seen_at=certificate.not_before or certificate.seen_at,
    )
    repository.record_observation(
        domain_id=domain.id,
        evidence_id=record.id,
        source="certstream",
        observed_at=certificate.seen_at,
        certificate_id=stored.id,
        target_id=match.target.id,
        query=f"live feed match ({match.tier.value})",
    )
    return record.id, domain.id


async def handle_certificate(
    *,
    config: Config,
    repository: Repository,
    evidence: EvidenceStore,
    matcher: VariantMatcher,
    certificate: StreamedCertificate,
    notifiers: list[Notifier],
    report: MonitorReport,
) -> list[Alert]:
    """Check one certificate against the watchlist and announce what it hit."""

    report.certificates_seen += 1
    report.names_seen += len(certificate.names)

    matches = matcher.match_all(certificate.names)
    if not matches:
        return []

    alerts: list[Alert] = []
    for match in matches:
        report.matches += 1
        evidence_id, domain_id = _persist_match(
            repository=repository,
            evidence=evidence,
            certificate=certificate,
            match=match,
        )
        report.archived += 1

        _, assessments = assess_target(repository=repository, config=config, target=match.target)
        assessment = next((item for item in assessments if item.domain.id == domain_id), None)
        if assessment is None or assessment.suppressed:
            continue

        alert = Alert(
            match=match,
            certificate=certificate,
            score=assessment.score.value,
            confidence=assessment.confidence.code,
            summary=assessment.score.summary,
            evidence_id=evidence_id,
            finding_id=assessment.finding_id,
            detected_at=utc_now(),
        )
        alerts.append(alert)
        report.alerts += 1

        for notifier in notifiers:
            try:
                await notifier.publish(alert)
            except Exception as exc:  # a notifier must not take the monitor down
                report.errors.append(f"{notifier.name}: {type(exc).__name__}: {exc}")

    return alerts


async def run_monitor(
    *,
    config: Config,
    repository: Repository,
    evidence: EvidenceStore,
    targets: list[WatchTarget],
    variants: int = 500,
    max_certificates: int | None = None,
    connect: ConnectLike | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    notifiers: list[Notifier] | None = None,
    on_event: Callable[[str], None] | None = None,
) -> MonitorReport:
    """Follow the feed until it ends, or until the certificate budget is spent.

    ``on_event`` receives operational notices — losing the feed, falling back
    to polling — as they happen. A monitor that reports those only when it
    exits is indistinguishable from one that has hung.
    """

    report = MonitorReport()
    announce = on_event or (lambda _message: None)
    matcher = VariantMatcher.build(targets, variants=variants)

    http = PassiveHttpClient(
        allowlist=build_allowlist(config),
        user_agent=config.network.user_agent,
        transport=transport,
    )
    active = notifiers if notifiers is not None else build_notifiers(config, http=http)

    stream_config = config.sources.certstream
    client = CertStreamClient(
        url=stream_config.url,
        connect=connect,
        reconnect_delay=stream_config.reconnect_delay_seconds,
        max_reconnect_delay=stream_config.max_reconnect_delay_seconds,
        max_consecutive_failures=stream_config.max_consecutive_failures,
        idle_timeout=stream_config.idle_timeout_seconds,
        on_disconnect=lambda failures, reason: _record_disconnect(
            report, failures, reason, announce
        ),
    )

    try:
        try:
            async for certificate in client.stream():
                await handle_certificate(
                    config=config,
                    repository=repository,
                    evidence=evidence,
                    matcher=matcher,
                    certificate=certificate,
                    notifiers=active,
                    report=report,
                )
                if max_certificates is not None and report.certificates_seen >= max_certificates:
                    break
        except StreamUnavailableError as exc:
            report.errors.append(str(exc))
            if not stream_config.fallback_to_polling:
                raise
            announce("the live feed is unavailable; falling back to polling")
            await _poll_once(
                config=config,
                repository=repository,
                evidence=evidence,
                targets=targets,
                report=report,
                transport=transport,
                announce=announce,
            )
    finally:
        for notifier in active:
            with contextlib.suppress(Exception):
                await notifier.aclose()
        await http.aclose()

    return report


def _record_disconnect(
    report: MonitorReport,
    failures: int,
    reason: str,
    announce: Callable[[str], None],
) -> None:
    report.disconnections += 1
    message = f"feed disconnected ({failures}): {reason}"
    if message not in report.errors:
        report.errors.append(message)
    announce(message)


async def _poll_once(
    *,
    config: Config,
    repository: Repository,
    evidence: EvidenceStore,
    targets: list[WatchTarget],
    report: MonitorReport,
    transport: httpx.AsyncBaseTransport | None,
    announce: Callable[[str], None] | None = None,
) -> None:
    """Fall back to asking the ordinary sources.

    Polling covers far less ground than the feed — it sees the watched names
    rather than every certificate issued — but it is the difference between a
    degraded monitor and a silent one.

    The round is bounded. A source that is down consumes its entire timeout
    budget on every single query, and without a deadline a monitor spends
    minutes inside a dead service instead of going back to the feed.
    """

    say = announce or (lambda _message: None)
    deadline = config.sources.certstream.polling_timeout_seconds

    try:
        async with asyncio.timeout(deadline if deadline > 0 else None):
            summaries = await run_scan(
                config=config,
                repository=repository,
                evidence=evidence,
                targets=targets,
                transport=transport,
            )
    except TimeoutError:
        report.polling_timeouts += 1
        message = f"the polling round did not finish within {deadline:g}s"
        if message not in report.errors:
            report.errors.append(message)
        say(message)
        return

    report.polling_rounds += 1
    for summary in summaries:
        for message in summary.errors:
            if message not in report.errors:
                report.errors.append(message)

    for target in targets:
        assess_target(repository=repository, config=config, target=target)

    say(f"polled {len(targets)} target(s)")


async def poll_forever(
    *,
    config: Config,
    repository: Repository,
    evidence: EvidenceStore,
    targets: list[WatchTarget],
    report: MonitorReport,
    rounds: int | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Keep polling on an interval, for when the feed is not coming back."""

    completed = 0
    while rounds is None or completed < rounds:
        await _poll_once(
            config=config,
            repository=repository,
            evidence=evidence,
            targets=targets,
            report=report,
            transport=transport,
        )
        completed += 1
        if rounds is not None and completed >= rounds:
            break
        await asyncio.sleep(config.sources.certstream.polling_interval_seconds)
