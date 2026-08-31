"""Expectations for live monitoring.

Two properties matter more than the rest. The feed is enormous and almost
entirely irrelevant, so nothing that fails to match may be written down. And
the public feed is a single point of failure, so a monitor that loses it has to
degrade to polling rather than sit quietly on a dead socket.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from ctwatch.config import Config
from ctwatch.monitor import MonitorReport, build_notifiers, run_monitor
from ctwatch.notify.base import Alert
from ctwatch.sources.certstream import (
    CertStreamClient,
    StreamUnavailableError,
    parse_message,
)
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository

FIXTURES = Path(__file__).parent / "fixtures"
CRTSH_LISTING = (FIXTURES / "crtsh_lemonde.json").read_bytes()


def certificate_message(
    *names: str,
    fingerprint: str = "aa:bb:cc:dd",
    issuer: str = "C=US, O=Let's Encrypt, CN=R11",
) -> str:
    return json.dumps(
        {
            "message_type": "certificate_update",
            "data": {
                "update_type": "X509LogEntry",
                "cert_index": 42,
                "seen": 1772000000.0,
                "source": {"name": "Google 'argon2026' log", "url": "ct.googleapis.com"},
                "leaf_cert": {
                    "all_domains": list(names),
                    "subject": {"CN": names[0]},
                    "issuer": {"aggregated": issuer, "O": "Let's Encrypt"},
                    "not_before": 1771990000.0,
                    "not_after": 1779990000.0,
                    "fingerprint": fingerprint,
                },
            },
        }
    )


HEARTBEAT = json.dumps({"message_type": "heartbeat", "timestamp": 1772000000.0})


class FakeSocket:
    def __init__(self, messages: list[str]) -> None:
        self._messages = messages

    def __aiter__(self) -> AsyncIterator[str]:
        async def generator() -> AsyncIterator[str]:
            for message in self._messages:
                yield message

        return generator()


class FakeConnection:
    """One connection attempt: either a set of messages, or a failure."""

    def __init__(self, messages: list[str] | None = None, error: Exception | None = None) -> None:
        self._messages = messages or []
        self._error = error

    async def __aenter__(self) -> FakeSocket:
        if self._error is not None:
            raise self._error
        return FakeSocket(self._messages)

    async def __aexit__(self, *args: object) -> None:
        return None


def feed(*attempts: FakeConnection) -> Any:
    """A connect callable that plays the given attempts in order."""

    remaining = list(attempts)

    def connect(url: str, *args: object, **kwargs: object) -> FakeConnection:
        if remaining:
            return remaining.pop(0)
        return FakeConnection(error=ConnectionResetError("feed gone"))

    return connect


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.model_validate(
        {
            "targets": [
                {
                    "brand": "Le Monde",
                    "canonical_domains": ["lemonde.fr"],
                    "keywords": ["actu", "info"],
                }
            ],
            "sources": {
                "order": ["crtsh"],
                "certspotter": {"enabled": False},
                "crtsh": {"rate_limit_rps": 0, "max_attempts": 1, "retry_backoff_seconds": 0},
                "certstream": {
                    "enabled": True,
                    "reconnect_delay_seconds": 0,
                    "max_consecutive_failures": 2,
                },
            },
            "notify": {"console": {"enabled": False}},
            "storage": {
                "database": str(tmp_path / "ctwatch.db"),
                "evidence_dir": str(tmp_path / "evidence"),
            },
        }
    )


@pytest.fixture
def target(repository: Repository) -> WatchTarget:
    return repository.upsert_target(
        brand="Le Monde", canonical_domain="lemonde.fr", keywords=["actu", "info"]
    )


@pytest.fixture
def store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


class Recorder:
    """A notifier that keeps what it was told."""

    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    @property
    def name(self) -> str:
        return "recorder"

    async def publish(self, alert: Alert) -> None:
        self.alerts.append(alert)

    async def aclose(self) -> None:
        return None


# ----------------------------------------------------------------------------
# Reading the feed


def test_a_certificate_message_is_parsed() -> None:
    certificate = parse_message(certificate_message("lemonde-actu.info", "www.lemonde-actu.info"))
    assert certificate is not None
    assert certificate.names == ("lemonde-actu.info", "www.lemonde-actu.info")
    assert certificate.issuer == "C=US, O=Let's Encrypt, CN=R11"
    assert certificate.fingerprint == "aabbccdd"
    assert certificate.not_before is not None


@pytest.mark.parametrize(
    "payload",
    [HEARTBEAT, "not json at all", json.dumps({"data": {}}), json.dumps([1, 2]), b"\xff\xfe"],
)
def test_anything_that_is_not_a_certificate_is_ignored(payload: str | bytes) -> None:
    assert parse_message(payload) is None


async def test_the_stream_gives_up_after_its_failure_budget() -> None:
    client = CertStreamClient(
        url="wss://example.invalid/",
        connect=feed(
            FakeConnection(error=ConnectionResetError("nope")),
            FakeConnection(error=ConnectionResetError("still nope")),
        ),
        reconnect_delay=0.0,
        max_consecutive_failures=2,
    )
    with pytest.raises(StreamUnavailableError) as caught:
        async for _ in client.stream():
            pass
    assert caught.value.failures == 2


async def test_a_reconnection_resets_the_failure_count() -> None:
    """The budget counts consecutive disconnects, and a good run clears it.

    A feed that drops once an hour must not accumulate its way to a shutdown.
    Note that a stream ending cleanly counts as a disconnect too: as far as a
    monitor is concerned, a feed that stopped sending is a feed that is down.
    """

    seen: list[str] = []
    client = CertStreamClient(
        url="wss://example.invalid/",
        connect=feed(
            FakeConnection(error=ConnectionResetError("blip")),
            FakeConnection([certificate_message("lemonde-actu.info")]),
            FakeConnection([certificate_message("lemonde-live.info")]),
            FakeConnection(error=ConnectionResetError("down")),
            FakeConnection(error=ConnectionResetError("still down")),
            FakeConnection(error=ConnectionResetError("gone")),
        ),
        reconnect_delay=0.0,
        max_consecutive_failures=3,
    )
    with pytest.raises(StreamUnavailableError):
        async for certificate in client.stream():
            seen.extend(certificate.names)
    assert seen == ["lemonde-actu.info", "lemonde-live.info"]


# ----------------------------------------------------------------------------
# What the monitor stores


async def test_only_matching_certificates_are_written_down(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    """The feed is mostly other people's certificates. None of it may be kept."""

    messages = [
        certificate_message("example.com", "www.example.com"),
        certificate_message("kubernetes.io"),
        certificate_message("lemonde-actu.info"),
        certificate_message("some-random-shop.de"),
    ]
    recorder = Recorder()
    report = await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(FakeConnection(messages)),
        max_certificates=4,
        notifiers=[recorder],
    )

    assert report.certificates_seen == 4
    assert report.matches == 1
    assert report.archived == 1
    assert len(list(store.root.rglob("*.gz"))) == 1
    assert repository.count_domains() == 1
    assert repository.get_domain("lemonde-actu.info") is not None
    assert repository.get_domain("example.com") is None


async def test_a_match_becomes_an_alert_with_its_reasoning(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    recorder = Recorder()
    await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(FakeConnection([certificate_message("lemonde-actu.info")])),
        max_certificates=1,
        notifiers=[recorder],
    )

    assert len(recorder.alerts) == 1
    alert = recorder.alerts[0]
    assert alert.domain == "lemonde-actu.info"
    assert alert.match.target.brand == "Le Monde"
    assert alert.score > 0
    assert alert.confidence
    assert alert.match.detail
    assert alert.finding_id is not None

    payload = alert.as_dict()
    assert payload["technique"]
    assert payload["issuer"]
    assert payload["evidence_id"]


async def test_the_archived_message_is_the_one_that_matched(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    message = certificate_message("lemonde-actu.info")
    recorder = Recorder()
    await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(FakeConnection([message])),
        max_certificates=1,
        notifiers=[recorder],
    )

    record = repository.get_evidence(recorder.alerts[0].evidence_id)
    assert record is not None
    assert store.read(record) == message.encode()


async def test_a_disguised_name_from_the_feed_is_caught(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    recorder = Recorder()
    await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(FakeConnection([certificate_message("xn--lemnde-yqf.fr")])),
        max_certificates=1,
        notifiers=[recorder],
    )

    assert len(recorder.alerts) == 1
    assert recorder.alerts[0].display_name == "lemоnde.fr"
    assert recorder.alerts[0].as_dict()["idn"] is True


async def test_the_watched_domain_itself_raises_no_alert(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    recorder = Recorder()
    report = await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(FakeConnection([certificate_message("www.lemonde.fr", "lemonde.fr")])),
        max_certificates=1,
        notifiers=[recorder],
    )

    assert report.matches == 0
    assert recorder.alerts == []


# ----------------------------------------------------------------------------
# Losing the feed


async def test_losing_the_feed_falls_back_to_polling(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    """A monitor that cannot reach the feed must degrade, not go quiet."""

    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=CRTSH_LISTING))
    report = await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(
            FakeConnection(error=ConnectionResetError("down")),
            FakeConnection(error=ConnectionResetError("still down")),
        ),
        transport=transport,
        notifiers=[Recorder()],
    )

    assert report.disconnections == 2
    assert report.polling_rounds == 1
    assert any("could not be kept open" in message for message in report.errors)
    assert repository.count_domains() > 0


async def test_the_fallback_can_be_turned_off(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    config.sources.certstream.fallback_to_polling = False
    with pytest.raises(StreamUnavailableError):
        await run_monitor(
            config=config,
            repository=repository,
            evidence=store,
            targets=[target],
            connect=feed(FakeConnection(error=ConnectionResetError("down"))),
            notifiers=[Recorder()],
        )


# ----------------------------------------------------------------------------
# Notifiers


async def test_alerts_are_appended_as_json_lines(
    config: Config,
    repository: Repository,
    store: EvidenceStore,
    target: WatchTarget,
    tmp_path: Path,
) -> None:
    config.notify.jsonl.enabled = True
    config.notify.jsonl.path = tmp_path / "alerts.jsonl"

    await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(FakeConnection([certificate_message("lemonde-actu.info")])),
        max_certificates=1,
    )

    lines = config.notify.jsonl.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["domain"] == "lemonde-actu.info"
    assert entry["brand"] == "Le Monde"


async def test_a_failing_notifier_does_not_stop_the_monitor(
    config: Config, repository: Repository, store: EvidenceStore, target: WatchTarget
) -> None:
    class Broken:
        @property
        def name(self) -> str:
            return "broken"

        async def publish(self, alert: Alert) -> None:
            msg = "the chat integration is down"
            raise RuntimeError(msg)

        async def aclose(self) -> None:
            return None

    recorder = Recorder()
    report = await run_monitor(
        config=config,
        repository=repository,
        evidence=store,
        targets=[target],
        connect=feed(FakeConnection([certificate_message("lemonde-actu.info")])),
        max_certificates=1,
        notifiers=[Broken(), recorder],
    )

    assert len(recorder.alerts) == 1
    assert any("chat integration" in message for message in report.errors)


def test_notifiers_are_built_from_the_configuration(config: Config, tmp_path: Path) -> None:
    config.notify.console.enabled = True
    config.notify.jsonl.enabled = True
    config.notify.jsonl.path = tmp_path / "alerts.jsonl"
    names = {notifier.name for notifier in build_notifiers(config)}
    assert names == {"console", "jsonl"}


def test_a_webhook_must_be_declared_with_an_https_url() -> None:
    with pytest.raises(ValueError, match="https"):
        Config.model_validate({"notify": {"webhook": {"enabled": True, "url": "http://x/"}}})


def test_an_enabled_webhook_host_joins_the_allowlist() -> None:
    from ctwatch.net.policy import allowed_hosts

    config = Config.model_validate(
        {"notify": {"webhook": {"enabled": True, "url": "https://hooks.example.org/ctwatch"}}}
    )
    assert "hooks.example.org" in allowed_hosts(config)


def test_the_report_is_serialisable() -> None:
    assert MonitorReport(certificates_seen=3).as_dict()["certificates_seen"] == 3
