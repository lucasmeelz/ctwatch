from __future__ import annotations

import httpx
import pytest

from ctwatch.config import Config
from ctwatch.net.client import (
    HostAllowlist,
    HostNotAllowedError,
    InsecureSchemeError,
    PassiveHttpClient,
    UpstreamError,
)
from ctwatch.net.policy import allowed_hosts, build_allowlist

WATCHED_DOMAINS = ["lemonde.fr", "lemonde-actu.info", "xn--lemnde-cua.fr"]


def client(handler: httpx.MockTransport, **kwargs: object) -> PassiveHttpClient:
    defaults: dict[str, object] = {
        "allowlist": HostAllowlist(["crt.sh"]),
        "user_agent": "ctwatch/test",
        "backoff_base_seconds": 0.0,
        "transport": handler,
    }
    defaults.update(kwargs)
    return PassiveHttpClient(**defaults)  # type: ignore[arg-type]


def responder(status: int = 200, body: bytes = b"[]") -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, content=body))


def test_allowlist_matches_exact_hosts_and_subdomain_wildcards() -> None:
    allowlist = HostAllowlist(["crt.sh", "*.example.org", " API.CERTSPOTTER.COM "])
    assert allowlist.permits("crt.sh")
    assert allowlist.permits("CRT.SH.")
    assert allowlist.permits("api.certspotter.com")
    assert allowlist.permits("a.example.org")
    assert not allowlist.permits("example.org")
    assert not allowlist.permits("evil-crt.sh")
    assert not allowlist.permits(None)


async def test_watched_domains_are_never_contacted() -> None:
    """The central guarantee: looking at a domain must not touch it."""

    async with client(responder()) as http:
        for domain in WATCHED_DOMAINS:
            with pytest.raises(HostNotAllowedError, match="not in the allowed-host list"):
                await http.get(f"https://{domain}/")


async def test_plain_http_is_refused() -> None:
    async with client(responder()) as http:
        with pytest.raises(InsecureSchemeError):
            await http.get("http://crt.sh/")


async def test_redirect_to_a_forbidden_host_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "crt.sh":
            return httpx.Response(302, headers={"Location": "https://lemonde-actu.info/"})
        return httpx.Response(200, content=b"trapped")

    async with client(httpx.MockTransport(handler)) as http:
        with pytest.raises(HostNotAllowedError):
            await http.get("https://crt.sh/?q=lemonde.fr")


async def test_successful_fetch_reports_what_was_retrieved() -> None:
    async with client(responder(body=b'[{"id": 1}]')) as http:
        result = await http.get("https://crt.sh/", params={"q": "lemonde.fr"})
    assert result.status_code == 200
    assert result.content == b'[{"id": 1}]'
    assert result.attempts == 1
    assert result.requested_at.tzinfo is not None


async def test_transient_failures_are_retried_then_succeed() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, content=b"ok")

    async with client(httpx.MockTransport(handler)) as http:
        result = await http.get("https://crt.sh/")
    assert result.attempts == 3
    assert result.content == b"ok"


async def test_retry_budget_is_finite() -> None:
    async with client(responder(status=503), max_attempts=2) as http:
        with pytest.raises(UpstreamError, match="after 2 attempts"):
            await http.get("https://crt.sh/")


async def test_client_errors_are_not_retried() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404)

    async with client(httpx.MockTransport(handler)) as http:
        result = await http.get("https://crt.sh/")
    assert result.status_code == 404
    assert len(calls) == 1


async def test_connection_errors_are_retried() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 2:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, content=b"ok")

    async with client(httpx.MockTransport(handler)) as http:
        result = await http.get("https://crt.sh/")
    assert result.attempts == 2


def test_allowlist_is_built_from_declared_services_only() -> None:
    config = Config.model_validate(
        {"targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}]}
    )
    hosts = allowed_hosts(config)
    assert "crt.sh" in hosts
    assert "lemonde.fr" not in hosts

    allowlist = build_allowlist(config)
    assert allowlist.permits("crt.sh")
    assert not allowlist.permits("lemonde.fr")
