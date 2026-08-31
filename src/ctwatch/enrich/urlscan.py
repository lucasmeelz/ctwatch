"""Looking at a suspicious page without being the one who looks.

Opening a suspect site from an analyst's machine puts their address in the
operator's logs and tells them someone is paying attention. urlscan.io renders
the page instead, from its own infrastructure, and keeps a screenshot and the
network trace.

Two modes, and the difference matters:

* **search** asks urlscan what it has already seen about a domain. It reveals
  nothing, needs no key, and is the default.
* **submit** asks urlscan to visit the page now. That is a real visit — by a
  third party rather than by the analyst, which is the point — and a public
  submission is itself visible to anyone watching urlscan, the operator
  included. It therefore requires a key, an explicit flag, and defaults to an
  unlisted scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ctwatch.names import DomainName
from ctwatch.net.client import PassiveHttpClient
from ctwatch.store.evidence import EvidenceStore
from ctwatch.timeutil import parse_iso

BASE_URL = "https://urlscan.io"
SEARCH_PATH = "/api/v1/search/"


class UrlscanError(RuntimeError):
    """Raised when urlscan answered with something unusable."""


@dataclass(frozen=True, slots=True)
class ScanResult:
    """One page urlscan has already rendered."""

    domain: str
    evidence_id: int
    retrieved_at: datetime
    scan_uuid: str | None = None
    result_url: str | None = None
    screenshot_url: str | None = None
    page_ip: str | None = None
    page_asn: str | None = None
    page_asn_name: str | None = None
    page_server: str | None = None
    page_title: str | None = None
    scanned_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "scan_uuid": self.scan_uuid,
            "result_url": self.result_url,
            "screenshot_url": self.screenshot_url,
            "ip": self.page_ip,
            "asn": self.page_asn,
            "asn_name": self.page_asn_name,
            "server": self.page_server,
            "title": self.page_title,
            "scanned_at": None if self.scanned_at is None else self.scanned_at.isoformat(),
        }


def _moment(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return parse_iso(str(raw))
    except ValueError:
        return None


def parse_search(
    content: bytes, *, domain: str, evidence_id: int, retrieved_at: datetime
) -> list[ScanResult]:
    try:
        payload: Any = json.loads(content)
    except json.JSONDecodeError as exc:
        msg = f"urlscan did not return JSON for {domain}"
        raise UrlscanError(msg) from exc
    if not isinstance(payload, dict):
        msg = f"urlscan returned an unexpected shape for {domain}"
        raise UrlscanError(msg)
    if "results" not in payload and payload.get("message"):
        msg = f"urlscan refused the search for {domain}: {payload['message']}"
        raise UrlscanError(msg)

    results: list[ScanResult] = []
    for item in payload.get("results", []):
        if not isinstance(item, dict):
            continue
        raw_page = item.get("page")
        raw_task = item.get("task")
        page: dict[str, Any] = raw_page if isinstance(raw_page, dict) else {}
        task: dict[str, Any] = raw_task if isinstance(raw_task, dict) else {}
        results.append(
            ScanResult(
                domain=domain,
                evidence_id=evidence_id,
                retrieved_at=retrieved_at,
                scan_uuid=str(item.get("_id")) if item.get("_id") else None,
                result_url=item.get("result"),
                screenshot_url=item.get("screenshot"),
                page_ip=page.get("ip"),
                page_asn=page.get("asn"),
                page_asn_name=page.get("asnname"),
                page_server=page.get("server"),
                page_title=page.get("title"),
                scanned_at=_moment(task.get("time")),
            )
        )
    return results


class UrlscanClient:
    """Reads what urlscan already knows about a domain."""

    def __init__(
        self,
        *,
        http: PassiveHttpClient,
        evidence: EvidenceStore,
        base_url: str = BASE_URL,
        api_key: str | None = None,
        limit: int = 10,
    ) -> None:
        self._http = http
        self._evidence = evidence
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._limit = max(1, limit)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["API-Key"] = self._api_key
        return headers

    async def search(self, name: DomainName) -> list[ScanResult]:
        """Ask urlscan what it has already rendered for this domain.

        This is a question about urlscan's archive. Nothing reaches the domain,
        and nobody watching the domain learns anything.
        """

        result = await self._http.get(
            f"{self._base_url}{SEARCH_PATH}",
            params={"q": f"domain:{name.ascii_name}", "size": self._limit},
            headers=self._headers(),
        )
        if result.status_code == 404:
            return []
        if result.status_code >= 400:
            detail = result.content[:160].decode("utf-8", errors="replace").strip()
            msg = f"urlscan returned HTTP {result.status_code} for {name.ascii_name}: {detail}"
            raise UrlscanError(msg)

        record = self._evidence.capture(
            source="urlscan",
            endpoint=result.url,
            content=result.content,
            requested_at=result.requested_at,
            status_code=result.status_code,
            meta={"domain": name.ascii_name},
        )
        return parse_search(
            result.content,
            domain=name.ascii_name,
            evidence_id=record.id,
            retrieved_at=record.requested_at,
        )
