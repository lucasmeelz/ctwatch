"""Cert Spotter source.

SSLMate's Cert Spotter serves the same Certificate Transparency data as crt.sh
through a considerably more dependable interface. It works without an API key
at a low rate, pages through results with a cursor, and — unlike crt.sh's JSON
listing — returns the SHA-256 fingerprint of each certificate, which is what
lets observations from different sources be reconciled and what makes
fingerprint pivots possible at all.

The free tier is metered per address, so a key is worth configuring for any
sustained use. Everything here works without one.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError

from ctwatch.names import normalize_all
from ctwatch.sources.base import CertObservation, Source, SourceError, SourceQuery
from ctwatch.timeutil import parse_iso

DEFAULT_MAX_PAGES = 10


class CertSpotterIssuer(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    friendly_name: str | None = None
    pubkey_sha256: str | None = None

    def label(self) -> str | None:
        return self.name or self.friendly_name


class CertSpotterIssuance(BaseModel):
    """One certificate as Cert Spotter reports it."""

    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    cert_sha256: str | None = None
    tbs_sha256: str | None = None
    pubkey_sha256: str | None = None
    dns_names: list[str] = []
    issuer: CertSpotterIssuer | None = None
    not_before: str | None = None
    not_after: str | None = None
    revoked: bool | None = None

    def moment(self, field_name: str) -> Any:
        raw = getattr(self, field_name, None)
        if not raw:
            return None
        try:
            return parse_iso(str(raw))
        except ValueError:
            return None


def _parse_page(content: bytes, endpoint: str) -> list[CertSpotterIssuance]:
    try:
        payload: Any = json.loads(content)
    except json.JSONDecodeError as exc:
        preview = content[:120].decode("utf-8", errors="replace").strip()
        msg = f"cert spotter did not return JSON for {endpoint}: {preview!r}"
        raise SourceError(msg) from exc

    if payload is None:
        return []
    if isinstance(payload, dict):
        # The error shape: {"code": "...", "message": "..."}
        message = payload.get("message") or payload.get("code") or "unspecified error"
        msg = f"cert spotter refused {endpoint}: {message}"
        raise SourceError(msg)
    if not isinstance(payload, list):
        msg = f"cert spotter returned an unexpected JSON shape for {endpoint}"
        raise SourceError(msg)

    issuances: list[CertSpotterIssuance] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            issuances.append(CertSpotterIssuance.model_validate(item))
        except ValidationError:
            continue
    return issuances


class CertSpotterSource(Source):
    name: ClassVar[str] = "certspotter"

    def __init__(
        self,
        *,
        base_url: str = "https://api.certspotter.com",
        api_key: str | None = None,
        max_pages: int = DEFAULT_MAX_PAGES,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._max_pages = max(1, max_pages)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def search(self, query: SourceQuery) -> AsyncIterator[CertObservation]:
        """Page through every issuance Cert Spotter holds for this name."""

        after: str | None = None

        for page in range(self._max_pages):
            params: dict[str, str | int] = {
                "domain": query.pattern,
                "include_subdomains": "true" if query.include_subdomains else "false",
                "expand": "dns_names",
                "match_wildcards": "true",
            }
            if after is not None:
                params["after"] = after

            fetched = await self.fetch(
                url=f"{self._base_url}/v1/issuances",
                params=params,
                cache_key=f"certspotter|{query.cache_key}|page={page}|after={after or ''}",
                headers=self._headers(),
            )

            issuances = _parse_page(fetched.content, fetched.evidence.endpoint)
            if not issuances:
                return

            for issuance in issuances:
                names = normalize_all(issuance.dns_names)
                if not names:
                    continue

                entry_timestamp = issuance.moment("not_before")
                if (
                    query.since is not None
                    and entry_timestamp is not None
                    and entry_timestamp < query.since
                ):
                    continue

                yield CertObservation(
                    source=self.name,
                    names=names,
                    evidence_id=fetched.evidence.id,
                    retrieved_at=fetched.evidence.requested_at,
                    query=query.pattern,
                    issuer=issuance.issuer.label() if issuance.issuer else None,
                    not_before=issuance.moment("not_before"),
                    not_after=issuance.moment("not_after"),
                    entry_timestamp=entry_timestamp,
                    fingerprint_sha256=issuance.cert_sha256,
                    source_ref=issuance.id,
                    raw=issuance.model_dump(exclude_none=True),
                )

            last_id = issuances[-1].id
            if last_id is None:
                return
            after = last_id
