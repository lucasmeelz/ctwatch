"""crt.sh source.

crt.sh exposes a JSON view over the aggregated Certificate Transparency logs.
It is free and requires no key, which makes it the natural default, but it is
also slow and frequently overloaded: expect multi-second responses, HTML error
pages instead of JSON, and outright outages. Everything here is written with
that in mind.

The ``%`` wildcard it accepts is useful, and structurally insufficient: a
search for ``%lemonde%`` cannot match a name whose "o" is Cyrillic, because
that name is stored as ``xn--`` punycode. Candidate names are therefore
generated first and looked up one by one; substring search is a complement,
never the primary path.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ctwatch.names import normalize_all
from ctwatch.sources.base import CertObservation, Source, SourceError, SourceQuery
from ctwatch.timeutil import parse_iso


class CrtShEntry(BaseModel):
    """One row of a crt.sh JSON listing.

    Unknown fields are ignored on purpose: crt.sh adds columns from time to
    time, and a new one is not a reason to lose a day of observations.
    """

    model_config = ConfigDict(extra="ignore")

    id: int | None = None
    issuer_name: str | None = None
    common_name: str | None = None
    name_value: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    entry_timestamp: str | None = None
    result_count: int | None = Field(default=None)

    def moment(self, field_name: str) -> datetime | None:
        raw = getattr(self, field_name, None)
        if not raw:
            return None
        try:
            return parse_iso(str(raw))
        except ValueError:
            return None


def _parse_listing(content: bytes, endpoint: str) -> list[CrtShEntry]:
    """Decode a crt.sh listing, with a readable error when it is not JSON."""

    try:
        payload: Any = json.loads(content)
    except json.JSONDecodeError as exc:
        preview = content[:120].decode("utf-8", errors="replace").strip()
        msg = (
            f"crt.sh did not return JSON for {endpoint} "
            f"(it usually serves an HTML error page when overloaded): {preview!r}"
        )
        raise SourceError(msg) from exc

    if payload is None:
        return []
    if not isinstance(payload, list):
        msg = f"crt.sh returned an unexpected JSON shape for {endpoint}: {type(payload).__name__}"
        raise SourceError(msg)

    entries: list[CrtShEntry] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            entries.append(CrtShEntry.model_validate(item))
        except ValidationError:
            # A single malformed row is not worth discarding the whole listing.
            continue
    return entries


class CrtShSource(Source):
    name: ClassVar[str] = "crtsh"

    def __init__(self, *, base_url: str = "https://crt.sh", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._base_url = base_url.rstrip("/")

    def _pattern_for(self, query: SourceQuery) -> str:
        if not query.exact:
            return query.pattern
        # A leading %. asks crt.sh for the name and everything below it.
        return f"%.{query.pattern}" if query.include_subdomains else query.pattern

    async def search(self, query: SourceQuery) -> AsyncIterator[CertObservation]:
        pattern = self._pattern_for(query)
        fetched = await self.fetch(
            url=f"{self._base_url}/",
            params={"q": pattern, "output": "json"},
            cache_key=f"crtsh|{query.cache_key}",
            headers={"Accept": "application/json"},
        )

        for entry in _parse_listing(fetched.content, fetched.evidence.endpoint):
            entry_timestamp = entry.moment("entry_timestamp")
            if (
                query.since is not None
                and entry_timestamp is not None
                and entry_timestamp < query.since
            ):
                continue

            raw_names: list[str] = []
            if entry.name_value:
                raw_names.append(entry.name_value)
            if entry.common_name:
                raw_names.append(entry.common_name)
            names = normalize_all(raw_names)
            if not names:
                continue

            yield CertObservation(
                source=self.name,
                names=names,
                evidence_id=fetched.evidence.id,
                retrieved_at=fetched.evidence.requested_at,
                query=pattern,
                issuer=entry.issuer_name,
                serial_number=entry.serial_number,
                not_before=entry.moment("not_before"),
                not_after=entry.moment("not_after"),
                entry_timestamp=entry_timestamp,
                source_ref=None if entry.id is None else str(entry.id),
                raw=entry.model_dump(exclude_none=True),
            )
