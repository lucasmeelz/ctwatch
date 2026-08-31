"""Name resolution, done over HTTPS through a resolver of the operator's choosing.

Resolving a suspicious name is not contacting it — the query goes to a
resolver, never to the domain — but a plaintext DNS query still tells whoever
is on the path exactly which names an analyst is interested in. DNS over HTTPS
removes that leak, keeps the traffic inside the same audited HTTP client, and
means the response can be archived as evidence like everything else.

It also avoids adding a DNS library to a project whose only network dependency
is an HTTP client.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ctwatch.names import DomainName
from ctwatch.net.client import PassiveHttpClient
from ctwatch.store.evidence import EvidenceStore
from ctwatch.timeutil import utc_now

# The record types that say something about who is behind a domain and where
# it is hosted. Anything else is noise for this purpose.
DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "NS", "MX")

RECORD_TYPE_NUMBERS: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}

NXDOMAIN = 3


class DnsError(RuntimeError):
    """Raised when a resolver answered with something unusable."""


@dataclass(frozen=True, slots=True)
class DnsRecord:
    name: str
    record_type: str
    value: str
    ttl: int | None = None


@dataclass(frozen=True, slots=True)
class Resolution:
    """Everything one resolver said about one name."""

    domain: str
    records: tuple[DnsRecord, ...]
    evidence_ids: tuple[int, ...]
    resolved_at: datetime
    exists: bool = True

    def of_type(self, record_type: str) -> tuple[str, ...]:
        return tuple(record.value for record in self.records if record.record_type == record_type)

    @property
    def addresses(self) -> tuple[str, ...]:
        return self.of_type("A") + self.of_type("AAAA")

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "exists": self.exists,
            "records": [
                {"type": record.record_type, "value": record.value, "ttl": record.ttl}
                for record in self.records
            ],
        }


def parse_answer(content: bytes, *, record_type: str, domain: str) -> tuple[list[DnsRecord], bool]:
    """Read one DNS-over-HTTPS JSON answer."""

    try:
        payload: Any = json.loads(content)
    except json.JSONDecodeError as exc:
        msg = f"the resolver did not return JSON for {domain} {record_type}"
        raise DnsError(msg) from exc
    if not isinstance(payload, dict):
        msg = f"the resolver returned an unexpected shape for {domain} {record_type}"
        raise DnsError(msg)

    if payload.get("Status") == NXDOMAIN:
        return [], False

    records: list[DnsRecord] = []
    for answer in payload.get("Answer", []):
        if not isinstance(answer, dict):
            continue
        kind = RECORD_TYPE_NUMBERS.get(int(answer.get("type", 0)))
        value = str(answer.get("data", "")).strip().rstrip(".")
        if not kind or not value:
            continue
        ttl = answer.get("TTL")
        records.append(
            DnsRecord(
                name=str(answer.get("name", domain)).rstrip("."),
                record_type=kind,
                value=value,
                ttl=None if ttl is None else int(ttl),
            )
        )
    return records, True


class DohResolver:
    """Asks a public resolver about a name, over HTTPS."""

    def __init__(
        self,
        *,
        http: PassiveHttpClient,
        evidence: EvidenceStore,
        endpoint: str,
        record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES,
    ) -> None:
        self._http = http
        self._evidence = evidence
        self._endpoint = endpoint
        self._record_types = record_types

    async def resolve(self, name: DomainName) -> Resolution:
        records: list[DnsRecord] = []
        evidence_ids: list[int] = []
        exists = False
        resolved_at: datetime | None = None

        for record_type in self._record_types:
            result = await self._http.get(
                self._endpoint,
                params={"name": name.ascii_name, "type": record_type},
                headers={"Accept": "application/dns-json"},
            )
            if result.status_code >= 400:
                msg = (
                    f"resolver returned HTTP {result.status_code} "
                    f"for {name.ascii_name} {record_type}"
                )
                raise DnsError(msg)

            record = self._evidence.capture(
                source="dns",
                endpoint=result.url,
                content=result.content,
                requested_at=result.requested_at,
                status_code=result.status_code,
                meta={"domain": name.ascii_name, "type": record_type},
            )
            evidence_ids.append(record.id)
            resolved_at = resolved_at or result.requested_at

            found, present = parse_answer(
                result.content, record_type=record_type, domain=name.ascii_name
            )
            records.extend(found)
            exists = exists or present

        return Resolution(
            domain=name.ascii_name,
            records=tuple(dict.fromkeys(records)),
            evidence_ids=tuple(evidence_ids),
            resolved_at=resolved_at or utc_now(),
            exists=exists,
        )
