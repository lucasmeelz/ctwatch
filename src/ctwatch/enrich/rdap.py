"""Registration data, read from the registry that issued the domain.

RDAP answers the questions a report needs and Certificate Transparency cannot:
who the registrar is, when the domain was created, and whether the registry has
locked it. A name registered nine days ago and a name registered in 2005 are
different stories about the same certificate.

RDAP is also the one service whose hosts cannot be listed in a configuration
file: several hundred registries each run their own server. Rather than punch a
hole in the host allowlist, ctwatch reads IANA's bootstrap document — the
authoritative registry of RDAP servers — and permits exactly the hosts it
names, recording that they came from there. The allowlist stays auditable, and
no host is ever added because a watched domain pointed at it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from ctwatch.names import DomainName
from ctwatch.net.client import HostAllowlist, PassiveHttpClient
from ctwatch.publicsuffix import split
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import EvidenceRecord
from ctwatch.timeutil import parse_iso

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_HOST = "data.iana.org"
BOOTSTRAP_ORIGIN = "IANA RDAP bootstrap (data.iana.org/rdap/dns.json)"


class RdapError(RuntimeError):
    """Raised when registration data could not be retrieved or parsed."""


@dataclass(frozen=True, slots=True)
class Bootstrap:
    """IANA's map from top-level domain to RDAP server."""

    services: dict[str, tuple[str, ...]]
    published: str | None = None

    @classmethod
    def parse(cls, content: bytes) -> Bootstrap:
        try:
            payload: Any = json.loads(content)
        except json.JSONDecodeError as exc:
            msg = "the RDAP bootstrap document is not valid JSON"
            raise RdapError(msg) from exc
        if not isinstance(payload, dict):
            msg = "the RDAP bootstrap document is not an object"
            raise RdapError(msg)

        services: dict[str, tuple[str, ...]] = {}
        for entry in payload.get("services", []):
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            tlds, urls = entry[0], entry[1]
            cleaned = tuple(str(url).rstrip("/") for url in urls if str(url).startswith("https://"))
            if not cleaned:
                continue
            for tld in tlds:
                services[str(tld).strip().lower()] = cleaned

        if not services:
            msg = "the RDAP bootstrap document lists no usable service"
            raise RdapError(msg)
        return cls(services=services, published=payload.get("publication"))

    def servers_for(self, tld: str) -> tuple[str, ...]:
        return self.services.get(tld.strip().lower().lstrip("."), ())

    def hosts(self) -> tuple[str, ...]:
        found = {
            host
            for urls in self.services.values()
            for host in (urlsplit(url).hostname for url in urls)
            if host
        }
        return tuple(sorted(found))


@dataclass(frozen=True, slots=True)
class Registration:
    """What a registry says about a domain."""

    domain: str
    rdap_server: str
    evidence_id: int
    retrieved_at: datetime
    registrar: str | None = None
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    last_changed_at: datetime | None = None
    statuses: tuple[str, ...] = ()
    nameservers: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "rdap_server": self.rdap_server,
            "registrar": self.registrar,
            "registered_at": None if self.registered_at is None else self.registered_at.isoformat(),
            "expires_at": None if self.expires_at is None else self.expires_at.isoformat(),
            "statuses": list(self.statuses),
            "nameservers": list(self.nameservers),
        }


def _event(events: Any, action: str) -> datetime | None:
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction", "")).strip().lower() != action:
            continue
        raw = event.get("eventDate")
        if not raw:
            continue
        try:
            return parse_iso(str(raw))
        except ValueError:
            return None
    return None


def _registrar(entities: Any) -> str | None:
    """Pull the registrar's name out of the jCard soup RDAP returns."""

    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = [str(role).lower() for role in entity.get("roles", [])]
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    return str(item[3])
        handle = entity.get("handle")
        if handle:
            return str(handle)
    return None


def parse_registration(
    content: bytes, *, domain: str, server: str, evidence: EvidenceRecord
) -> Registration:
    try:
        payload: Any = json.loads(content)
    except json.JSONDecodeError as exc:
        msg = f"the RDAP response for {domain} is not valid JSON"
        raise RdapError(msg) from exc
    if not isinstance(payload, dict):
        msg = f"the RDAP response for {domain} is not an object"
        raise RdapError(msg)

    nameservers = tuple(
        str(entry.get("ldhName")).lower().rstrip(".")
        for entry in payload.get("nameservers", [])
        if isinstance(entry, dict) and entry.get("ldhName")
    )
    statuses = tuple(str(status) for status in payload.get("status", []) if status)

    return Registration(
        domain=domain,
        rdap_server=server,
        evidence_id=evidence.id,
        retrieved_at=evidence.requested_at,
        registrar=_registrar(payload.get("entities")),
        registered_at=_event(payload.get("events"), "registration"),
        expires_at=_event(payload.get("events"), "expiration"),
        last_changed_at=_event(payload.get("events"), "last changed"),
        statuses=statuses,
        nameservers=nameservers,
    )


class RdapClient:
    """Looks a domain up at the registry that is authoritative for its suffix."""

    def __init__(
        self,
        *,
        http: PassiveHttpClient,
        evidence: EvidenceStore,
        allowlist: HostAllowlist,
        bootstrap_url: str = BOOTSTRAP_URL,
    ) -> None:
        self._http = http
        self._evidence = evidence
        self._allowlist = allowlist
        self._bootstrap_url = bootstrap_url
        self._bootstrap: Bootstrap | None = None

    async def bootstrap(self) -> Bootstrap:
        """Fetch IANA's server list and permit exactly the hosts it names."""

        if self._bootstrap is not None:
            return self._bootstrap

        result = await self._http.get(self._bootstrap_url, headers={"Accept": "application/json"})
        if result.status_code >= 400:
            msg = f"could not read the RDAP bootstrap document: HTTP {result.status_code}"
            raise RdapError(msg)

        self._evidence.capture(
            source="rdap-bootstrap",
            endpoint=result.url,
            content=result.content,
            requested_at=result.requested_at,
            status_code=result.status_code,
        )

        bootstrap = Bootstrap.parse(result.content)
        self._allowlist.allow(bootstrap.hosts(), origin=BOOTSTRAP_ORIGIN)
        self._bootstrap = bootstrap
        return bootstrap

    async def lookup(self, name: DomainName) -> Registration | None:
        """Return what the registry says, or ``None`` if it has no record."""

        parts = split(name.ascii_name)
        registrable = parts.registrable_domain
        if registrable is None:
            return None

        bootstrap = await self.bootstrap()
        servers = bootstrap.servers_for(parts.tld)
        if not servers:
            msg = f"no RDAP server is registered for the {parts.tld!r} suffix"
            raise RdapError(msg)

        last_error = ""
        for server in servers:
            url = f"{server}/domain/{registrable}"
            result = await self._http.get(url, headers={"Accept": "application/rdap+json"})

            if result.status_code == 404:
                # A registry that has no record is an answer, not a failure:
                # the name is not registered under that suffix.
                return None
            if result.status_code >= 400:
                last_error = f"HTTP {result.status_code} from {server}"
                continue

            record = self._evidence.capture(
                source="rdap",
                endpoint=result.url,
                content=result.content,
                requested_at=result.requested_at,
                status_code=result.status_code,
                meta={"domain": registrable, "server": server},
            )
            return parse_registration(
                result.content, domain=registrable, server=server, evidence=record
            )

        msg = f"no RDAP server answered for {registrable}: {last_error}"
        raise RdapError(msg)
