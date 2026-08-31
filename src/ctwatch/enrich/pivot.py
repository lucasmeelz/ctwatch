"""Finding the other domains that belong to the same operation.

A single impersonating domain is a nuisance. Twenty of them on one address,
registered the same week through the same registrar, is a campaign — and that
is the finding worth publishing. Pivots are what turn one into the other.

Everything here is computed from what previous enrichment already stored. No
request is made, and nothing is inferred from contacting a domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ctwatch.store.repository import Repository

# How many domains sharing an attribute stops being a coincidence. One other
# domain on a shared hosting IP means nothing; a dozen is a pattern.
INTERESTING_CLUSTER_SIZE = 2


@dataclass(frozen=True, slots=True)
class Pivot:
    """One attribute shared with other domains, and who shares it."""

    kind: str
    value: str
    description: str
    domains: tuple[str, ...]

    @property
    def size(self) -> int:
        return len(self.domains)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "description": self.description,
            "domains": list(self.domains),
            "size": self.size,
        }


def _others(names: list[str], subject: str) -> tuple[str, ...]:
    return tuple(name for name in names if name != subject)


def pivots_for(repository: Repository, *, domain_id: int, name: str) -> list[Pivot]:
    """Every attribute this domain shares with at least one other."""

    pivots: list[Pivot] = []

    for record in repository.dns_records_for(domain_id):
        record_type = str(record["record_type"])
        value = str(record["value"])
        shared = _others(repository.domains_sharing_dns_value(record_type, value), name)
        if len(shared) < INTERESTING_CLUSTER_SIZE - 1:
            continue

        if record_type in {"A", "AAAA"}:
            kind, description = "address", f"resolves to {value}"
        elif record_type == "NS":
            kind, description = "nameserver", f"served by {value}"
        elif record_type == "MX":
            kind, description = "mail_exchange", f"receives mail through {value}"
        else:
            kind, description = record_type.lower(), f"{record_type} record {value}"
        pivots.append(Pivot(kind=kind, value=value, description=description, domains=shared))

    shared_certificate = _others(repository.names_sharing_certificate(domain_id), name)
    if shared_certificate:
        pivots.append(
            Pivot(
                kind="certificate",
                value="shared certificate",
                description="listed on the same certificate",
                domains=shared_certificate,
            )
        )

    for scan in repository.url_scans_for(domain_id):
        asn = scan["page_asn"]
        if not asn:
            continue
        shared_asn = _others(repository.domains_sharing_asn(str(asn)), name)
        if len(shared_asn) < INTERESTING_CLUSTER_SIZE - 1:
            continue
        label = scan["page_asn_name"] or asn
        pivots.append(
            Pivot(
                kind="asn",
                value=str(asn),
                description=f"hosted in {label}",
                domains=shared_asn,
            )
        )

    registration = repository.get_registration(domain_id)
    if registration is not None and registration["registrar"]:
        registrar = str(registration["registrar"])
        shared_registrar = _others(repository.domains_sharing_registrar(registrar), name)
        if shared_registrar:
            pivots.append(
                Pivot(
                    kind="registrar",
                    value=registrar,
                    description=f"registered through {registrar}",
                    domains=shared_registrar,
                )
            )

    # Deduplicate on (kind, value): a domain with two A records pointing at the
    # same address should not produce the same pivot twice.
    seen: set[tuple[str, str]] = set()
    unique: list[Pivot] = []
    for pivot in pivots:
        key = (pivot.kind, pivot.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(pivot)

    unique.sort(key=lambda pivot: (-pivot.size, pivot.kind, pivot.value))
    return unique
