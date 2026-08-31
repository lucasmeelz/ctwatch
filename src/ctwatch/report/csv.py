"""Flat export, for the spreadsheet stage of an investigation.

One row per finding, with the columns someone sorts and filters on. The score
breakdown is flattened into its own columns rather than buried in a JSON blob,
because a column nobody can sort is a column nobody uses.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable

from ctwatch.config import SCORING_CRITERIA
from ctwatch.report.dossier import Dossier

BASE_COLUMNS: tuple[str, ...] = (
    "finding_id",
    "brand",
    "watched_domain",
    "domain",
    "displayed_as",
    "is_idn",
    "score",
    "confidence",
    "status",
    "registrar",
    "registered_at",
    "first_certificate",
    "issuer",
    "addresses",
    "nameservers",
    "shared_with",
    "evidence_count",
    "summary",
)


def columns() -> tuple[str, ...]:
    return BASE_COLUMNS + tuple(f"score_{criterion}" for criterion in SCORING_CRITERIA)


def _row(dossier: Dossier) -> dict[str, str]:
    certificates = dossier.certificates
    oldest = min((c.not_before for c in certificates if c.not_before is not None), default=None)
    addresses = [value for kind, value in dossier.dns if kind in {"A", "AAAA"}]
    nameservers = [value for kind, value in dossier.dns if kind == "NS"]
    shared = sorted({name for pivot in dossier.pivots for name in pivot.domains})

    contributions = {
        str(item.get("criterion")): float(item.get("weighted", 0.0))
        for item in dossier.contributions
    }

    row = {
        "finding_id": str(dossier.finding_id),
        "brand": dossier.target.brand,
        "watched_domain": dossier.target.canonical_domain,
        "domain": dossier.domain.name,
        "displayed_as": dossier.domain.display_name if dossier.domain.is_idn else "",
        "is_idn": "yes" if dossier.domain.is_idn else "no",
        "score": f"{dossier.score:.4f}",
        "confidence": dossier.confidence or "",
        "status": dossier.status,
        "registrar": dossier.registration.registrar or "",
        "registered_at": dossier.registration.registered_at or "",
        "first_certificate": "" if oldest is None else oldest.date().isoformat(),
        "issuer": certificates[0].issuer if certificates and certificates[0].issuer else "",
        "addresses": " ".join(addresses),
        "nameservers": " ".join(nameservers),
        "shared_with": " ".join(shared[:20]),
        "evidence_count": str(len(dossier.evidence)),
        "summary": dossier.summary,
    }
    for criterion in SCORING_CRITERIA:
        row[f"score_{criterion}"] = f"{contributions.get(criterion, 0.0):.4f}"
    return row


def render_csv(dossiers: Iterable[Dossier]) -> str:
    """Render findings as CSV text, with a header row."""

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(columns()), lineterminator="\n")
    writer.writeheader()
    for dossier in dossiers:
        writer.writerow(_row(dossier))
    return buffer.getvalue()
