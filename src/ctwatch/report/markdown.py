"""The written report.

Two readers are assumed. One has to decide whether a finding is worth acting
on, and needs the reasoning, not the number. The other may be checking the work
months later, possibly in a dispute, and needs to know exactly what was
retrieved, from where, and how to confirm it independently.

So every claim is followed by its source, every score by its breakdown, and the
report ends with the commands that verify it without this tool.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from ctwatch import __version__
from ctwatch.report.dossier import Dossier
from ctwatch.timeutil import to_iso, utc_now

METHOD_NOTE = """This report was produced from Certificate Transparency logs and passive
enrichment only. No request was made to any of the domains it describes: their
operators have no way of knowing that this was written. Page renderings, where
present, were performed by urlscan.io rather than by the analyst.
"""


def _escape(value: str) -> str:
    return value.replace("|", "\\|")


def _table(headers: Iterable[str], rows: Iterable[Iterable[str]]) -> list[str]:
    columns = list(headers)
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    lines.extend("| " + " | ".join(_escape(cell) for cell in row) + " |" for row in rows)
    return lines


def _name_heading(dossier: Dossier) -> str:
    if dossier.domain.is_idn:
        return f"{dossier.domain.display_name} (`{dossier.domain.name}`)"
    return f"`{dossier.domain.name}`"


def _finding_section(dossier: Dossier) -> list[str]:
    lines = [f"### {_name_heading(dossier)}", ""]

    confidence = dossier.confidence_detail()
    header = [
        f"**Score** {dossier.score:.2f}",
        f"**Confidence** {dossier.confidence or 'not rated'}"
        + (f" — {confidence.get('label')}" if confidence.get("label") else ""),
        f"**Brand** {dossier.target.brand} ({dossier.target.canonical_domain})",
        f"**Status** {dossier.status}",
    ]
    lines.extend([" · ".join(header), ""])

    if dossier.domain.is_idn:
        lines.extend(
            [
                "This name is internationalised. What a reader sees is "
                f"`{dossier.domain.display_name}`; what is registered and what appears in "
                f"the certificate is `{dossier.domain.name}`. A search for the original "
                "spelling would not have found it.",
                "",
            ]
        )

    if dossier.suppressed and dossier.suppression_reason:
        lines.extend([f"Suppressed: {dossier.suppression_reason}", ""])

    if dossier.contributions:
        lines.extend(["**How the score was reached**", ""])
        lines.extend(
            _table(
                ["Criterion", "Value", "Weight", "Contribution", "Reason"],
                [
                    [
                        str(item.get("criterion", "")),
                        f"{float(item.get('value', 0)):.2f}",
                        f"{float(item.get('weight', 0)):.2f}",
                        f"{float(item.get('weighted', 0)):.3f}",
                        str(item.get("explanation", "")),
                    ]
                    for item in dossier.contributions
                ],
            )
        )
        lines.append("")

    if confidence:
        lines.extend(
            [
                "**Confidence**",
                "",
                f"- Source reliability {confidence.get('reliability', '?')}: "
                f"{confidence.get('reliability_reason', '')}",
                f"- Information credibility {confidence.get('credibility', '?')}: "
                f"{confidence.get('credibility_reason', '')}",
                "",
            ]
        )

    if dossier.certificates:
        lines.extend(["**Certificates**", ""])
        lines.extend(
            _table(
                ["Issued", "Expires", "Issuer", "SHA-256", "Seen through"],
                [
                    [
                        "" if c.not_before is None else c.not_before.date().isoformat(),
                        "" if c.not_after is None else c.not_after.date().isoformat(),
                        c.issuer or "",
                        (c.fingerprint_sha256 or "")[:16],
                        c.source,
                    ]
                    for c in dossier.certificates[:10]
                ],
            )
        )
        lines.append("")

    registration = dossier.registration
    if not registration.is_empty:
        lines.extend(["**Registration**", ""])
        if registration.registered_at:
            lines.append(f"- Registered {registration.registered_at}")
        if registration.registrar:
            lines.append(f"- Registrar {registration.registrar}")
        if registration.expires_at:
            lines.append(f"- Expires {registration.expires_at}")
        if registration.statuses:
            lines.append(f"- Registry status: {', '.join(registration.statuses)}")
        if registration.nameservers:
            lines.append(f"- Nameservers: {', '.join(registration.nameservers)}")
        if registration.rdap_server:
            lines.append(f"- Read from {registration.rdap_server}")
        lines.append("")

    if dossier.dns:
        lines.extend(["**Resolution**", ""])
        lines.extend(f"- {kind} {value}" for kind, value in dossier.dns[:20])
        lines.append("")

    if dossier.scans:
        lines.extend(["**Rendered by urlscan.io**", ""])
        for scan in dossier.scans[:5]:
            detail = ", ".join(
                part for part in (scan.ip, scan.asn_name, scan.server, scan.title) if part
            )
            if scan.result_url:
                lines.append(f"- [{scan.scanned_at or 'scan'}]({scan.result_url}) — {detail}")
            else:
                lines.append(f"- {scan.scanned_at or 'scan'} — {detail}")
        lines.append("")

    if dossier.pivots:
        lines.extend(["**Shared with other domains**", ""])
        for pivot in dossier.pivots[:10]:
            listed = ", ".join(f"`{name}`" for name in pivot.domains[:8])
            more = "" if pivot.size <= 8 else f" and {pivot.size - 8} more"
            lines.append(f"- {pivot.description}: {listed}{more}")
        lines.append("")

    if dossier.evidence:
        lines.extend(["**Evidence**", ""])
        lines.extend(
            _table(
                ["Retrieved (UTC)", "Source", "Endpoint", "SHA-256 of the response"],
                [
                    [
                        record.requested_at.isoformat(),
                        record.source,
                        record.endpoint,
                        record.content_sha256,
                    ]
                    for record in dossier.evidence[:20]
                ],
            )
        )
        lines.extend(
            [
                "",
                f"Export the full set with `ctwatch evidence export {dossier.finding_id}`.",
                "",
            ]
        )

    return lines


def render_report(
    dossiers: list[Dossier],
    *,
    title: str | None = None,
    scope: str | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render an analysis report for a set of findings."""

    moment = generated_at or utc_now()
    lines: list[str] = [
        f"# {title or 'Domain impersonation report'}",
        "",
        f"Generated {to_iso(moment)} by ctwatch {__version__}.",
        "",
    ]

    if scope:
        lines.extend([f"Scope: {scope}.", ""])

    lines.extend(["## Method", "", METHOD_NOTE, ""])

    if not dossiers:
        lines.extend(
            [
                "## Findings",
                "",
                "No domain met the reporting threshold. That is a statement about "
                "what the sources held when this ran, not a guarantee that none "
                "exists.",
                "",
            ]
        )
        return "\n".join(lines) + "\n"

    lines.extend(["## Summary", ""])
    lines.extend(
        _table(
            ["Score", "Confidence", "Domain", "As displayed", "Brand"],
            [
                [
                    f"{dossier.score:.2f}",
                    dossier.confidence or "",
                    f"`{dossier.domain.name}`",
                    dossier.domain.display_name if dossier.domain.is_idn else "",
                    dossier.target.brand,
                ]
                for dossier in dossiers
            ],
        )
    )
    lines.extend(["", "## Findings", ""])

    for dossier in dossiers:
        lines.extend(_finding_section(dossier))

    lines.extend(
        [
            "## Verifying this report",
            "",
            "Every claim above comes from a response that was archived when it was "
            "retrieved. The archive is plain gzip and the digests are plain SHA-256, "
            "so nothing in this project is needed to check them:",
            "",
            "```",
            "gunzip -c evidence/<year>/<month>/<xx>/<digest>.gz | sha256sum",
            "```",
            "",
            "The digest that comes out must equal the one in the evidence table. "
            "The endpoint and the retrieval time are recorded alongside it, so the "
            "same query can be repeated against the same service.",
            "",
        ]
    )

    return "\n".join(lines) + "\n"
