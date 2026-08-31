"""A dashboard that is a single file.

An analyst needs to sort, filter and read findings side by side; a table in a
terminal stops being enough somewhere around the fortieth row. What they do not
need is a server to keep running, a port to remember, or a dependency to
install on the machine where the evidence lives.

So the dashboard is one HTML file with its data inside it. It opens from the
filesystem, works with no network at all, and can be attached to an email or
dropped into a shared folder. Everything below is inlined for the same reason
the evidence bundle carries its own checksums: an artefact that needs
infrastructure to be read is an artefact that will not be read.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from ctwatch import __version__
from ctwatch.report.dossier import Dossier
from ctwatch.store.models import WatchTarget
from ctwatch.timeutil import to_iso, utc_now

STYLE = """
:root {
  --ink: #16181d;
  --muted: #6b7280;
  --line: #d8dbe0;
  --page: #fbfbfa;
  --panel: #ffffff;
  --accent: #1f4f82;
  --high: #9b2226;
  --medium: #a8630b;
  --low: #4b5563;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--page);
  color: var(--ink);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
header { padding: 28px 32px 18px; border-bottom: 1px solid var(--line); background: var(--panel); }
h1 { margin: 0 0 6px; font-size: 21px; font-weight: 600; letter-spacing: -0.01em; }
.meta, .note { color: var(--muted); font-size: 13px; }
.note { max-width: 62ch; margin-top: 10px; }
main { padding: 22px 32px 60px; }
.controls { display: flex; gap: 14px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 18px; }
.control { display: flex; flex-direction: column; gap: 4px; }
label { font-size: 12px; color: var(--muted); }
input, select {
  font: inherit; padding: 6px 8px; border: 1px solid var(--line);
  border-radius: 3px; background: var(--panel); color: var(--ink); min-width: 190px;
}
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 12px; font-weight: 600; color: var(--muted); cursor: pointer; user-select: none; white-space: nowrap; }
th[data-sort]::after { content: ""; }
th.asc::after { content: " \\2191"; }
th.desc::after { content: " \\2193"; }
tbody tr { cursor: pointer; }
tbody tr:hover { background: #f4f6f8; }
tbody tr.open { background: #eef2f6; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.score { font-variant-numeric: tabular-nums; font-weight: 600; }
.score.high { color: var(--high); }
.score.medium { color: var(--medium); }
.score.low { color: var(--low); }
.tag { display: inline-block; padding: 1px 6px; border: 1px solid var(--line); border-radius: 3px; font-size: 11px; color: var(--muted); }
.detail td { background: #f7f8fa; }
.detail h3 { margin: 14px 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
.detail h3:first-child { margin-top: 2px; }
.detail table { border: none; background: transparent; }
.detail th, .detail td { border-bottom: 1px solid var(--line); padding: 5px 10px 5px 0; }
.detail ul { margin: 0; padding-left: 18px; }
.detail li { margin: 2px 0; }
.empty { padding: 40px; text-align: center; color: var(--muted); background: var(--panel); border: 1px solid var(--line); }
a { color: var(--accent); }
footer { padding: 0 32px 40px; color: var(--muted); font-size: 12px; max-width: 78ch; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: #eef0f3; padding: 1px 4px; border-radius: 3px; }
"""

SCRIPT = """
const DATA = JSON.parse(document.getElementById("findings").textContent);
const body = document.getElementById("rows");
const search = document.getElementById("search");
const brand = document.getElementById("brand");
const status = document.getElementById("status");
const minScore = document.getElementById("minScore");
const count = document.getElementById("count");
let sortKey = "score";
let sortDescending = true;

function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, function (character) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character];
  });
}

function scoreClass(score) {
  if (score >= 0.6) return "high";
  if (score >= 0.3) return "medium";
  return "low";
}

function matches(item) {
  const needle = search.value.trim().toLowerCase();
  if (needle) {
    const haystack = [item.domain, item.display_name, item.brand, item.why].join(" ").toLowerCase();
    if (!haystack.includes(needle)) return false;
  }
  if (brand.value && item.brand !== brand.value) return false;
  if (status.value && item.status !== status.value) return false;
  return item.score >= parseFloat(minScore.value || "0");
}

function detailHtml(item) {
  const parts = [];
  if (item.contributions.length) {
    parts.push("<h3>How the score was reached</h3><table><tbody>");
    item.contributions.forEach(function (c) {
      parts.push(
        "<tr><th>" + escapeHtml(c.criterion) + "</th><td class='mono'>" +
        c.weighted.toFixed(3) + "</td><td>" + escapeHtml(c.explanation) + "</td></tr>"
      );
    });
    parts.push("</tbody></table>");
  }
  if (item.confidence_label) {
    parts.push("<h3>Confidence</h3><p>" + escapeHtml(item.confidence) + " — " + escapeHtml(item.confidence_label) + "</p>");
  }
  if (item.suppression_reason) {
    parts.push("<h3>Suppressed</h3><p>" + escapeHtml(item.suppression_reason) + "</p>");
  }
  if (item.registration.length) {
    parts.push("<h3>Registration</h3><ul>");
    item.registration.forEach(function (line) { parts.push("<li>" + escapeHtml(line) + "</li>"); });
    parts.push("</ul>");
  }
  if (item.dns.length) {
    parts.push("<h3>Resolution</h3><ul>");
    item.dns.forEach(function (line) { parts.push("<li class='mono'>" + escapeHtml(line) + "</li>"); });
    parts.push("</ul>");
  }
  if (item.certificates.length) {
    parts.push("<h3>Certificates</h3><ul>");
    item.certificates.forEach(function (line) { parts.push("<li>" + escapeHtml(line) + "</li>"); });
    parts.push("</ul>");
  }
  if (item.scans.length) {
    parts.push("<h3>Rendered by urlscan.io</h3><ul>");
    item.scans.forEach(function (scan) {
      const label = escapeHtml(scan.label);
      parts.push(scan.url ? "<li><a href='" + escapeHtml(scan.url) + "' rel='noreferrer noopener'>" + label + "</a></li>" : "<li>" + label + "</li>");
    });
    parts.push("</ul>");
  }
  if (item.pivots.length) {
    parts.push("<h3>Shared with other domains</h3><ul>");
    item.pivots.forEach(function (line) { parts.push("<li>" + escapeHtml(line) + "</li>"); });
    parts.push("</ul>");
  }
  if (item.evidence.length) {
    parts.push("<h3>Evidence</h3><ul>");
    item.evidence.forEach(function (line) { parts.push("<li class='mono'>" + escapeHtml(line) + "</li>"); });
    parts.push("</ul><p>Export it with <code>ctwatch evidence export " + item.id + "</code>.</p>");
  }
  return parts.join("");
}

function render() {
  const visible = DATA.filter(matches).sort(function (a, b) {
    const left = a[sortKey], right = b[sortKey];
    const order = typeof left === "number" ? left - right : String(left).localeCompare(String(right));
    return sortDescending ? -order : order;
  });

  count.textContent = visible.length + " of " + DATA.length + " finding(s)";
  if (!visible.length) {
    body.innerHTML = "<tr><td colspan='6' class='empty'>Nothing matches these filters.</td></tr>";
    return;
  }

  body.innerHTML = visible.map(function (item) {
    const shown = item.idn
      ? "<span class='mono'>" + escapeHtml(item.display_name) + "</span><br><span class='mono' style='color:var(--muted)'>" + escapeHtml(item.domain) + "</span>"
      : "<span class='mono'>" + escapeHtml(item.domain) + "</span>";
    return "<tr data-id='" + item.id + "'>" +
      "<td class='score " + scoreClass(item.score) + "'>" + item.score.toFixed(2) + "</td>" +
      "<td><span class='tag'>" + escapeHtml(item.confidence || "-") + "</span></td>" +
      "<td>" + shown + "</td>" +
      "<td>" + escapeHtml(item.brand) + "</td>" +
      "<td>" + escapeHtml(item.why) + "</td>" +
      "<td><span class='tag'>" + escapeHtml(item.status) + "</span></td>" +
      "</tr><tr class='detail' data-detail='" + item.id + "' hidden><td colspan='6'>" + detailHtml(item) + "</td></tr>";
  }).join("");
}

body.addEventListener("click", function (event) {
  const row = event.target.closest("tr[data-id]");
  if (!row) return;
  const detail = body.querySelector("tr[data-detail='" + row.dataset.id + "']");
  if (!detail) return;
  detail.hidden = !detail.hidden;
  row.classList.toggle("open", !detail.hidden);
});

document.querySelectorAll("th[data-sort]").forEach(function (header) {
  header.addEventListener("click", function () {
    const key = header.dataset.sort;
    sortDescending = sortKey === key ? !sortDescending : true;
    sortKey = key;
    document.querySelectorAll("th[data-sort]").forEach(function (other) {
      other.classList.remove("asc", "desc");
    });
    header.classList.add(sortDescending ? "desc" : "asc");
    render();
  });
});

[search, brand, status, minScore].forEach(function (control) {
  control.addEventListener("input", render);
  control.addEventListener("change", render);
});

render();
"""


def _certificate_lines(dossier: Dossier) -> list[str]:
    lines: list[str] = []
    for certificate in dossier.certificates[:10]:
        issued = "" if certificate.not_before is None else certificate.not_before.date().isoformat()
        issuer = certificate.issuer or "unknown issuer"
        fingerprint = (certificate.fingerprint_sha256 or "")[:16]
        suffix = f" · {fingerprint}" if fingerprint else ""
        lines.append(f"{issued or 'date unknown'} — {issuer}{suffix}")
    return lines


def _registration_lines(dossier: Dossier) -> list[str]:
    registration = dossier.registration
    lines: list[str] = []
    if registration.registered_at:
        lines.append(f"Registered {registration.registered_at}")
    if registration.registrar:
        lines.append(f"Registrar {registration.registrar}")
    if registration.expires_at:
        lines.append(f"Expires {registration.expires_at}")
    if registration.statuses:
        lines.append("Registry status: " + ", ".join(registration.statuses))
    if registration.nameservers:
        lines.append("Nameservers: " + ", ".join(registration.nameservers))
    return lines


def _entry(dossier: Dossier) -> dict[str, Any]:
    confidence = dossier.confidence_detail()
    strongest = max(
        dossier.contributions,
        key=lambda item: float(item.get("weighted", 0.0)),
        default={},
    )
    return {
        "id": dossier.finding_id,
        "domain": dossier.domain.name,
        "display_name": dossier.domain.display_name,
        "idn": dossier.domain.is_idn,
        "brand": dossier.target.brand,
        "target": dossier.target.canonical_domain,
        "score": round(dossier.score, 4),
        "confidence": dossier.confidence or "",
        "confidence_label": confidence.get("label", ""),
        "status": dossier.status,
        "why": strongest.get("explanation", dossier.summary),
        "suppression_reason": dossier.suppression_reason or "",
        "contributions": [
            {
                "criterion": str(item.get("criterion", "")),
                "weighted": float(item.get("weighted", 0.0)),
                "explanation": str(item.get("explanation", "")),
            }
            for item in dossier.contributions
        ],
        "registration": _registration_lines(dossier),
        "dns": [f"{kind} {value}" for kind, value in dossier.dns[:20]],
        "certificates": _certificate_lines(dossier),
        "scans": [
            {
                "url": scan.result_url,
                "label": ", ".join(
                    part for part in (scan.scanned_at, scan.ip, scan.asn_name, scan.title) if part
                )
                or "scan",
            }
            for scan in dossier.scans[:5]
        ],
        "pivots": [
            pivot.description + ": " + ", ".join(pivot.domains[:8]) for pivot in dossier.pivots[:10]
        ],
        "evidence": [
            f"{record.requested_at.isoformat()} · {record.source} · {record.content_sha256[:16]}"
            for record in dossier.evidence[:20]
        ],
    }


def _options(values: Iterable[str]) -> str:
    return "".join(
        f'<option value="{html.escape(value)}">{html.escape(value)}</option>'
        for value in sorted(set(values))
    )


def render_dashboard(
    dossiers: list[Dossier],
    *,
    targets: list[WatchTarget] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render the whole dashboard into one self-contained HTML document."""

    moment = generated_at or utc_now()
    entries = [_entry(dossier) for dossier in dossiers]

    # `</script>` inside the payload would end the tag early; escaping the
    # slash keeps the JSON valid and the document intact.
    payload = json.dumps(entries, ensure_ascii=False).replace("</", "<\\/")

    watched = targets or []
    scope = f"{len(watched)} brand(s) watched" if watched else "no brand on the watchlist"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ctwatch — findings</title>
<style>{STYLE}</style>
</head>
<body>
<header>
  <h1>Domains resembling watched brands</h1>
  <div class="meta">Generated {html.escape(to_iso(moment))} by ctwatch {html.escape(__version__)} · {html.escape(scope)} · <span id="count"></span></div>
  <p class="note">Built from Certificate Transparency logs and passive enrichment. No request was
  made to any domain listed here. Select a row to see how its score was reached and which archived
  responses back it.</p>
</header>
<main>
  <div class="controls">
    <div class="control"><label for="search">Search</label><input id="search" type="search" placeholder="domain, brand, reason"></div>
    <div class="control"><label for="brand">Brand</label><select id="brand"><option value="">all</option>{_options(entry["brand"] for entry in entries)}</select></div>
    <div class="control"><label for="status">Status</label><select id="status"><option value="">all</option>{_options(entry["status"] for entry in entries)}</select></div>
    <div class="control"><label for="minScore">Minimum score</label><input id="minScore" type="number" step="0.05" min="0" max="1" value="0"></div>
  </div>
  <table>
    <thead>
      <tr>
        <th data-sort="score" class="desc">Score</th>
        <th data-sort="confidence">Conf.</th>
        <th data-sort="domain">Domain</th>
        <th data-sort="brand">Brand</th>
        <th data-sort="why">Why</th>
        <th data-sort="status">Status</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
</main>
<footer>
  <p>Every figure above can be traced to a response that was archived when it was retrieved.
  Run <code>ctwatch evidence export &lt;id&gt;</code> for a folder containing those responses and the
  checksums to verify them, or <code>ctwatch report</code> for the written version.</p>
</footer>
<script id="findings" type="application/json">{payload}</script>
<script>{SCRIPT}</script>
</body>
</html>
"""
