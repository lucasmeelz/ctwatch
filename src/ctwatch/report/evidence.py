"""Exporting a finding as a folder anyone can check without this tool.

The point of archiving every response was never the archive itself. It was to
be able to hand someone — an editor, a lawyer, a CERT, a colleague in two
years — a directory that stands on its own: the responses exactly as they
arrived, the digests that identify them, the endpoints and timestamps they came
from, and instructions that use nothing but ``sha256sum``.

Nothing in here requires ctwatch to read. That is the whole idea.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ctwatch import __version__
from ctwatch.report.dossier import Dossier
from ctwatch.report.markdown import render_report
from ctwatch.store.evidence import EvidenceError, EvidenceStore, sha256_hex
from ctwatch.timeutil import to_iso, utc_now

RESPONSES_DIRECTORY = "responses"
CHECKSUM_FILE = "MANIFEST.sha256"

README = """# Evidence for finding {finding_id}: {domain}

This folder documents one domain that resembles {brand} ({watched}). It was
produced by ctwatch {version} on {generated}.

## What is here

- `report.md` — the analysis, with the reasoning behind the score.
- `finding.json` — the same content as structured data.
- `manifest.json` — one entry per archived response: where it came from, when
  it was retrieved, and the SHA-256 of its contents.
- `{responses}/` — the responses themselves, exactly as the services returned
  them. Nothing has been reformatted.
- `{checksums}` — the digests in the format `sha256sum` expects.

## How to check it

Every file in `{responses}/` is named after the SHA-256 of its own contents.
From this folder:

```
sha256sum -c {checksums}
```

On macOS, `shasum -a 256 -c {checksums}`.

If every line reports `OK`, the responses are byte-for-byte what was retrieved
at the times recorded in `manifest.json`. To go further, repeat the query
yourself: each manifest entry records the exact endpoint it was fetched from.

## What this does not establish

The archive proves what the services said and when we asked. It does not prove
what the operator of {domain} intended, nor that the domain was used for
anything. Those are conclusions a person has to reach, and the report above is
written to be argued with.

## How this was collected

No request was ever made to {domain}. The information here comes from
Certificate Transparency logs, the domain registry, a public DNS resolver, and
urlscan.io. The operator of {domain} has no way of knowing this folder exists.
"""


@dataclass(slots=True)
class ExportResult:
    """What an export wrote."""

    directory: Path
    files: list[str] = field(default_factory=list)
    responses: int = 0
    missing: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "directory": str(self.directory),
            "files": list(self.files),
            "responses": self.responses,
            "missing": list(self.missing),
        }


def _extension(content: bytes) -> str:
    """A sensible file extension, so the responses open in an editor."""

    stripped = content.lstrip()[:1]
    if stripped in (b"{", b"["):
        return "json"
    if stripped == b"<":
        return "html"
    return "txt"


def export_finding(
    dossier: Dossier,
    *,
    store: EvidenceStore,
    destination: Path,
    generated_at: datetime | None = None,
) -> ExportResult:
    """Write a self-contained folder documenting one finding."""

    moment = generated_at or utc_now()
    destination.mkdir(parents=True, exist_ok=True)
    responses = destination / RESPONSES_DIRECTORY
    responses.mkdir(exist_ok=True)

    result = ExportResult(directory=destination)
    manifest: list[dict[str, Any]] = []
    checksums: list[str] = []
    by_digest: dict[str, dict[str, Any]] = {}

    for record in dossier.evidence:
        try:
            content = store.read(record)
        except (EvidenceError, OSError) as exc:
            result.missing.append(f"evidence {record.id}: {exc}")
            continue

        digest = sha256_hex(content)
        retrieval = {
            "evidence_id": record.id,
            "source": record.source,
            "endpoint": record.endpoint,
            "retrieved_at": to_iso(record.requested_at),
            "status_code": record.status_code,
        }

        existing = by_digest.get(digest)
        if existing is not None:
            # The same bytes retrieved twice is one file and two retrievals.
            # Writing it twice would pad the folder and suggest two findings
            # where there is one.
            retrievals = existing["retrievals"]
            if isinstance(retrievals, list):
                retrievals.append(retrieval)
            continue

        position = len(by_digest) + 1
        filename = f"{position:04d}-{record.source}-{digest[:12]}.{_extension(content)}"
        (responses / filename).write_bytes(content)
        result.responses += 1

        relative = f"{RESPONSES_DIRECTORY}/{filename}"
        checksums.append(f"{digest}  {relative}")
        entry: dict[str, Any] = {
            "file": relative,
            "content_sha256": digest,
            "content_length": len(content),
            "retrievals": [retrieval],
        }
        by_digest[digest] = entry
        manifest.append(entry)

    manifest_document = {
        "tool": "ctwatch",
        "version": __version__,
        "generated_at": to_iso(moment),
        "finding_id": dossier.finding_id,
        "domain": dossier.domain.name,
        "displayed_as": dossier.domain.display_name,
        "brand": dossier.target.brand,
        "watched_domain": dossier.target.canonical_domain,
        "responses": manifest,
        "notes": (
            "Each response is named after the SHA-256 of its own contents. "
            "No request was made to the domain described."
        ),
    }

    files = {
        "manifest.json": json.dumps(manifest_document, indent=2, sort_keys=True) + "\n",
        "finding.json": json.dumps(dossier.as_dict(), indent=2, sort_keys=True) + "\n",
        "report.md": render_report(
            [dossier],
            title=f"Finding {dossier.finding_id}: {dossier.domain.display_name}",
            scope=f"{dossier.target.brand} ({dossier.target.canonical_domain})",
            generated_at=moment,
        ),
        CHECKSUM_FILE: "\n".join(checksums) + ("\n" if checksums else ""),
        "README.md": README.format(
            finding_id=dossier.finding_id,
            domain=dossier.domain.name,
            brand=dossier.target.brand,
            watched=dossier.target.canonical_domain,
            version=__version__,
            generated=to_iso(moment),
            responses=RESPONSES_DIRECTORY,
            checksums=CHECKSUM_FILE,
        ),
    }

    for name, document in files.items():
        (destination / name).write_text(document, encoding="utf-8")

    result.files = sorted([*files, *(str(entry["file"]) for entry in manifest)])
    return result
