"""Expectations for reports and the evidence bundle.

The bundle is the part that matters most. Everything archived since the first
scan exists so that a folder can be handed to an editor, a lawyer or a CERT and
checked by them, months later, with tools they already have. If that folder
needs ctwatch to be read, the archiving was pointless.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctwatch.config import Config
from ctwatch.findings import assess_target
from ctwatch.report.csv import columns, render_csv
from ctwatch.report.dossier import build_dossier, dossiers_for_target
from ctwatch.report.evidence import export_finding
from ctwatch.report.markdown import render_report
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository

NOW = datetime(2026, 3, 10, 12, 0, tzinfo=UTC)
SUSPECT = "lemonde-actu.info"
RESPONSE = b'[{"dns_names": ["lemonde-actu.info"], "cert_sha256": "abc"}]'


@pytest.fixture
def config() -> Config:
    return Config.model_validate(
        {"targets": [{"brand": "Le Monde", "canonical_domains": ["lemonde.fr"]}]}
    )


@pytest.fixture
def store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


@pytest.fixture
def target(repository: Repository) -> WatchTarget:
    return repository.upsert_target(
        brand="Le Monde", canonical_domain="lemonde.fr", keywords=["actu", "info"]
    )


@pytest.fixture
def finding_id(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> int:
    evidence = store.capture(
        source="certspotter",
        endpoint="https://api.certspotter.com/v1/issuances?domain=lemonde.fr",
        content=RESPONSE,
        requested_at=NOW - timedelta(hours=1),
        status_code=200,
    )
    certificate = repository.upsert_certificate(
        source="certspotter",
        source_ref="1",
        fingerprint_sha256="c" * 64,
        issuer="C=US, O=Let's Encrypt, CN=R11",
        not_before=NOW - timedelta(days=2),
        not_after=NOW + timedelta(days=88),
    )
    domain = repository.upsert_domain(name=SUSPECT, tld="info")
    repository.record_observation(
        domain_id=domain.id,
        evidence_id=evidence.id,
        source="certspotter",
        certificate_id=certificate.id,
        target_id=target.id,
    )
    repository.upsert_registration(
        domain_id=domain.id,
        evidence_id=evidence.id,
        rdap_server="https://rdap.identitydigital.services",
        registrar="Budget Registrar Ltd",
        registered_at=NOW - timedelta(days=3),
        expires_at=NOW + timedelta(days=362),
        last_changed_at=None,
        statuses=["client transfer prohibited"],
        nameservers=["ns1.cheap-hosting.example"],
    )
    repository.record_dns_record(
        domain_id=domain.id, evidence_id=evidence.id, record_type="A", value="203.0.113.42"
    )
    repository.upsert_url_scan(
        domain_id=domain.id,
        evidence_id=evidence.id,
        scan_uuid="0193-aaaa",
        result_url="https://urlscan.io/result/0193-aaaa/",
        page_ip="203.0.113.42",
        page_asn="AS64500",
        page_asn_name="EXAMPLE-HOSTING",
        page_title="Le Monde - Actualites",
    )

    _, assessments = assess_target(repository=repository, config=config, target=target, now=NOW)
    identifier = assessments[0].finding_id
    assert identifier is not None
    return identifier


# ----------------------------------------------------------------------------
# The dossier


def test_a_dossier_gathers_everything_stored(repository: Repository, finding_id: int) -> None:
    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    assert dossier.domain.name == SUSPECT
    assert dossier.certificates
    assert dossier.evidence
    assert dossier.registration.registrar == "Budget Registrar Ltd"
    assert dossier.dns == [("A", "203.0.113.42")]
    assert dossier.scans[0].asn == "AS64500"
    assert dossier.contributions


def test_an_unknown_finding_has_no_dossier(repository: Repository) -> None:
    assert build_dossier(repository, finding_id=9999) is None


# ----------------------------------------------------------------------------
# The written report


def test_the_report_states_how_it_was_produced(repository: Repository, finding_id: int) -> None:
    document = render_report(dossiers_for_target(repository, min_score=0.0))
    assert "No request was made to any of the domains it describes" in document
    assert "urlscan.io rather than by the analyst" in document
    assert "Certificate Transparency logs" in document


def test_the_report_shows_the_score_breakdown(repository: Repository, finding_id: int) -> None:
    document = render_report(dossiers_for_target(repository, min_score=0.0))
    assert "How the score was reached" in document
    assert "keyword_combo" in document
    assert "tld_risk" in document
    # Every criterion carries its sentence, not just its number.
    assert "high-risk suffix list" in document


def test_the_report_carries_the_evidence_digests(
    repository: Repository, finding_id: int, store: EvidenceStore
) -> None:
    document = render_report(dossiers_for_target(repository, min_score=0.0))
    digest = hashlib.sha256(RESPONSE).hexdigest()
    assert digest in document
    assert "api.certspotter.com" in document
    assert "sha256sum" in document


def test_the_report_explains_an_internationalised_name(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    evidence = store.capture(source="certspotter", endpoint="https://x/", content=b"[]")
    domain = repository.upsert_domain(
        name="xn--lemnde-yqf.fr", unicode_name="lemоnde.fr", is_idn=True
    )
    repository.record_observation(
        domain_id=domain.id, evidence_id=evidence.id, source="certspotter", target_id=target.id
    )
    assess_target(repository=repository, config=config, target=target, now=NOW)

    document = render_report(dossiers_for_target(repository, min_score=0.0))
    assert "lemоnde.fr" in document
    assert "xn--lemnde-yqf.fr" in document
    assert "would not have found it" in document


def test_an_empty_report_says_what_it_means(repository: Repository) -> None:
    document = render_report([])
    assert "No domain met the reporting threshold" in document
    assert "not a guarantee" in document


def test_the_report_has_no_unfilled_placeholders(repository: Repository, finding_id: int) -> None:
    document = render_report(dossiers_for_target(repository, min_score=0.0))
    assert "{" not in document.replace("{}", "")
    assert "None" not in document


# ----------------------------------------------------------------------------
# CSV


def test_csv_has_one_row_per_finding(repository: Repository, finding_id: int) -> None:
    document = render_csv(dossiers_for_target(repository, min_score=0.0))
    lines = document.strip().splitlines()
    assert len(lines) == 2
    assert lines[0].split(",")[0] == "finding_id"
    assert SUSPECT in lines[1]


def test_csv_breaks_the_score_into_sortable_columns(
    repository: Repository, finding_id: int
) -> None:
    header = render_csv(dossiers_for_target(repository, min_score=0.0)).splitlines()[0]
    assert "score_tld_risk" in header
    assert "score_homoglyph" in header
    assert set(columns()) == set(header.split(","))


def test_csv_of_nothing_is_still_valid(repository: Repository) -> None:
    document = render_csv([])
    assert document.strip().splitlines() == [",".join(columns())]


# ----------------------------------------------------------------------------
# The evidence bundle


def test_the_bundle_is_self_contained(
    repository: Repository, finding_id: int, store: EvidenceStore, tmp_path: Path
) -> None:
    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    destination = tmp_path / "bundle"
    result = export_finding(dossier, store=store, destination=destination, generated_at=NOW)

    assert result.responses == 1
    assert result.missing == []
    for name in ("README.md", "report.md", "finding.json", "manifest.json", "MANIFEST.sha256"):
        assert (destination / name).is_file()
    assert list((destination / "responses").iterdir())


def test_the_archived_response_is_byte_for_byte_what_arrived(
    repository: Repository, finding_id: int, store: EvidenceStore, tmp_path: Path
) -> None:
    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    destination = tmp_path / "bundle"
    export_finding(dossier, store=store, destination=destination, generated_at=NOW)

    written = next((destination / "responses").iterdir())
    assert written.read_bytes() == RESPONSE
    assert written.suffix == ".json"


def test_the_checksums_verify_with_sha256sum(
    repository: Repository, finding_id: int, store: EvidenceStore, tmp_path: Path
) -> None:
    """The claim the whole archive rests on, checked with the real tool."""

    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    destination = tmp_path / "bundle"
    export_finding(dossier, store=store, destination=destination, generated_at=NOW)

    for command in (
        ["sha256sum", "-c", "MANIFEST.sha256"],
        ["shasum", "-a", "256", "-c", "MANIFEST.sha256"],
    ):
        try:
            completed = subprocess.run(
                command, cwd=destination, capture_output=True, text=True, check=False
            )
        except FileNotFoundError:
            continue
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert "OK" in completed.stdout
        return
    pytest.skip("neither sha256sum nor shasum is available")


def test_the_manifest_records_where_each_response_came_from(
    repository: Repository, finding_id: int, store: EvidenceStore, tmp_path: Path
) -> None:
    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    destination = tmp_path / "bundle"
    export_finding(dossier, store=store, destination=destination, generated_at=NOW)

    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["responses"][0]
    assert entry["content_sha256"] == hashlib.sha256(RESPONSE).hexdigest()

    retrieval = entry["retrievals"][0]
    assert retrieval["endpoint"].startswith("https://api.certspotter.com/")
    assert retrieval["retrieved_at"].endswith("+00:00")
    assert retrieval["status_code"] == 200


def test_the_same_bytes_retrieved_twice_are_one_file_and_two_retrievals(
    repository: Repository,
    finding_id: int,
    store: EvidenceStore,
    target: WatchTarget,
    tmp_path: Path,
) -> None:
    """Two copies of one response would suggest two findings where there is one."""

    again = store.capture(
        source="certspotter",
        endpoint="https://api.certspotter.com/v1/issuances?domain=lemonde.fr",
        content=RESPONSE,
        requested_at=NOW,
        status_code=200,
    )
    domain = repository.get_domain(SUSPECT)
    assert domain is not None
    repository.record_observation(
        domain_id=domain.id, evidence_id=again.id, source="certspotter", target_id=target.id
    )

    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    assert len(dossier.evidence) == 2

    destination = tmp_path / "bundle"
    result = export_finding(dossier, store=store, destination=destination, generated_at=NOW)

    assert result.responses == 1
    assert len(list((destination / "responses").iterdir())) == 1
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["responses"]) == 1
    assert len(manifest["responses"][0]["retrievals"]) == 2


def test_the_bundle_carries_the_enrichment_responses(
    repository: Repository, finding_id: int, store: EvidenceStore, tmp_path: Path
) -> None:
    """A report citing a registrar must hand over the response it read it from."""

    rdap = store.capture(
        source="rdap",
        endpoint="https://rdap.identitydigital.services/domain/lemonde-actu.info",
        content=b'{"objectClassName": "domain"}',
        requested_at=NOW,
        status_code=200,
    )
    domain = repository.get_domain(SUSPECT)
    assert domain is not None
    repository.upsert_registration(
        domain_id=domain.id,
        evidence_id=rdap.id,
        rdap_server="https://rdap.identitydigital.services",
        registrar="Budget Registrar Ltd",
        registered_at=None,
        expires_at=None,
        last_changed_at=None,
    )

    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    assert any(record.source == "rdap" for record in dossier.evidence)

    destination = tmp_path / "bundle"
    export_finding(dossier, store=store, destination=destination, generated_at=NOW)
    written = [path.name for path in (destination / "responses").iterdir()]
    assert any("rdap" in name for name in written)


def test_the_readme_says_what_the_archive_does_not_prove(
    repository: Repository, finding_id: int, store: EvidenceStore, tmp_path: Path
) -> None:
    """Overclaiming in an evidence folder is worse than not producing one."""

    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    destination = tmp_path / "bundle"
    export_finding(dossier, store=store, destination=destination, generated_at=NOW)

    readme = (destination / "README.md").read_text(encoding="utf-8")
    assert "does not establish" in readme
    assert "sha256sum -c" in readme
    assert "No request was ever made" in readme
    assert "{" not in readme


def test_a_missing_archive_is_reported_not_hidden(
    repository: Repository, finding_id: int, store: EvidenceStore, tmp_path: Path
) -> None:
    dossier = build_dossier(repository, finding_id=finding_id)
    assert dossier is not None
    store.absolute_path(dossier.evidence[0]).unlink()

    destination = tmp_path / "bundle"
    result = export_finding(dossier, store=store, destination=destination, generated_at=NOW)
    assert result.responses == 0
    assert result.missing
    assert "missing" in result.missing[0]


# ----------------------------------------------------------------------------
# The dashboard


def test_the_dashboard_is_one_self_contained_file(repository: Repository, finding_id: int) -> None:
    """It has to open from a filesystem, with no server and no network."""

    from ctwatch.report.html import render_dashboard

    document = render_dashboard(dossiers_for_target(repository, min_score=0.0))
    assert document.startswith("<!DOCTYPE html>")
    assert "<style>" in document and "<script" in document
    # Nothing fetched from anywhere.
    assert "src=" not in document
    assert 'rel="stylesheet"' not in document
    assert "http://" not in document


def test_the_dashboard_carries_its_data_inline(repository: Repository, finding_id: int) -> None:
    from ctwatch.report.html import render_dashboard

    document = render_dashboard(dossiers_for_target(repository, min_score=0.0))
    start = document.index('<script id="findings" type="application/json">') + len(
        '<script id="findings" type="application/json">'
    )
    payload = document[start : document.index("</script>", start)]
    entries = json.loads(payload.replace("<\\/", "</"))

    assert len(entries) == 1
    assert entries[0]["domain"] == SUSPECT
    assert entries[0]["contributions"]
    assert entries[0]["evidence"]


def test_the_dashboard_cannot_be_broken_by_a_domain_name(
    repository: Repository, store: EvidenceStore, target: WatchTarget, config: Config
) -> None:
    """Names come from certificates, which are not a trusted input."""

    from ctwatch.report.html import render_dashboard

    evidence = store.capture(source="certspotter", endpoint="https://x/", content=b"[]")
    hostile = "lemonde-script.info"
    domain = repository.upsert_domain(name=hostile, unicode_name="</script><b>x</b>", is_idn=True)
    repository.record_observation(
        domain_id=domain.id, evidence_id=evidence.id, source="certspotter", target_id=target.id
    )
    assess_target(repository=repository, config=config, target=target, now=NOW)

    document = render_dashboard(dossiers_for_target(repository, min_score=0.0))
    assert "</script><b>x</b>" not in document
    assert document.count("</script>") == 2


def test_the_dashboard_says_nothing_was_contacted(repository: Repository, finding_id: int) -> None:
    from ctwatch.report.html import render_dashboard

    document = render_dashboard(dossiers_for_target(repository, min_score=0.0))
    assert "No request was\n  made to any domain listed here" in document


def test_an_empty_dashboard_still_renders(repository: Repository) -> None:
    from ctwatch.report.html import render_dashboard

    document = render_dashboard([])
    assert "<!DOCTYPE html>" in document
    assert 'id="findings"' in document
