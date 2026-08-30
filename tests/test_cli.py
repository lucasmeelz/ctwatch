from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from ctwatch import cli
from ctwatch.timeutil import parse_duration

FIXTURES = Path(__file__).parent / "fixtures"
LISTING = (FIXTURES / "crtsh_lemonde.json").read_bytes()

runner = CliRunner()


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.chdir(tmp_path)
    yield tmp_path


def invoke(*args: str) -> Any:
    result = runner.invoke(cli.app, list(args))
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result


def payload(result: Any) -> Any:
    return json.loads(result.stdout)


@pytest.fixture
def offline_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route the scan command through a recorded crt.sh response."""

    original = cli.run_scan

    async def patched(**kwargs: Any) -> Any:
        kwargs["transport"] = httpx.MockTransport(
            lambda request: httpx.Response(200, content=LISTING)
        )
        # The shipped configuration throttles crt.sh to one request every two
        # seconds, which is right in production and pointless against a
        # recorded response.
        kwargs["config"].sources.crtsh.rate_limit_rps = 0
        return await original(**kwargs)

    monkeypatch.setattr(cli, "run_scan", patched)


def test_init_creates_config_database_and_evidence(workspace: Path) -> None:
    result = invoke("--json", "init")
    assert result.exit_code == 0

    data = payload(result)
    assert data["config_created"] is True
    assert data["targets"] > 0
    assert (workspace / "ctwatch.yaml").is_file()
    assert (workspace / "ctwatch.db").is_file()
    assert (workspace / "evidence").is_dir()


def test_init_reports_the_hosts_it_may_contact(workspace: Path) -> None:
    data = payload(invoke("--json", "init"))
    assert "crt.sh" in data["allowed_hosts"]
    assert not any(host.endswith("lemonde.fr") for host in data["allowed_hosts"])


def test_init_does_not_clobber_an_existing_config(workspace: Path) -> None:
    invoke("--json", "init")
    (workspace / "ctwatch.yaml").write_text("targets: []\n", encoding="utf-8")

    data = payload(invoke("--json", "init"))
    assert data["config_created"] is False
    assert (workspace / "ctwatch.yaml").read_text(encoding="utf-8") == "targets: []\n"

    forced = payload(invoke("--json", "init", "--force"))
    assert forced["config_created"] is True


def test_target_add_and_list(workspace: Path) -> None:
    invoke("--json", "init")
    added = payload(
        invoke(
            "--json",
            "target",
            "add",
            "--brand",
            "Mediapart",
            "--domain",
            "MEDIAPART.fr.",
            "--keyword",
            "actu",
            "--allow",
            "mediapart-abonnes.fr",
        )
    )
    assert added["canonical_domain"] == "mediapart.fr"
    assert added["keywords"] == ["actu"]

    listed = payload(invoke("--json", "target", "list"))
    assert any(entry["brand"] == "Mediapart" for entry in listed)


def test_target_add_rejects_a_non_domain(workspace: Path) -> None:
    invoke("--json", "init")
    result = invoke("--json", "target", "add", "--brand", "X", "--domain", "not a domain")
    assert result.exit_code == 1
    assert "not a usable domain name" in payload(result)["error"]


def test_commands_require_an_initialised_config(workspace: Path) -> None:
    result = invoke("--json", "target", "list")
    assert result.exit_code == 1
    assert "ctwatch init" in payload(result)["error"]


def test_scan_stores_findings_and_reports_counts(workspace: Path, offline_scan: None) -> None:
    invoke("--json", "init")
    data = payload(invoke("--json", "scan", "--target", "lemonde.fr"))
    assert len(data) == 1
    assert data[0]["canonical_domain"] == "lemonde.fr"
    assert data[0]["certificates"] == 3
    assert data[0]["new_domains"] == 4


def test_scan_rejects_an_unknown_target(workspace: Path, offline_scan: None) -> None:
    invoke("--json", "init")
    result = invoke("--json", "scan", "--target", "unknown-outlet.fr")
    assert result.exit_code == 1
    assert "not on the watchlist" in payload(result)["error"]


def test_scan_rejects_an_unparseable_since(workspace: Path, offline_scan: None) -> None:
    invoke("--json", "init")
    result = invoke("--json", "scan", "--since", "yesterday")
    assert result.exit_code == 1
    assert "duration" in payload(result)["error"]


def test_human_output_is_rendered_without_json(workspace: Path) -> None:
    invoke("--json", "init")
    result = invoke("target", "list")
    assert result.exit_code == 0
    assert "Le Monde" in result.stdout


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("30d", 2592000), ("12h", 43200), ("90m", 5400), ("2w", 1209600), ("45", 3888000)],
)
def test_duration_shorthand(text: str, seconds: int) -> None:
    assert parse_duration(text).total_seconds() == seconds


@pytest.mark.parametrize("text", ["", "yesterday", "-3d", "3y"])
def test_invalid_duration_is_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(text)


def test_permutations_command_lists_candidates(workspace: Path) -> None:
    invoke("--json", "init")
    data = payload(invoke("--json", "permutations", "lemonde.fr", "--limit", "40"))
    assert len(data) == 40
    assert all(entry["base"] == "lemonde.fr" for entry in data)
    assert all(entry["detail"] for entry in data)


def test_permutations_uses_the_watchlist_keywords(workspace: Path) -> None:
    invoke("--json", "init")
    data = payload(invoke("--json", "permutations", "lemonde.fr"))
    produced = {entry["name"] for entry in data}
    assert "lemonde-actu.info" in produced


def test_permutations_can_drop_homoglyphs(workspace: Path) -> None:
    invoke("--json", "init")
    data = payload(invoke("--json", "permutations", "lemonde.fr", "--no-homoglyphs"))
    assert not any(entry["kind"] == "homoglyph" for entry in data)


def test_permutations_can_select_a_technique(workspace: Path) -> None:
    invoke("--json", "init")
    data = payload(invoke("--json", "permutations", "lemonde.fr", "--kind", "omission"))
    assert {entry["kind"] for entry in data} == {"omission"}


def test_permutations_rejects_an_unknown_technique(workspace: Path) -> None:
    invoke("--json", "init")
    result = invoke("--json", "permutations", "lemonde.fr", "--kind", "telepathy")
    assert result.exit_code == 1
    assert "unknown technique" in payload(result)["error"]


def test_permutations_reports_the_readable_form_of_an_idn(workspace: Path) -> None:
    invoke("--json", "init")
    data = payload(invoke("--json", "permutations", "lemonde.fr"))
    idn = [entry for entry in data if entry["name"] == "xn--lemnde-yqf.fr"]
    assert idn and idn[0]["idn"] is True
    assert idn[0]["display_name"] == "lemоnde.fr"


def test_scan_can_look_up_generated_variants(workspace: Path, offline_scan: None) -> None:
    invoke("--json", "init")
    data = payload(invoke("--json", "scan", "--target", "lemonde.fr", "--variants", "5"))
    assert data[0]["variants_queried"] == 5
    assert data[0]["queries"] == 6
