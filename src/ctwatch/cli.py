"""Command line interface.

Every command accepts ``--json`` so that ctwatch can sit inside someone else's
pipeline. The human-readable output is a convenience; the JSON is the contract.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from ctwatch import __version__
from ctwatch.config import DEFAULT_CONFIG_FILENAME, Config, ConfigError, load_config
from ctwatch.enrichment import enrich_domains
from ctwatch.findings import assess_targets
from ctwatch.monitor import run_monitor
from ctwatch.names import InvalidDomainNameError, normalize
from ctwatch.net.client import NetworkPolicyError
from ctwatch.net.policy import allowed_hosts
from ctwatch.permutations.generator import PermutationGenerator
from ctwatch.permutations.model import Permutation, PermutationKind
from ctwatch.scan import run_scan
from ctwatch.sources.base import SourceError
from ctwatch.store.database import open_database
from ctwatch.store.evidence import EvidenceStore
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository
from ctwatch.timeutil import parse_duration, utc_now

DEFAULT_TEMPLATE = Path(__file__).resolve().parent / "data" / "default_config.yaml"

console = Console()
error_console = Console(stderr=True)


@dataclass(slots=True)
class AppState:
    config_path: Path
    json_output: bool


app = typer.Typer(
    name="ctwatch",
    help=(
        "Detect and document domains impersonating news outlets and public "
        "institutions, using Certificate Transparency logs. ctwatch observes "
        "certificates; it never contacts the domains it reports on."
    ),
    no_args_is_help=True,
    add_completion=False,
)
target_app = typer.Typer(help="Manage the watchlist.", no_args_is_help=True)
app.add_typer(target_app, name="target")


def _state(ctx: typer.Context) -> AppState:
    state = ctx.obj
    if not isinstance(state, AppState):  # pragma: no cover - typer always sets it
        msg = "command was invoked without application state"
        raise RuntimeError(msg)
    return state


def _emit(state: AppState, payload: Any, render: Any = None) -> None:
    if state.json_output:
        console.print_json(json.dumps(payload, default=str))
    elif render is not None:
        render()


def _fail(message: str, *, state: AppState, code: int = 1) -> None:
    if state.json_output:
        console.print_json(json.dumps({"error": message}))
    else:
        error_console.print(f"[bold red]error[/bold red] {message}")
    raise typer.Exit(code)


def _load(state: AppState) -> Config:
    try:
        return load_config(state.config_path)
    except ConfigError as exc:
        _fail(str(exc), state=state)
        raise  # pragma: no cover - _fail always raises


def _target_payload(target: WatchTarget) -> dict[str, Any]:
    return {
        "brand": target.brand,
        "canonical_domain": target.canonical_domain,
        "keywords": list(target.keywords),
        "allowlist": list(target.allowlist),
        "active": target.active,
    }


def sync_targets_from_config(repository: Repository, config: Config) -> int:
    """Mirror the configured watchlist into the database.

    The YAML file stays the declarative source of truth; targets added with
    ``ctwatch target add`` live alongside it and are never removed by a sync.
    """

    for target in config.targets:
        for domain in target.canonical_domains:
            repository.upsert_target(
                brand=target.brand,
                canonical_domain=domain,
                keywords=target.keywords,
                allowlist=target.allowlist,
            )
    return len(config.targets)


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path,
        typer.Option("--config", "-c", help="Path to the configuration file."),
    ] = Path(DEFAULT_CONFIG_FILENAME),
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON instead of a table."),
    ] = False,
) -> None:
    ctx.obj = AppState(config_path=config, json_output=json_output)


@app.command()
def version(ctx: typer.Context) -> None:
    """Print the ctwatch version."""

    state = _state(ctx)
    _emit(state, {"version": __version__}, lambda: console.print(__version__))


@app.command()
def init(
    ctx: typer.Context,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing configuration file.")
    ] = False,
) -> None:
    """Create the configuration file, the database and the evidence directory."""

    state = _state(ctx)
    created_config = False

    if state.config_path.exists() and not force:
        if not state.json_output:
            console.print(f"[yellow]keeping[/yellow] existing configuration at {state.config_path}")
    else:
        state.config_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(DEFAULT_TEMPLATE, state.config_path)
        created_config = True

    config = _load(state)
    config.storage.evidence_dir.mkdir(parents=True, exist_ok=True)

    with open_database(config.storage.database) as connection:
        repository = Repository(connection)
        targets = sync_targets_from_config(repository, config)

    payload = {
        "config": str(state.config_path),
        "config_created": created_config,
        "database": str(config.storage.database),
        "evidence_dir": str(config.storage.evidence_dir),
        "targets": targets,
        "allowed_hosts": allowed_hosts(config),
    }

    def render() -> None:
        console.print(f"configuration  {state.config_path}")
        console.print(f"database       {config.storage.database}")
        console.print(f"evidence       {config.storage.evidence_dir}")
        console.print(f"watchlist      {targets} target(s) from the configuration")
        console.print(f"outbound hosts {', '.join(allowed_hosts(config))}")
        console.print(
            "\n[dim]ctwatch only ever contacts the hosts listed above. "
            "Watched domains are never queried directly.[/dim]"
        )

    _emit(state, payload, render)


@target_app.command("add")
def target_add(
    ctx: typer.Context,
    brand: Annotated[str, typer.Option("--brand", help="Name of the organisation.")],
    domain: Annotated[
        str, typer.Option("--domain", help="A domain that legitimately belongs to the brand.")
    ],
    keyword: Annotated[
        list[str] | None,
        typer.Option("--keyword", help="Word an impersonator is likely to append. Repeatable."),
    ] = None,
    allow: Annotated[
        list[str] | None,
        typer.Option(
            "--allow",
            help="Known-legitimate lookalike, such as a defensive registration. Repeatable.",
        ),
    ] = None,
) -> None:
    """Add a brand to the watchlist, or update the one already recorded."""

    state = _state(ctx)
    config = _load(state)

    try:
        canonical = normalize(domain).ascii_name
    except InvalidDomainNameError as exc:
        _fail(str(exc), state=state)
        return

    with open_database(config.storage.database) as connection:
        repository = Repository(connection)
        target = repository.upsert_target(
            brand=brand,
            canonical_domain=canonical,
            keywords=keyword or [],
            allowlist=allow or [],
        )

    _emit(
        state,
        _target_payload(target),
        lambda: console.print(f"watching [bold]{target.brand}[/bold] ({target.canonical_domain})"),
    )


@target_app.command("list")
def target_list(
    ctx: typer.Context,
    all_targets: Annotated[
        bool, typer.Option("--all", help="Include targets that were deactivated.")
    ] = False,
) -> None:
    """Show the watchlist."""

    state = _state(ctx)
    config = _load(state)

    with open_database(config.storage.database) as connection:
        targets = Repository(connection).list_targets(active_only=not all_targets)

    def render() -> None:
        if not targets:
            console.print(
                "[dim]the watchlist is empty; run `ctwatch init` or `ctwatch target add`[/dim]"
            )
            return
        table = Table(title="Watchlist", title_justify="left")
        table.add_column("Brand")
        table.add_column("Domain")
        table.add_column("Keywords")
        table.add_column("Allowlisted")
        for target in targets:
            table.add_row(
                target.brand,
                target.canonical_domain,
                ", ".join(target.keywords) or "-",
                str(len(target.allowlist)),
            )
        console.print(table)

    _emit(state, [_target_payload(target) for target in targets], render)


def _finding_payload(row: Any) -> dict[str, Any]:
    breakdown: dict[str, Any] = json.loads(row["breakdown"] or "{}")
    contributions = breakdown.get("contributions", [])
    strongest = max(contributions, key=lambda item: item.get("weighted", 0.0), default=None)
    return {
        "id": int(row["id"]),
        "brand": row["brand"],
        "target": row["canonical_domain"],
        "domain": row["domain_name"],
        "display_name": row["domain_unicode_name"] or row["domain_name"],
        "idn": bool(row["domain_is_idn"]),
        "score": float(row["score"]),
        "confidence": row["confidence"],
        "status": row["status"],
        "why": (strongest or {}).get("explanation", ""),
        "breakdown": breakdown,
    }


def _permutation_payload(permutation: Permutation) -> dict[str, Any]:
    return {
        "name": permutation.name.ascii_name,
        "display_name": permutation.name.unicode_name,
        "idn": permutation.name.is_idn,
        "kind": permutation.kind.value,
        "detail": permutation.detail,
        "base": permutation.base,
    }


@app.command()
def permutations(
    ctx: typer.Context,
    domain: Annotated[str, typer.Argument(help="Domain to derive candidates from.")],
    limit: Annotated[
        int | None, typer.Option("--limit", help="Stop after this many candidates.")
    ] = None,
    include_homoglyphs: Annotated[
        bool,
        typer.Option(
            "--include-homoglyphs/--no-homoglyphs",
            help="Include lookalike characters from other scripts.",
        ),
    ] = True,
    kind: Annotated[
        list[str] | None,
        typer.Option("--kind", help="Restrict to one technique. Repeatable."),
    ] = None,
    keyword: Annotated[
        list[str] | None,
        typer.Option(
            "--keyword",
            help="Word to combine with the name. Defaults to the watchlist entry's own.",
        ),
    ] = None,
) -> None:
    """Show the candidate names a scan would look up. Contacts nothing."""

    state = _state(ctx)
    config = _load(state)

    kinds = set(PermutationKind)
    if kind:
        try:
            kinds = {PermutationKind(value.strip().lower()) for value in kind}
        except ValueError:
            known = ", ".join(sorted(item.value for item in PermutationKind))
            _fail(f"unknown technique; known techniques: {known}", state=state)
            return
    if not include_homoglyphs:
        kinds.discard(PermutationKind.HOMOGLYPH)

    keywords = list(keyword or [])
    if not keywords:
        configured = config.target_for_domain(domain)
        if configured is not None:
            keywords = list(configured.keywords)

    generator = PermutationGenerator(
        layouts=tuple(config.permutations.keyboard_layouts),
        extra_tlds=config.permutations.extra_tlds,
        keywords=keywords,
        kinds=kinds,
    )

    try:
        produced = list(generator.generate(domain, limit=limit))
    except ValueError as exc:
        _fail(str(exc), state=state)
        return

    def render() -> None:
        table = Table(title=f"Candidates derived from {domain}", title_justify="left")
        table.add_column("Name")
        table.add_column("As displayed")
        table.add_column("Technique")
        table.add_column("Why")
        for permutation in produced:
            table.add_row(
                permutation.name.ascii_name,
                permutation.name.unicode_name if permutation.name.is_idn else "",
                permutation.kind.value,
                permutation.detail,
            )
        console.print(table)
        console.print(f"[dim]{len(produced)} candidate(s); nothing was contacted[/dim]")

    _emit(state, [_permutation_payload(permutation) for permutation in produced], render)


@app.command()
def monitor(
    ctx: typer.Context,
    target: Annotated[
        list[str] | None,
        typer.Option("--target", help="Watch one domain. Repeatable; defaults to all."),
    ] = None,
    variants: Annotated[
        int,
        typer.Option(
            "--variants",
            help="Candidates per brand to hold in the matcher. Costs memory, not requests.",
        ),
    ] = 500,
    max_certificates: Annotated[
        int | None,
        typer.Option("--max-certificates", help="Stop after this many. Mostly for testing."),
    ] = None,
) -> None:
    """Follow the live certificate feed and report what matches the watchlist.

    Unlike a scan, coverage here is not paid for by the name: every certificate
    that goes past is checked against the whole candidate set at once. Only the
    ones that match are stored.
    """

    state = _state(ctx)
    config = _load(state)

    if not config.sources.certstream.enabled:
        _fail(
            "the live feed is disabled; set sources.certstream.enabled in the configuration",
            state=state,
        )
        return

    config.storage.evidence_dir.mkdir(parents=True, exist_ok=True)

    with open_database(config.storage.database) as connection:
        repository = Repository(connection)
        sync_targets_from_config(repository, config)

        available = repository.list_targets()
        if target:
            wanted = {normalize(item).ascii_name for item in target}
            selected = [item for item in available if item.canonical_domain in wanted]
            missing = wanted - {item.canonical_domain for item in selected}
            if missing:
                _fail(f"not on the watchlist: {', '.join(sorted(missing))}", state=state)
                return
        else:
            selected = available

        if not selected:
            _fail("the watchlist is empty; run `ctwatch init` first", state=state)
            return

        evidence = EvidenceStore(config.storage.evidence_dir, repository)

        if not state.json_output:
            console.print(
                f"watching {len(selected)} brand(s) against {config.sources.certstream.url}"
            )
            console.print("[dim]press Ctrl-C to stop[/dim]\n")

        def announce(message: str) -> None:
            if not state.json_output:
                error_console.print(f"[dim]{message}[/dim]")

        try:
            report = asyncio.run(
                run_monitor(
                    config=config,
                    repository=repository,
                    evidence=evidence,
                    targets=selected,
                    variants=variants,
                    max_certificates=max_certificates,
                    on_event=announce,
                )
            )
        except KeyboardInterrupt:
            console.print("\n[dim]stopped[/dim]")
            raise typer.Exit(0) from None

    def render() -> None:
        console.print()
        console.print(
            f"{report.certificates_seen} certificate(s) seen, "
            f"{report.matches} match(es), {report.alerts} alert(s), "
            f"{report.archived} message(s) archived"
        )
        if report.polling_rounds:
            console.print(
                f"[yellow]the feed was unavailable; fell back to polling "
                f"{report.polling_rounds} time(s)[/yellow]"
            )
        for message in report.errors:
            error_console.print(f"[yellow]{message}[/yellow]")

    _emit(state, report.as_dict(), render)


@app.command()
def enrich(
    ctx: typer.Context,
    finding_id: Annotated[
        int | None, typer.Option("--finding-id", help="Enrich the domain behind one finding.")
    ] = None,
    domain: Annotated[
        list[str] | None,
        typer.Option("--domain", help="Enrich a specific domain. Repeatable."),
    ] = None,
    target: Annotated[
        str | None, typer.Option("--target", help="Restrict to one watched domain.")
    ] = None,
    min_score: Annotated[
        float | None,
        typer.Option("--min-score", help="Only enrich findings at or above this score."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Stop after this many domains.")] = 10,
) -> None:
    """Add registration, resolution and third-party rendering to findings.

    Every step asks somebody about the domain — the registry, a public
    resolver, urlscan.io. None of them contacts the domain itself.
    """

    state = _state(ctx)
    config = _load(state)
    threshold = config.scoring.review_threshold if min_score is None else min_score
    config.storage.evidence_dir.mkdir(parents=True, exist_ok=True)

    with open_database(config.storage.database) as connection:
        repository = Repository(connection)
        sync_targets_from_config(repository, config)

        records = []
        if finding_id is not None:
            row = repository.get_finding(finding_id)
            if row is None:
                _fail(f"no finding with id {finding_id}", state=state)
                return
            found = repository.get_domain_by_id(int(row["domain_id"]))
            if found is not None:
                records.append(found)
        elif domain:
            for entry in domain:
                try:
                    wanted = normalize(entry).ascii_name
                except InvalidDomainNameError as exc:
                    _fail(str(exc), state=state)
                    return
                found = repository.get_domain(wanted)
                if found is None:
                    _fail(f"never observed, so there is nothing to enrich: {wanted}", state=state)
                    return
                records.append(found)
        else:
            target_id = None
            if target is not None:
                wanted = normalize(target).ascii_name
                matches = [t for t in repository.list_targets() if t.canonical_domain == wanted]
                if not matches:
                    _fail(f"not on the watchlist: {wanted}", state=state)
                    return
                target_id = matches[0].id
            records = repository.domains_for_findings(
                target_id=target_id, min_score=threshold, limit=limit
            )

        if not records:
            _fail(
                "nothing to enrich; scan first, or lower --min-score",
                state=state,
            )
            return

        evidence = EvidenceStore(config.storage.evidence_dir, repository)
        try:
            results = asyncio.run(
                enrich_domains(
                    config=config,
                    repository=repository,
                    evidence=evidence,
                    domains=records,
                )
            )
        except NetworkPolicyError as exc:
            _fail(str(exc), state=state)
            return

    def render() -> None:
        for result in results:
            console.print(f"[bold]{result.domain.display_name}[/bold]")
            registration = result.registration
            if registration is not None:
                registered = (
                    registration.registered_at.date().isoformat()
                    if registration.registered_at
                    else "unknown"
                )
                console.print(
                    f"  registered  {registered}  via "
                    f"{registration.registrar or 'unknown registrar'}"
                )
                if registration.statuses:
                    console.print(f"  status      {', '.join(registration.statuses)}")
            if result.resolution is not None:
                addresses = ", ".join(result.resolution.addresses) or "does not resolve"
                console.print(f"  resolves to {addresses}")
                nameservers = result.resolution.of_type("NS")
                if nameservers:
                    console.print(f"  nameservers {', '.join(nameservers)}")
            for scan in result.scans[:3]:
                console.print(f"  rendered    {scan.result_url} ({scan.page_asn_name or '?'})")
            for pivot in result.pivots[:5]:
                shared = ", ".join(pivot.domains[:4])
                more = "" if pivot.size <= 4 else f" and {pivot.size - 4} more"
                console.print(f"  [cyan]pivot[/cyan] {pivot.description}: {shared}{more}")
            for message in result.errors:
                error_console.print(f"  [yellow]{message}[/yellow]")
            console.print()

    _emit(state, [result.as_dict() for result in results], render)


@app.command()
def findings(
    ctx: typer.Context,
    target: Annotated[
        str | None, typer.Option("--target", help="Restrict to one watched domain.")
    ] = None,
    min_score: Annotated[
        float | None,
        typer.Option("--min-score", help="Only show findings at or above this score."),
    ] = None,
    status: Annotated[
        list[str] | None,
        typer.Option("--status", help="Restrict to a review status. Repeatable."),
    ] = None,
    include_allowlisted: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Also show domains suppressed as belonging to the watched brand.",
        ),
    ] = False,
    limit: Annotated[int | None, typer.Option("--limit", help="Stop after this many.")] = None,
    recompute: Annotated[
        bool,
        typer.Option(
            "--recompute/--no-recompute",
            help="Re-score stored observations first. Contacts nothing.",
        ),
    ] = True,
) -> None:
    """List assessed findings, highest score first."""

    state = _state(ctx)
    config = _load(state)
    threshold = config.scoring.review_threshold if min_score is None else min_score

    with open_database(config.storage.database) as connection:
        repository = Repository(connection)
        sync_targets_from_config(repository, config)

        available = repository.list_targets()
        selected = available
        if target is not None:
            wanted = normalize(target).ascii_name
            selected = [item for item in available if item.canonical_domain == wanted]
            if not selected:
                _fail(f"not on the watchlist: {wanted}", state=state)
                return

        if recompute:
            assess_targets(repository=repository, config=config, targets=selected)

        rows = repository.list_findings(
            target_id=selected[0].id if target is not None else None,
            min_score=threshold,
            include_allowlisted=include_allowlisted,
            statuses=[item.strip().lower() for item in status] if status else None,
            limit=limit,
        )
        results = [_finding_payload(row) for row in rows]

    def render() -> None:
        if not results:
            console.print(
                f"[dim]no finding at or above {threshold:.2f}; "
                "try --min-score 0, or scan with --variants[/dim]"
            )
            return
        table = Table(title="Findings", title_justify="left")
        table.add_column("Score", justify="right")
        table.add_column("Conf.")
        table.add_column("Domain")
        table.add_column("As displayed")
        table.add_column("Brand")
        table.add_column("Why")
        for entry in results:
            table.add_row(
                f"{entry['score']:.2f}",
                entry["confidence"] or "-",
                entry["domain"],
                entry["display_name"] if entry["idn"] else "",
                entry["brand"],
                entry["why"],
            )
        console.print(table)

    _emit(state, results, render)


@app.command()
def scan(
    ctx: typer.Context,
    target: Annotated[
        list[str] | None,
        typer.Option("--target", help="Canonical domain to scan. Repeatable; defaults to all."),
    ] = None,
    since: Annotated[
        str | None,
        typer.Option("--since", help="Only keep entries newer than this, e.g. 30d or 12h."),
    ] = None,
    source: Annotated[
        list[str] | None,
        typer.Option("--source", help="Restrict to one source, e.g. crtsh. Repeatable."),
    ] = None,
    variants: Annotated[
        int,
        typer.Option(
            "--variants",
            help=(
                "Also look up this many generated candidates per target. "
                "Each one is a separate request to a rate-limited service."
            ),
        ),
    ] = 0,
) -> None:
    """Query the Certificate Transparency sources for the watched domains."""

    state = _state(ctx)
    config = _load(state)

    cutoff = None
    if since is not None:
        try:
            cutoff = utc_now() - parse_duration(since)
        except ValueError as exc:
            _fail(str(exc), state=state)
            return

    config.storage.evidence_dir.mkdir(parents=True, exist_ok=True)

    with open_database(config.storage.database) as connection:
        repository = Repository(connection)
        sync_targets_from_config(repository, config)

        available = repository.list_targets()
        if target:
            wanted = {normalize(item).ascii_name for item in target}
            selected = [item for item in available if item.canonical_domain in wanted]
            missing = wanted - {item.canonical_domain for item in selected}
            if missing:
                _fail(f"not on the watchlist: {', '.join(sorted(missing))}", state=state)
                return
        else:
            selected = available

        if not selected:
            _fail("the watchlist is empty; run `ctwatch init` first", state=state)
            return

        evidence = EvidenceStore(config.storage.evidence_dir, repository)
        try:
            summaries = asyncio.run(
                run_scan(
                    config=config,
                    repository=repository,
                    evidence=evidence,
                    targets=selected,
                    since=cutoff,
                    only_sources=source,
                    variants=variants,
                )
            )
        except (SourceError, NetworkPolicyError) as exc:
            _fail(str(exc), state=state)
            return

        # Scoring reads what the scan just stored and contacts nothing, so it
        # is always worth doing straight away.
        reports = {
            report.target.canonical_domain: report.as_dict()
            for report in assess_targets(repository=repository, config=config, targets=selected)
        }
        payloads = []
        for summary in summaries:
            entry = summary.as_dict()
            entry["findings"] = reports.get(summary.canonical_domain, {})
            payloads.append(entry)

    def render() -> None:
        table = Table(title="Scan", title_justify="left")
        table.add_column("Brand")
        table.add_column("Domain")
        table.add_column("Queries", justify="right")
        table.add_column("Certificates", justify="right")
        table.add_column("Names", justify="right")
        table.add_column("New", justify="right")
        table.add_column("To review", justify="right")
        table.add_column("Suppressed", justify="right")
        for summary in summaries:
            report = reports.get(summary.canonical_domain, {})
            table.add_row(
                summary.brand,
                summary.canonical_domain,
                str(summary.queries),
                str(summary.certificates),
                str(summary.domains_seen),
                str(summary.new_domains),
                str(report.get("above_threshold", 0)),
                str(report.get("suppressed", 0)),
            )
        console.print(table)
        for summary in summaries:
            for message in summary.errors:
                error_console.print(f"[yellow]{summary.canonical_domain}[/yellow] {message}")
        if variants <= 0:
            console.print(
                "\n[dim]Only the watched names were looked up. A domain registered with a "
                "lookalike character will not appear in a search for the original spelling; "
                "pass --variants N to look up generated candidates as well, or run "
                "`ctwatch permutations <domain>` to see them first.[/dim]"
            )

    _emit(state, payloads, render)


if __name__ == "__main__":  # pragma: no cover
    app()
