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

    def render() -> None:
        table = Table(title="Scan", title_justify="left")
        table.add_column("Brand")
        table.add_column("Domain")
        table.add_column("Queries", justify="right")
        table.add_column("Certificates", justify="right")
        table.add_column("Names", justify="right")
        table.add_column("New", justify="right")
        for summary in summaries:
            table.add_row(
                summary.brand,
                summary.canonical_domain,
                str(summary.queries),
                str(summary.certificates),
                str(summary.domains_seen),
                str(summary.new_domains),
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

    _emit(state, [summary.as_dict() for summary in summaries], render)


if __name__ == "__main__":  # pragma: no cover
    app()
