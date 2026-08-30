from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ctwatch.store.database import (
    MigrationError,
    applied_versions,
    connect,
    discover_migrations,
    migrate,
    open_database,
)

EXPECTED_TABLES = {
    "watch_targets",
    "evidence",
    "certificates",
    "domains",
    "observations",
    "findings",
    "source_cache",
}


def table_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {row["name"] for row in rows}


def test_migrations_create_expected_tables(tmp_path: Path) -> None:
    with open_database(tmp_path / "ctwatch.db") as connection:
        assert table_names(connection) >= EXPECTED_TABLES


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "ctwatch.db"
    with open_database(database) as connection:
        first = applied_versions(connection)
    with open_database(database) as connection:
        assert migrate(connection) == []
        assert applied_versions(connection) == first


def test_foreign_keys_are_enforced(tmp_path: Path) -> None:
    with (
        open_database(tmp_path / "ctwatch.db") as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "INSERT INTO observations (domain_id, evidence_id, source, observed_at) "
            "VALUES (999, 999, 'crtsh', '2026-01-01T00:00:00+00:00')"
        )


def test_failed_migration_leaves_no_partial_schema(tmp_path: Path) -> None:
    broken = tmp_path / "migrations"
    broken.mkdir()
    (broken / "0001_broken.sql").write_text(
        "CREATE TABLE good (id INTEGER PRIMARY KEY);\nCREATE TABLE bad (;\n",
        encoding="utf-8",
    )
    connection = connect(tmp_path / "ctwatch.db")
    try:
        with pytest.raises(MigrationError):
            migrate(connection, broken)
        assert "good" not in table_names(connection)
        assert applied_versions(connection) == set()
    finally:
        connection.close()


def test_unnumbered_migration_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "migrations"
    directory.mkdir()
    (directory / "initial.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(MigrationError, match="numeric version"):
        discover_migrations(directory)


def test_shipped_migrations_are_numbered_without_gaps() -> None:
    versions = [migration.version for migration in discover_migrations()]
    assert versions == list(range(1, len(versions) + 1))
