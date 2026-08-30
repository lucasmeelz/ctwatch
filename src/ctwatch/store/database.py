"""SQLite connection handling and schema migrations.

Migrations are plain ``.sql`` files named ``NNNN_description.sql``. They are
applied in numeric order inside a transaction, and the applied version is
recorded, so an existing database created by an older release can be brought
forward without losing collected evidence.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  TEXT NOT NULL
)
"""


class MigrationError(RuntimeError):
    """Raised when the on-disk schema cannot be brought to the expected state."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    path: Path

    def read(self) -> str:
        return self.path.read_text(encoding="utf-8")


def discover_migrations(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    migrations: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        prefix, _, remainder = path.stem.partition("_")
        if not prefix.isdigit():
            msg = f"migration file must start with a numeric version: {path.name}"
            raise MigrationError(msg)
        migrations.append(Migration(version=int(prefix), name=remainder or path.stem, path=path))

    versions = [migration.version for migration in migrations]
    if len(set(versions)) != len(versions):
        msg = f"duplicate migration version in {directory}"
        raise MigrationError(msg)
    return migrations


def connect(database: Path) -> sqlite3.Connection:
    """Open a connection with the pragmas this project relies on."""

    if database != Path(":memory:"):
        database.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def applied_versions(connection: sqlite3.Connection) -> set[int]:
    connection.execute(_MIGRATIONS_TABLE)
    rows = connection.execute("SELECT version FROM schema_migrations").fetchall()
    return {int(row["version"]) for row in rows}


def _sql_literal(value: str) -> str:
    """Quote a string for inline use in a migration script."""

    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def migrate(connection: sqlite3.Connection, directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    """Apply every migration that has not run yet. Returns the ones applied."""

    already = applied_versions(connection)
    pending = [m for m in discover_migrations(directory) if m.version not in already]

    for migration in pending:
        # sqlite3.executescript() commits any pending transaction before it
        # runs, so the transaction has to live inside the script itself for a
        # failed migration to leave no trace. SQLite supports transactional
        # DDL, so a rollback really does undo half-created tables.
        bookkeeping = (
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES "
            f"({migration.version:d}, {_sql_literal(migration.name)}, "
            f"{_sql_literal(datetime.now(UTC).isoformat())});"
        )
        try:
            connection.executescript(f"BEGIN;\n{migration.read()}\n{bookkeeping}\nCOMMIT;")
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            msg = f"migration {migration.version} ({migration.name}) failed: {exc}"
            raise MigrationError(msg) from exc

    return pending


@contextmanager
def open_database(database: Path) -> Iterator[sqlite3.Connection]:
    """Open a migrated database and close it afterwards."""

    connection = connect(database)
    try:
        migrate(connection)
        yield connection
    finally:
        connection.close()


@contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    connection.execute("BEGIN")
    try:
        yield connection
    except BaseException:
        connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")
