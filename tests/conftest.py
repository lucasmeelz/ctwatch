from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from ctwatch.store.database import connect, migrate
from ctwatch.store.repository import Repository


@pytest.fixture
def connection(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(tmp_path / "ctwatch.db")
    migrate(conn)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def repository(connection: sqlite3.Connection) -> Repository:
    return Repository(connection)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if a test ever tries to open a real connection.

    The suite runs entirely on recorded fixtures. A test that reaches the
    network is either flaky or, worse, contacting something it should not.
    """

    import socket

    def refuse(*args: object, **kwargs: object) -> None:
        msg = "tests must not open network connections; use a recorded fixture instead"
        raise RuntimeError(msg)

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
