from __future__ import annotations

import gzip
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ctwatch.store.evidence import EvidenceError, EvidenceStore
from ctwatch.store.repository import Repository

MOMENT = datetime(2026, 3, 9, 15, 48, tzinfo=UTC)
BODY = b'[{"name_value": "lemonde-actu.info"}]'


@pytest.fixture
def store(tmp_path: Path, repository: Repository) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", repository)


def test_capture_archives_verifiable_bytes(store: EvidenceStore) -> None:
    record = store.capture(
        source="crtsh",
        endpoint="https://crt.sh/?q=lemonde.fr&output=json",
        content=BODY,
        requested_at=MOMENT,
        status_code=200,
    )
    assert record.content_sha256 == hashlib.sha256(BODY).hexdigest()
    assert record.content_length == len(BODY)
    assert store.read(record) == BODY


def test_archive_is_readable_without_the_tool(store: EvidenceStore) -> None:
    record = store.capture(source="crtsh", endpoint="https://crt.sh/", content=BODY)
    path = store.absolute_path(record)
    assert path.suffix == ".gz"
    assert gzip.decompress(path.read_bytes()) == BODY


def test_path_is_content_addressed_and_dated(store: EvidenceStore) -> None:
    record = store.capture(
        source="crtsh", endpoint="https://crt.sh/", content=BODY, requested_at=MOMENT
    )
    digest = hashlib.sha256(BODY).hexdigest()
    assert record.blob_path == f"2026/03/{digest[:2]}/{digest}.gz"


def test_identical_content_is_stored_once_but_recorded_twice(store: EvidenceStore) -> None:
    first = store.capture(source="crtsh", endpoint="https://crt.sh/", content=BODY)
    second = store.capture(source="crtsh", endpoint="https://crt.sh/", content=BODY)
    assert first.id != second.id
    assert first.blob_path == second.blob_path
    assert len(list(store.root.rglob("*.gz"))) == 1


def test_tampered_archive_is_refused(store: EvidenceStore) -> None:
    record = store.capture(source="crtsh", endpoint="https://crt.sh/", content=BODY)
    store.absolute_path(record).write_bytes(gzip.compress(b"[]"))
    with pytest.raises(EvidenceError, match="does not match its recorded digest"):
        store.read(record)
    assert store.verify(record) is False


def test_missing_archive_is_reported(store: EvidenceStore) -> None:
    record = store.capture(source="crtsh", endpoint="https://crt.sh/", content=BODY)
    store.absolute_path(record).unlink()
    with pytest.raises(EvidenceError, match="missing"):
        store.read(record)


def test_compressed_output_is_reproducible(store: EvidenceStore, tmp_path: Path) -> None:
    record = store.capture(source="crtsh", endpoint="https://crt.sh/", content=BODY)
    archived = store.absolute_path(record).read_bytes()
    expected = gzip.compress(BODY, mtime=0)
    assert archived == expected
