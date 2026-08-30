"""Archival of raw responses.

Nothing this tool asserts should have to be taken on trust. Every response that
feeds a finding is stored verbatim, compressed, addressed by the SHA-256 of its
*uncompressed* bytes, and paired with the exact endpoint and UTC timestamp of
the request. Six months later, the same digest can be recomputed from the
archived file with nothing more exotic than ``gunzip`` and ``sha256sum``.
"""

from __future__ import annotations

import gzip
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

from ctwatch.store.models import EvidenceRecord
from ctwatch.store.repository import Repository
from ctwatch.timeutil import utc_now


class EvidenceError(RuntimeError):
    """Raised when archived content cannot be read back or does not verify."""


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def blob_relative_path(digest: str, moment: datetime) -> Path:
    """Content-addressed layout, bucketed by month to keep directories small."""

    return Path(f"{moment:%Y}") / f"{moment:%m}" / digest[:2] / f"{digest}.gz"


class EvidenceStore:
    """Writes response bodies to disk and records them in the database."""

    def __init__(self, root: Path, repository: Repository) -> None:
        self._root = root
        self._repository = repository

    @property
    def root(self) -> Path:
        return self._root

    def capture(
        self,
        *,
        source: str,
        endpoint: str,
        content: bytes,
        requested_at: datetime | None = None,
        status_code: int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """Archive one response and return its evidence row.

        Identical content retrieved twice is written once but recorded twice:
        the file is a fact about the bytes, the row is a fact about the request.
        """

        moment = requested_at or utc_now()
        digest = sha256_hex(content)
        relative = blob_relative_path(digest, moment)
        absolute = self._root / relative

        if not absolute.exists():
            absolute.parent.mkdir(parents=True, exist_ok=True)
            # mtime=0 keeps the compressed file byte-for-byte reproducible, so
            # two analysts archiving the same response get the same file. The
            # write goes through a uniquely named temporary so a crash, or a
            # second process archiving the same bytes, cannot leave a truncated
            # file sitting at the final path.
            temporary = absolute.parent / f"{absolute.name}.{secrets.token_hex(8)}.partial"
            try:
                temporary.write_bytes(gzip.compress(content, mtime=0))
                temporary.replace(absolute)
            finally:
                temporary.unlink(missing_ok=True)

        return self._repository.insert_evidence(
            source=source,
            endpoint=endpoint,
            requested_at=moment,
            status_code=status_code,
            content_sha256=digest,
            content_length=len(content),
            blob_path=relative.as_posix(),
            meta=meta,
        )

    def absolute_path(self, record: EvidenceRecord) -> Path:
        return self._root / record.blob_path

    def read(self, record: EvidenceRecord) -> bytes:
        """Return the archived bytes, refusing to hand back altered content."""

        path = self.absolute_path(record)
        if not path.is_file():
            msg = f"archived response is missing: {path}"
            raise EvidenceError(msg)

        content = gzip.decompress(path.read_bytes())
        digest = sha256_hex(content)
        if digest != record.content_sha256:
            msg = (
                f"archived response does not match its recorded digest: {path} "
                f"(expected {record.content_sha256}, found {digest})"
            )
            raise EvidenceError(msg)
        return content

    def verify(self, record: EvidenceRecord) -> bool:
        try:
            self.read(record)
        except (EvidenceError, OSError):
            return False
        return True
