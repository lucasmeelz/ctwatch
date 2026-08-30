#!/usr/bin/env python3
"""Refresh the vendored Public Suffix List snapshot.

Run this by hand, review the diff, and commit it. The snapshot is deliberately
not fetched at runtime: a scan should not depend on yet another service being
reachable, and tests should not change behaviour because an upstream list did.

    uv run python scripts/refresh_public_suffix_list.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import httpx

SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"
DESTINATION = (
    Path(__file__).resolve().parents[1] / "src" / "ctwatch" / "data" / "public_suffix_list.dat"
)
MINIMUM_BYTES = 100_000


def main() -> int:
    response = httpx.get(SOURCE, timeout=60.0, follow_redirects=True)
    response.raise_for_status()
    content = response.content

    if len(content) < MINIMUM_BYTES:
        print(
            f"refusing to write a suspiciously small list ({len(content)} bytes)", file=sys.stderr
        )
        return 1
    if b"===BEGIN ICANN DOMAINS===" not in content:
        print("refusing to write a list without its ICANN section marker", file=sys.stderr)
        return 1

    previous = DESTINATION.read_bytes() if DESTINATION.exists() else b""
    DESTINATION.write_bytes(content)

    print(f"source  {SOURCE}")
    print(f"written {DESTINATION}")
    print(f"bytes   {len(content)}")
    print(f"sha256  {hashlib.sha256(content).hexdigest()}")
    print("changed" if content != previous else "unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
