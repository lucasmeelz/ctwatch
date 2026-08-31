"""Alerts appended to a file, one JSON object per line.

The format is chosen so a monitor left running for weeks stays readable with
``tail -f`` and pipeable into anything else without a parser.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from ctwatch.notify.base import Alert


class JsonlNotifier:
    NAME: ClassVar[str] = "jsonl"

    @property
    def name(self) -> str:
        return self.NAME

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    async def publish(self, alert: Alert) -> None:
        line = json.dumps(alert.as_dict(), sort_keys=True, ensure_ascii=False)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")

    async def aclose(self) -> None:
        return None
