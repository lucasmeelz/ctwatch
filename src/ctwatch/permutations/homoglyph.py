"""Names that read the same but resolve somewhere else.

This is the technique a substring search over Certificate Transparency cannot
find. ``lemonde.fr`` written with a Cyrillic "о" is stored in the logs as
``xn--lemnde-yqf.fr``; no query derived from the Latin spelling will ever match
it. The variant has to be constructed first and looked up by name.

Two families of substitution are covered:

* characters from other scripts that Unicode itself flags as confusable
  (UTS #39), reduced to those that survive UTS #46 as a genuinely different
  registration — see ``scripts/refresh_confusables.py``;
* the plain ASCII lookalikes that no Unicode table records because both sides
  are ASCII: ``1`` for ``l``, ``0`` for ``o``, ``rn`` for ``m``. These are the
  ones that appear in almost every published case, and they would be missed
  entirely by a Unicode-only approach.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ctwatch.names import InvalidDomainNameError, normalize
from ctwatch.permutations.model import Permutation, PermutationKind
from ctwatch.publicsuffix import split

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "confusables_ascii.tsv"

# Scripts an impersonator actually reaches for, listed first so that `--limit`
# keeps the plausible variants rather than the Old Italic ones.
SCRIPT_PRIORITY: tuple[str, ...] = ("CYRILLIC", "GREEK", "LATIN", "ARMENIAN")

# Pairs that look alike in ASCII, where neither side is a Unicode confusable of
# the other because both are plain ASCII. Curated by hand; each entry is read
# in both directions.
_ASCII_PAIRS: tuple[tuple[str, str], ...] = (
    ("o", "0"),
    ("l", "1"),
    ("l", "i"),
    ("i", "1"),
    ("e", "3"),
    ("a", "4"),
    ("s", "5"),
    ("t", "7"),
    ("b", "6"),
    ("b", "8"),
    ("g", "9"),
    ("g", "q"),
    ("z", "2"),
    ("u", "v"),
    ("h", "b"),
    ("m", "rn"),
    ("m", "nn"),
    ("w", "vv"),
    ("d", "cl"),
    ("n", "ri"),
)


def _build_ascii_lookalikes() -> dict[str, tuple[str, ...]]:
    mapping: dict[str, set[str]] = {}
    for left, right in _ASCII_PAIRS:
        mapping.setdefault(left, set()).add(right)
        mapping.setdefault(right, set()).add(left)
    return {key: tuple(sorted(values)) for key, values in mapping.items()}


ASCII_LOOKALIKES: dict[str, tuple[str, ...]] = _build_ascii_lookalikes()


@dataclass(frozen=True, slots=True)
class Confusable:
    """A single character that can stand in for an ASCII one."""

    character: str
    script: str
    name: str

    @property
    def code_point(self) -> str:
        return f"U+{ord(self.character):04X}"


class ConfusableTable:
    """The vendored UTS #39 subset, indexed by the ASCII character it mimics."""

    def __init__(self, entries: dict[str, tuple[Confusable, ...]]) -> None:
        self._entries = entries

    @classmethod
    def parse(cls, text: str) -> ConfusableTable:
        collected: dict[str, list[Confusable]] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) < 4:
                continue
            target, code_point, script, name = fields[0], fields[1], fields[2], fields[3]
            collected.setdefault(target, []).append(
                Confusable(character=chr(int(code_point, 16)), script=script, name=name)
            )

        ordered = {
            target: tuple(sorted(values, key=_script_sort_key))
            for target, values in collected.items()
        }
        return cls(ordered)

    def substitutes(self, character: str) -> tuple[Confusable, ...]:
        return self._entries.get(character, ())

    def targets(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))

    def scripts(self) -> tuple[str, ...]:
        found = {confusable.script for values in self._entries.values() for confusable in values}
        return tuple(sorted(found, key=lambda script: _script_rank(script)))

    def in_script(self, character: str, script: str) -> Confusable | None:
        for confusable in self.substitutes(character):
            if confusable.script == script:
                return confusable
        return None

    def __len__(self) -> int:
        return sum(len(values) for values in self._entries.values())


def _script_rank(script: str) -> int:
    try:
        return SCRIPT_PRIORITY.index(script)
    except ValueError:
        return len(SCRIPT_PRIORITY)


def _script_sort_key(confusable: Confusable) -> tuple[int, str, int]:
    return (_script_rank(confusable.script), confusable.script, ord(confusable.character))


@lru_cache(maxsize=1)
def load_confusables(path: Path = DATA_PATH) -> ConfusableTable:
    return ConfusableTable.parse(path.read_text(encoding="utf-8"))


def _replace_at(label: str, start: int, length: int, replacement: str) -> str:
    return label[:start] + replacement + label[start + length :]


def _occurrences(label: str, fragment: str) -> list[int]:
    positions: list[int] = []
    start = label.find(fragment)
    while start != -1:
        positions.append(start)
        start = label.find(fragment, start + 1)
    return positions


class HomoglyphGenerator:
    """Builds the visually identical names worth looking up."""

    def __init__(
        self,
        *,
        table: ConfusableTable | None = None,
        include_unicode: bool = True,
        include_ascii: bool = True,
        include_whole_word: bool = True,
    ) -> None:
        self._table = table or load_confusables()
        self._include_unicode = include_unicode
        self._include_ascii = include_ascii
        self._include_whole_word = include_whole_word

    def _ascii_candidates(self, label: str) -> Iterator[tuple[str, str]]:
        """(new label, explanation) for the plain ASCII lookalikes."""

        for fragment in sorted(ASCII_LOOKALIKES, key=lambda item: (-len(item), item)):
            positions = _occurrences(label, fragment)
            if not positions:
                continue
            for replacement in ASCII_LOOKALIKES[fragment]:
                for position in positions:
                    yield (
                        _replace_at(label, position, len(fragment), replacement),
                        f"{fragment!r} written as {replacement!r} at position {position + 1}",
                    )
                if len(positions) > 1:
                    yield (
                        label.replace(fragment, replacement),
                        f"every {fragment!r} written as {replacement!r}",
                    )

    def _unicode_candidates(self, label: str) -> Iterator[tuple[str, str]]:
        """(new label, explanation) for the Unicode confusables."""

        for character in dict.fromkeys(label):
            positions = _occurrences(label, character)
            for confusable in self._table.substitutes(character):
                described = (
                    f"{confusable.script.title()} {confusable.character!r} "
                    f"({confusable.code_point})"
                )
                for position in positions:
                    yield (
                        _replace_at(label, position, 1, confusable.character),
                        f"{character!r} replaced by {described} at position {position + 1}",
                    )
                if len(positions) > 1:
                    yield (
                        label.replace(character, confusable.character),
                        f"every {character!r} replaced by {described}",
                    )

    def _whole_word_candidates(self, label: str) -> Iterator[tuple[str, str]]:
        """A name rewritten entirely in one other script."""

        letters = [character for character in label if character.isalnum()]
        if len(letters) < 2:
            return

        for script in self._table.scripts():
            rewritten: list[str] = []
            complete = True
            for character in label:
                if not character.isalnum():
                    rewritten.append(character)
                    continue
                confusable = self._table.in_script(character, script)
                if confusable is None:
                    complete = False
                    break
                rewritten.append(confusable.character)
            if complete:
                yield (
                    "".join(rewritten),
                    f"every character rewritten in {script.title()}",
                )

    def variants(self, domain: str) -> Iterator[Permutation]:
        """Yield homoglyph variants of ``domain``, most plausible first."""

        parts = split(domain)
        base = parts.registrable_domain
        if base is None:
            msg = (
                f"{domain!r} has no registrable part to mutate; "
                "it is a public suffix, not a domain someone owns"
            )
            raise ValueError(msg)

        label, suffix = parts.registrable_label, parts.suffix
        seen: set[str] = {base, label}

        streams: list[Iterator[tuple[str, str]]] = []
        if self._include_ascii:
            streams.append(self._ascii_candidates(label))
        if self._include_unicode:
            streams.append(self._unicode_candidates(label))
            if self._include_whole_word:
                streams.append(self._whole_word_candidates(label))

        for stream in streams:
            for mutated, detail in stream:
                if mutated in seen or not mutated:
                    continue
                seen.add(mutated)
                try:
                    name = normalize(f"{mutated}.{suffix}")
                except InvalidDomainNameError:
                    continue
                if name.ascii_name in seen:
                    continue
                seen.add(name.ascii_name)
                yield Permutation(
                    name=name,
                    kind=PermutationKind.HOMOGLYPH,
                    detail=detail,
                    base=base,
                )
