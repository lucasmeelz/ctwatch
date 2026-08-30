"""Physical keyboard adjacency, used to model plausible typing mistakes.

Layout matters more than it looks. A French reader mistyping ``lemonde`` is
using an azerty keyboard, where ``z`` sits next to ``e``; on qwerty the same
slip produces ``w``. Watching only one layout misses half the realistic typos,
so several are modelled at once and their results merged.
"""

from __future__ import annotations

from functools import lru_cache

# Rows are listed as they appear on the physical keyboard, letters only. The
# digit row is deliberately absent: digit-for-letter substitutions such as
# o -> 0 are visual rather than positional, and belong with the homoglyphs.
LAYOUTS: dict[str, tuple[str, ...]] = {
    "azerty": ("azertyuiop", "qsdfghjklm", "wxcvbn"),
    "qwerty": ("qwertyuiop", "asdfghjkl", "zxcvbnm"),
    "qwertz": ("qwertzuiop", "asdfghjkl", "yxcvbnm"),
}

DEFAULT_LAYOUTS: tuple[str, ...] = ("azerty", "qwerty")


def _layout_adjacency(rows: tuple[str, ...]) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = {}

    for row_index, row in enumerate(rows):
        for column, character in enumerate(row):
            neighbours = adjacency.setdefault(character, set())
            if column > 0:
                neighbours.add(row[column - 1])
            if column + 1 < len(row):
                neighbours.add(row[column + 1])

            # Rows are staggered half a key to the right, so the keys above and
            # below sit at the same column and the one before it.
            for other_index in (row_index - 1, row_index + 1):
                if not 0 <= other_index < len(rows):
                    continue
                other = rows[other_index]
                for offset in (-1, 0):
                    position = column + offset
                    if 0 <= position < len(other):
                        neighbours.add(other[position])

    return adjacency


@lru_cache(maxsize=8)
def adjacency(layouts: tuple[str, ...] = DEFAULT_LAYOUTS) -> dict[str, frozenset[str]]:
    """Merged adjacency map for the requested layouts."""

    merged: dict[str, set[str]] = {}
    for name in layouts:
        try:
            rows = LAYOUTS[name]
        except KeyError as exc:
            known = ", ".join(sorted(LAYOUTS))
            msg = f"unknown keyboard layout {name!r}; known layouts: {known}"
            raise ValueError(msg) from exc
        for character, neighbours in _layout_adjacency(rows).items():
            merged.setdefault(character, set()).update(neighbours)

    return {character: frozenset(values) for character, values in merged.items()}


def keyboard_neighbours(
    character: str, layouts: tuple[str, ...] = DEFAULT_LAYOUTS
) -> frozenset[str]:
    """Keys physically next to ``character`` on any of the given layouts."""

    return adjacency(layouts).get(character, frozenset())
