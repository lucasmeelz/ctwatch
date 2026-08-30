"""Shared vocabulary for the permutation engine.

Kept in its own module so that the homoglyph generator and the typo generator
can both use it without importing each other.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ctwatch.names import DomainName


class PermutationKind(StrEnum):
    """How a candidate was derived from the watched name."""

    HOMOGLYPH = "homoglyph"
    REPLACEMENT = "replacement"
    OMISSION = "omission"
    TRANSPOSITION = "transposition"
    REPETITION = "repetition"
    INSERTION = "insertion"
    HYPHENATION = "hyphenation"
    VOWEL_SWAP = "vowel_swap"
    BITSQUAT = "bitsquat"
    KEYWORD = "keyword"
    SUFFIX_MERGE = "suffix_merge"
    TLD_SWAP = "tld_swap"

    @property
    def preserves_suffix(self) -> bool:
        """Whether the technique leaves the public suffix untouched."""

        return self not in {PermutationKind.SUFFIX_MERGE, PermutationKind.TLD_SWAP}


@dataclass(frozen=True, slots=True)
class Permutation:
    """One candidate name, with the reason it was generated."""

    name: DomainName
    kind: PermutationKind
    detail: str
    base: str

    @property
    def ascii_name(self) -> str:
        return self.name.ascii_name


@dataclass(frozen=True, slots=True)
class Candidate:
    """An intermediate result, before the full name is assembled."""

    label: str
    kind: PermutationKind
    detail: str
    suffix: str | None = None
