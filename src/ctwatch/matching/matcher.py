"""Matching a live certificate feed against every watched brand at once.

Scanning looks candidates up one at a time and pays a request for each. The
feed poses the opposite problem: certificates arrive by the thousand, unbidden,
and each of their names has to be checked against every candidate of every
watched brand before the next one lands. A loop over the watchlist would not
survive contact with the firehose.

So the watchlist is turned inside out into two dictionaries, and matching is a
lookup:

* the generated candidates, keyed by name — a hit carries the technique that
  produced it, which is the most useful thing a report can say;
* the *skeletons* of the watched names — the form a name takes once every
  character that reads like another has been folded onto one representative.
  ``1em0nde`` and ``lemоnde`` reduce to the same skeleton as ``lemonde``, so
  disguises nobody thought to enumerate are caught anyway.

A third, deliberately weak tier catches a watched name carried inside a longer
one, which is how a brand plus an unforeseen word gets registered.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from ctwatch.names import DomainName, InvalidDomainNameError, normalize, to_unicode_label
from ctwatch.permutations.generator import PermutationGenerator
from ctwatch.permutations.homoglyph import load_confusables
from ctwatch.permutations.model import PermutationKind
from ctwatch.publicsuffix import split
from ctwatch.store.models import WatchTarget

# Shortest watched label that may be looked for inside a longer name. Below
# this, the weak tier matches half the internet.
MINIMUM_CONTAINED_LENGTH = 5

# Characters folded together when reading a name. Deliberately narrower than
# what the generator produces: over-generating candidates costs a few lookups,
# whereas over-folding here would make unrelated words match each other. Pairs
# such as u/v or h/b are close enough to be worth generating and too close to
# be worth folding.
ASCII_FOLD_CLASSES: tuple[str, ...] = (
    "il1",
    "o0",
    "s5",
    "e3",
    "a4",
    "g9",
    "z2",
    "b6",
    "t7",
)

# Two characters that read as one. Applied before the single-character folding
# so that a Cyrillic r followed by an n also collapses.
SEQUENCE_FOLDS: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
)


class MatchTier(StrEnum):
    """How firmly a name was tied to a watched brand."""

    CANDIDATE = "candidate"
    LOOKALIKE = "lookalike"
    CONTAINS = "contains"


@lru_cache(maxsize=1)
def _fold_map() -> dict[str, str]:
    """Every character mapped onto the one it reads as."""

    folded: dict[str, str] = {}

    # Characters from other scripts fold onto the ASCII letter they mimic. A
    # character listed under several letters takes the first, alphabetically,
    # so the mapping is deterministic across runs.
    table = load_confusables()
    for target in table.targets():
        for confusable in table.substitutes(target):
            folded.setdefault(confusable.character, target)

    for group in ASCII_FOLD_CLASSES:
        representative = group[0]
        for character in group:
            folded[character] = representative

    return folded


def skeleton(label: str) -> str:
    """The form a label takes once everything that reads alike is folded.

    Two names with the same skeleton are two names a reader would not tell
    apart, whether or not anyone generated one from the other.
    """

    folded = _fold_map()
    mapped = "".join(folded.get(character, character) for character in label.strip().lower())

    for sequence, replacement in SEQUENCE_FOLDS:
        mapped = mapped.replace(sequence, replacement)

    # Folding a sequence can expose a character that still needs folding.
    return "".join(folded.get(character, character) for character in mapped)


@dataclass(frozen=True, slots=True)
class Match:
    """One name from the feed, tied to one watched brand."""

    name: DomainName
    target: WatchTarget
    tier: MatchTier
    detail: str
    kind: PermutationKind | None = None

    @property
    def is_strong(self) -> bool:
        return self.tier is not MatchTier.CONTAINS


@dataclass(frozen=True, slots=True)
class _Candidate:
    target_id: int
    kind: PermutationKind
    detail: str


class VariantMatcher:
    """The watchlist, turned inside out for lookup."""

    def __init__(
        self,
        *,
        targets: Iterable[WatchTarget],
        candidates: dict[str, _Candidate],
        skeletons: dict[str, int],
        labels: dict[str, int],
        excluded: set[str],
    ) -> None:
        self._targets = {target.id: target for target in targets}
        self._candidates = candidates
        self._skeletons = skeletons
        self._labels = labels
        self._excluded = excluded

    @classmethod
    def build(
        cls,
        targets: Iterable[WatchTarget],
        *,
        generator: PermutationGenerator | None = None,
        variants: int = 500,
    ) -> VariantMatcher:
        """Generate every candidate once, then index it."""

        watched = list(targets)
        candidates: dict[str, _Candidate] = {}
        skeletons: dict[str, int] = {}
        labels: dict[str, int] = {}
        excluded: set[str] = set()

        for target in watched:
            parts = split(target.canonical_domain)
            label = parts.registrable_label
            if label:
                skeletons.setdefault(skeleton(label), target.id)
                if len(label) >= MINIMUM_CONTAINED_LENGTH:
                    labels.setdefault(label, target.id)

            excluded.add(target.canonical_domain)
            excluded.update(entry.lstrip("*.") for entry in target.allowlist)

            engine = generator or PermutationGenerator(keywords=target.keywords)
            for permutation in engine.generate(target.canonical_domain, limit=variants):
                candidates.setdefault(
                    permutation.name.ascii_name,
                    _Candidate(
                        target_id=target.id,
                        kind=permutation.kind,
                        detail=permutation.detail,
                    ),
                )

        # A name that belongs to one brand must not be reported as an
        # impersonation of another: several outlets share words.
        for name in excluded:
            candidates.pop(name, None)

        return cls(
            targets=watched,
            candidates=candidates,
            skeletons=skeletons,
            labels=labels,
            excluded=excluded,
        )

    def __len__(self) -> int:
        return len(self._candidates)

    @property
    def targets(self) -> dict[int, WatchTarget]:
        return dict(self._targets)

    def _is_excluded(self, registrable: str) -> bool:
        return registrable in self._excluded or any(
            registrable.endswith(f".{entry}") for entry in self._excluded
        )

    def match(self, raw_name: str) -> Match | None:
        """Tie one name to a watched brand, or return ``None``."""

        try:
            name = normalize(raw_name)
        except InvalidDomainNameError:
            return None

        parts = split(name.ascii_name)
        registrable = parts.registrable_domain
        if registrable is None or self._is_excluded(registrable):
            return None

        candidate = self._candidates.get(registrable) or self._candidates.get(name.ascii_name)
        if candidate is not None:
            target = self._targets[candidate.target_id]
            return Match(
                name=name,
                target=target,
                tier=MatchTier.CANDIDATE,
                detail=candidate.detail,
                kind=candidate.kind,
            )

        # Read from the displayed form: the punycode spelling of a disguised
        # name shares no characters with what a victim actually sees.
        readable = to_unicode_label(parts.registrable_label)

        target_id = self._skeletons.get(skeleton(readable))
        if target_id is not None:
            target = self._targets[target_id]
            watched_label = split(target.canonical_domain).registrable_label
            return Match(
                name=name,
                target=target,
                tier=MatchTier.LOOKALIKE,
                detail=f"reads as {watched_label!r} without appearing in any candidate list",
            )

        for label, owner in self._labels.items():
            if label in readable:
                target = self._targets[owner]
                return Match(
                    name=name,
                    target=target,
                    tier=MatchTier.CONTAINS,
                    detail=f"contains the watched name {label!r}",
                )

        return None

    def match_all(self, names: Iterable[str]) -> list[Match]:
        """Match every name on one certificate, keeping each name once."""

        seen: set[str] = set()
        matches: list[Match] = []
        for raw in names:
            match = self.match(raw)
            if match is None or match.name.ascii_name in seen:
                continue
            seen.add(match.name.ascii_name)
            matches.append(match)
        return matches
