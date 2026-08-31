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

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from ctwatch.config import DEFAULT_HIGH_RISK_TLDS
from ctwatch.names import DomainName, InvalidDomainNameError, normalize, to_unicode_label
from ctwatch.permutations.generator import PermutationGenerator
from ctwatch.permutations.homoglyph import load_confusables
from ctwatch.permutations.model import PermutationKind
from ctwatch.publicsuffix import split
from ctwatch.store.models import WatchTarget

# Shortest watched label that may be looked for inside a longer name. Below
# this, the weak tier matches half the internet.
MINIMUM_CONTAINED_LENGTH = 5

# Shortest watched label worth checking for a single-character slip. Below it,
# one edit away is most of the dictionary.
MINIMUM_TYPO_LENGTH = 6

# Content delivery and edge providers put the customer's full domain in front
# of their own: www.lemonde.fr.edgekey.net is Akamai serving Le Monde, not an
# impersonation of it. The list is short and certainly incomplete, which is why
# a match here is dropped rather than downgraded — a missed lookalike on a CDN
# is recoverable, a report accusing Akamai is not.
DELIVERY_SUFFIXES: frozenset[str] = frozenset(
    {
        "edgekey.net",
        "edgesuite.net",
        "akamaiedge.net",
        "akamaized.net",
        "cloudfront.net",
        "fastly.net",
        "fastlylb.net",
        "azureedge.net",
        "cloudflare.net",
        "cdn77.org",
        "stackpathdns.com",
        "b-cdn.net",
        "hwcdn.net",
        "llnwd.net",
    }
)

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
    TYPO = "typo"
    BRAND_IN_SUBDOMAIN = "brand_in_subdomain"
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


def _strip_diacritics(label: str) -> str:
    """Drop combining accents, so lemondé reads as lemonde.

    Unicode records é as confusable with e only in some of its forms, and a
    French-language watchlist cannot afford to miss the rest: an accent is the
    cheapest lookalike there is, and it costs nothing to register.
    """

    decomposed = unicodedata.normalize("NFKD", label)
    return "".join(character for character in decomposed if not unicodedata.combining(character))


def skeleton(label: str) -> str:
    """The form a label takes once everything that reads alike is folded.

    Two names with the same skeleton are two names a reader would not tell
    apart, whether or not anyone generated one from the other.
    """

    folded = _fold_map()
    mapped = "".join(
        folded.get(character, character) for character in _strip_diacritics(label.strip().lower())
    )

    for sequence, replacement in SEQUENCE_FOLDS:
        mapped = mapped.replace(sequence, replacement)

    # Folding a sequence can expose a character that still needs folding.
    return "".join(folded.get(character, character) for character in mapped)


def _is_standalone_name(label: str, suffix: str) -> bool:
    """Does this label identify the brand without its suffix?

    ``lemonde`` does. ``sante`` does not — it identifies the health ministry
    only in combination with ``gouv.fr``, and on its own it is the word every
    French site uses for its health section. A multi-label public suffix is a
    reliable sign of a name living inside somebody's namespace.
    """

    return "." not in suffix and len(label) >= MINIMUM_TYPO_LENGTH


def _deletions(label: str) -> set[str]:
    """Every string one deletion away, including the label itself.

    Two labels within one edit of each other — a substitution, an insertion, a
    deletion, or a swap of neighbours — always share one of these. Indexing them
    turns "is this a typo of a watched name" into a dictionary lookup, which is
    what the live feed needs, and it works regardless of the suffix: lefigar.com
    is a slip for lefigaro.fr even though nothing about the two suffixes match.
    """

    return {label} | {label[:index] + label[index + 1 :] for index in range(len(label))}


def _at_token_boundary(haystack: str, needle: str) -> bool:
    """Is ``needle`` a whole word of ``haystack``, not a fragment of one?

    ``lemonde-actu`` carries the brand; ``lemondeduvin`` carries three French
    words that happen to begin with the same letters.
    """

    separators = "-_."
    start = haystack.find(needle)
    while start != -1:
        before = haystack[start - 1] if start else ""
        after_index = start + len(needle)
        after = haystack[after_index] if after_index < len(haystack) else ""
        if (not before or before in separators) and (not after or after in separators):
            return True
        start = haystack.find(needle, start + 1)
    return False


def _fused_with_keyword(haystack: str, label: str, keywords: tuple[str, ...]) -> bool:
    """Is the brand run straight into a watched word, with no separator?

    ``lemondeinfo`` reads as the brand plus a section name; ``lemondeduvin`` is
    three ordinary French words. Requiring the remainder to be a watched keyword
    is what tells them apart.
    """

    index = haystack.find(label)
    if index == -1:
        return False
    remainder = haystack[:index] + haystack[index + len(label) :]
    return any(word and len(word) >= 3 and remainder in (word, "") for word in keywords)


def _has_keyword(haystack: str, label: str, keywords: tuple[str, ...]) -> bool:
    remainder = haystack.replace(label, " ", 1)
    return any(word and len(word) >= 3 and word in remainder for word in keywords)


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
        standalone: dict[str, int],
        risky_suffixes: frozenset[str],
        registrables: dict[tuple[str, ...], int],
        near_labels: dict[str, int],
        excluded: set[str],
    ) -> None:
        self._targets = {target.id: target for target in targets}
        self._candidates = candidates
        self._skeletons = skeletons
        self._labels = labels
        self._standalone = standalone
        self._risky_suffixes = risky_suffixes
        self._registrables = registrables
        self._near_labels = near_labels
        self._excluded = excluded

    @classmethod
    def build(
        cls,
        targets: Iterable[WatchTarget],
        *,
        generator: PermutationGenerator | None = None,
        variants: int = 500,
        risky_suffixes: Iterable[str] = DEFAULT_HIGH_RISK_TLDS,
    ) -> VariantMatcher:
        """Generate every candidate once, then index it."""

        watched = list(targets)
        candidates: dict[str, _Candidate] = {}
        skeletons: dict[str, int] = {}
        labels: dict[str, int] = {}
        standalone: dict[str, int] = {}
        registrables: dict[tuple[str, ...], int] = {}
        near_labels: dict[str, int] = {}
        excluded: set[str] = set()

        for target in watched:
            parts = split(target.canonical_domain)
            label = parts.registrable_label
            if label:
                skeletons.setdefault(skeleton(label), target.id)
                if len(label) >= MINIMUM_CONTAINED_LENGTH:
                    labels.setdefault(label, target.id)
                    if _is_standalone_name(label, parts.suffix):
                        standalone.setdefault(label, target.id)
                if len(label) >= MINIMUM_TYPO_LENGTH:
                    for shortened in _deletions(skeleton(label)):
                        near_labels.setdefault(shortened, target.id)
            if parts.registrable_domain:
                registrables.setdefault(tuple(parts.registrable_domain.split(".")), target.id)

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
            standalone=standalone,
            risky_suffixes=frozenset(risky_suffixes),
            registrables=registrables,
            near_labels=near_labels,
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

        if len(readable) >= MINIMUM_TYPO_LENGTH:
            reduced = skeleton(readable)
            for shortened in _deletions(reduced):
                owner = self._near_labels.get(shortened)
                if owner is None:
                    continue
                target = self._targets[owner]
                watched_label = split(target.canonical_domain).registrable_label
                if reduced == skeleton(watched_label):
                    continue
                return Match(
                    name=name,
                    target=target,
                    tier=MatchTier.TYPO,
                    detail=f"one character away from {watched_label!r}",
                )

        carried = self._brand_in_subdomain(name, parts.subdomain, registrable)
        if carried is not None:
            return carried

        for label, owner in self._labels.items():
            if label not in readable:
                continue
            target = self._targets[owner]
            if not _at_token_boundary(readable, label) and not _fused_with_keyword(
                readable, label, target.keywords
            ):
                continue

            # A brand whose name is an ordinary word — Libération, Le Monde —
            # turns up inside prose: lemondeduvin.com, animal-liberation.org,
            # tax-liberation.co.uk. Containment on its own cannot tell those
            # from lemonde-actu.info. What can is the company the name keeps: a
            # word the brand is known by, or a suffix nobody registers a
            # brewery under.
            reason = ""
            if _has_keyword(readable, label, target.keywords):
                reason = "alongside a watched keyword"
            elif parts.tld in self._risky_suffixes:
                reason = f"under {parts.tld!r}, a suffix on the high-risk list"
            if not reason:
                continue

            return Match(
                name=name,
                target=target,
                tier=MatchTier.CONTAINS,
                detail=f"contains the watched name {label!r} {reason}",
            )

        return None

    def _brand_in_subdomain(
        self, name: DomainName, subdomain: str, registrable: str
    ) -> Match | None:
        """The watched name carried inside somebody else's registration.

        ``lemonde.fr.paiement-secure.net`` is registered by whoever owns
        paiement-secure.net, and every character a victim reads before the
        first slash says Le Monde. No criterion that looks only at the
        registered label can see it.
        """

        if not subdomain:
            return None

        labels = tuple(subdomain.split("."))
        delivery = registrable in DELIVERY_SUFFIXES

        for watched, owner in self._registrables.items():
            width = len(watched)
            if any(labels[i : i + width] == watched for i in range(len(labels) - width + 1)):
                if delivery:
                    # <customer domain>.edgekey.net is the customer's own
                    # delivery, not an impersonation of them.
                    return None
                target = self._targets[owner]
                return Match(
                    name=name,
                    target=target,
                    tier=MatchTier.BRAND_IN_SUBDOMAIN,
                    detail=(
                        f"carries {'.'.join(watched)} inside a subdomain of "
                        f"{registrable}, which somebody else registered"
                    ),
                )

        for label, owner in self._labels.items():
            target = self._targets[owner]
            carrier = next((part for part in labels if _at_token_boundary(part, label)), None)
            if carrier is None:
                continue
            if label not in self._standalone and not _has_keyword(carrier, label, target.keywords):
                # A label under a namespaced suffix is a department, not a
                # brand: sante.gouv.fr identifies the ministry only together
                # with gouv.fr, and `sante` on its own is what any magazine
                # calls its health section. Such a label needs a watched
                # keyword beside it before it means anything.
                continue
            return Match(
                name=name,
                target=target,
                tier=MatchTier.BRAND_IN_SUBDOMAIN,
                detail=(
                    f"carries the watched name {label!r} inside a subdomain of "
                    f"{registrable}, which somebody else registered"
                ),
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
