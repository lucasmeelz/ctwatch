"""Generating the names an impersonator is likely to have registered.

This is the part that decides what the tool can find. Certificate Transparency
search is a substring match over names as they are stored, which means a
lookalike registered with a Cyrillic character is invisible to any query built
from the original brand name. Candidates are therefore generated first and
each one is looked up; substring search is a complement, never the entry point.

Every candidate carries the technique that produced it and a short explanation,
so a finding can be read as "one character removed from lemonde.fr" rather than
as a number with no provenance.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ctwatch.names import InvalidDomainNameError, normalize
from ctwatch.permutations.homoglyph import HomoglyphGenerator
from ctwatch.permutations.keyboards import DEFAULT_LAYOUTS, keyboard_neighbours
from ctwatch.permutations.model import Candidate, Permutation, PermutationKind
from ctwatch.publicsuffix import split

LABEL_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
VOWELS = "aeiou"
MAX_LABEL_LENGTH = 63

# Where impersonating registrations actually land: cheap or unrestricted
# generic suffixes, plus the ones that read as news or as a country.
DEFAULT_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "info",
    "news",
    "press",
    "media",
    "live",
    "online",
    "site",
    "website",
    "click",
    "link",
    "shop",
    "store",
    "top",
    "xyz",
    "icu",
    "sbs",
    "cfd",
    "co",
    "io",
    "eu",
    "fr",
    "be",
    "ch",
    "app",
    "blog",
)

# Suffix-merge variants are combined with a deliberately short list: the point
# is to catch lemondefr.com, not to multiply every merge by thirty suffixes.
MERGE_TLDS: tuple[str, ...] = ("com", "net", "org", "info")


# Emission order, most plausible first, so that `--limit` keeps what matters.
KIND_ORDER: tuple[PermutationKind, ...] = (
    PermutationKind.HOMOGLYPH,
    PermutationKind.REPLACEMENT,
    PermutationKind.OMISSION,
    PermutationKind.TRANSPOSITION,
    PermutationKind.REPETITION,
    PermutationKind.INSERTION,
    PermutationKind.HYPHENATION,
    PermutationKind.VOWEL_SWAP,
    PermutationKind.KEYWORD,
    PermutationKind.BITSQUAT,
    PermutationKind.SUFFIX_MERGE,
    PermutationKind.TLD_SWAP,
)


def is_valid_label(label: str) -> bool:
    if not 0 < len(label) <= MAX_LABEL_LENGTH:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return set(label) <= LABEL_CHARACTERS


def _omissions(label: str) -> Iterator[Candidate]:
    for index, character in enumerate(label):
        yield Candidate(
            label=label[:index] + label[index + 1 :],
            kind=PermutationKind.OMISSION,
            detail=f"dropped {character!r} at position {index + 1}",
        )


def _repetitions(label: str) -> Iterator[Candidate]:
    for index, character in enumerate(label):
        yield Candidate(
            label=label[:index] + character + label[index:],
            kind=PermutationKind.REPETITION,
            detail=f"doubled {character!r} at position {index + 1}",
        )


def _transpositions(label: str) -> Iterator[Candidate]:
    for index in range(len(label) - 1):
        first, second = label[index], label[index + 1]
        if first == second:
            continue
        yield Candidate(
            label=label[:index] + second + first + label[index + 2 :],
            kind=PermutationKind.TRANSPOSITION,
            detail=f"swapped {first!r} and {second!r} at position {index + 1}",
        )


def _replacements(label: str, layouts: tuple[str, ...]) -> Iterator[Candidate]:
    for index, character in enumerate(label):
        for neighbour in sorted(keyboard_neighbours(character, layouts)):
            yield Candidate(
                label=label[:index] + neighbour + label[index + 1 :],
                kind=PermutationKind.REPLACEMENT,
                detail=f"{character!r} mistyped as {neighbour!r} at position {index + 1}",
            )


def _insertions(label: str, layouts: tuple[str, ...]) -> Iterator[Candidate]:
    for index, character in enumerate(label):
        for neighbour in sorted(keyboard_neighbours(character, layouts)):
            yield Candidate(
                label=label[:index] + neighbour + label[index:],
                kind=PermutationKind.INSERTION,
                detail=f"{neighbour!r} typed before {character!r} at position {index + 1}",
            )
            yield Candidate(
                label=label[: index + 1] + neighbour + label[index + 1 :],
                kind=PermutationKind.INSERTION,
                detail=f"{neighbour!r} typed after {character!r} at position {index + 1}",
            )


def _hyphenations(label: str) -> Iterator[Candidate]:
    for index in range(1, len(label)):
        # A hyphen next to an existing one produces legal but implausible
        # names; skipping them keeps the candidate list worth reading.
        if label[index - 1] == "-" or label[index] == "-":
            continue
        yield Candidate(
            label=label[:index] + "-" + label[index:],
            kind=PermutationKind.HYPHENATION,
            detail=f"hyphen inserted at position {index + 1}",
        )


def _vowel_swaps(label: str) -> Iterator[Candidate]:
    for index, character in enumerate(label):
        if character not in VOWELS:
            continue
        for vowel in VOWELS:
            if vowel == character:
                continue
            yield Candidate(
                label=label[:index] + vowel + label[index + 1 :],
                kind=PermutationKind.VOWEL_SWAP,
                detail=f"{character!r} replaced by {vowel!r} at position {index + 1}",
            )


def _bitsquats(label: str) -> Iterator[Candidate]:
    """Names one flipped bit away, which faulty memory and hardware produce."""

    for index, character in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(character) ^ (1 << bit))
            if flipped == character or flipped not in LABEL_CHARACTERS:
                continue
            yield Candidate(
                label=label[:index] + flipped + label[index + 1 :],
                kind=PermutationKind.BITSQUAT,
                detail=f"bit {bit} of {character!r} flipped to {flipped!r} at position {index + 1}",
            )


def _suffix_merges(label: str, suffix: str, merge_tlds: Iterable[str]) -> Iterator[Candidate]:
    """Fold the suffix into the name, as in lemondefr.com."""

    flattened = suffix.replace(".", "")
    for merged in (f"{label}{flattened}", f"{label}-{flattened}"):
        for tld in merge_tlds:
            if tld == suffix:
                continue
            yield Candidate(
                label=merged,
                kind=PermutationKind.SUFFIX_MERGE,
                detail=f"{suffix!r} folded into the name, registered under {tld!r}",
                suffix=tld,
            )


def _tld_swaps(label: str, suffix: str, tlds: Iterable[str]) -> Iterator[Candidate]:
    for tld in tlds:
        if tld == suffix:
            continue
        yield Candidate(
            label=label,
            kind=PermutationKind.TLD_SWAP,
            detail=f"same name registered under {tld!r} instead of {suffix!r}",
            suffix=tld,
        )


class PermutationGenerator:
    """Turns one watched domain into the candidates worth looking up."""

    def __init__(
        self,
        *,
        layouts: tuple[str, ...] = DEFAULT_LAYOUTS,
        extra_tlds: Iterable[str] = (),
        merge_tlds: Iterable[str] = MERGE_TLDS,
        kinds: Iterable[PermutationKind] | None = None,
        homoglyphs: HomoglyphGenerator | None = None,
    ) -> None:
        self._layouts = layouts
        self._homoglyphs = homoglyphs or HomoglyphGenerator()
        self._tlds = tuple(dict.fromkeys([*DEFAULT_TLDS, *(t.strip().lower() for t in extra_tlds)]))
        self._merge_tlds = tuple(merge_tlds)
        self._kinds = frozenset(kinds) if kinds is not None else frozenset(PermutationKind)

    @property
    def kinds(self) -> frozenset[PermutationKind]:
        return self._kinds

    def _candidates(self, label: str, suffix: str) -> Iterator[Candidate]:
        by_kind: dict[PermutationKind, Iterator[Candidate]] = {
            PermutationKind.REPLACEMENT: _replacements(label, self._layouts),
            PermutationKind.OMISSION: _omissions(label),
            PermutationKind.TRANSPOSITION: _transpositions(label),
            PermutationKind.REPETITION: _repetitions(label),
            PermutationKind.INSERTION: _insertions(label, self._layouts),
            PermutationKind.HYPHENATION: _hyphenations(label),
            PermutationKind.VOWEL_SWAP: _vowel_swaps(label),
            PermutationKind.BITSQUAT: _bitsquats(label),
            PermutationKind.SUFFIX_MERGE: _suffix_merges(label, suffix, self._merge_tlds),
            PermutationKind.TLD_SWAP: _tld_swaps(label, suffix, self._tlds),
        }
        for kind in KIND_ORDER:
            stream = by_kind.get(kind)
            if stream is None or kind not in self._kinds:
                continue
            yield from stream

    def generate(self, domain: str, *, limit: int | None = None) -> Iterator[Permutation]:
        """Yield candidate names derived from ``domain``, most plausible first.

        A subdomain in the input is ignored: watching ``www.lemonde.fr`` and
        watching ``lemonde.fr`` are the same request. A name reachable by more
        than one technique is attributed to the first one that produces it,
        which is the most plausible one given the emission order.
        """

        parts = split(domain)
        if parts.registrable_domain is None:
            msg = (
                f"{domain!r} has no registrable part to mutate; "
                "it is a public suffix, not a domain someone owns"
            )
            raise ValueError(msg)

        base = parts.registrable_domain
        seen: set[str] = {base}
        emitted = 0

        if PermutationKind.HOMOGLYPH in self._kinds:
            for permutation in self._homoglyphs.variants(domain):
                if permutation.name.ascii_name in seen:
                    continue
                seen.add(permutation.name.ascii_name)
                yield permutation
                emitted += 1
                if limit is not None and emitted >= limit:
                    return

        for candidate in self._candidates(parts.registrable_label, parts.suffix):
            if not is_valid_label(candidate.label):
                continue

            full = f"{candidate.label}.{candidate.suffix or parts.suffix}"
            if full in seen:
                continue
            try:
                name = normalize(full)
            except InvalidDomainNameError:
                continue
            if name.ascii_name in seen:
                continue

            seen.add(full)
            seen.add(name.ascii_name)
            yield Permutation(name=name, kind=candidate.kind, detail=candidate.detail, base=base)

            emitted += 1
            if limit is not None and emitted >= limit:
                return
