"""The individual signals a suspicion score is built from.

Each rule returns a value between zero and one together with the sentence that
explains it. Nothing here returns a bare number: a finding that cannot be
justified in plain language is of no use to the person who has to decide
whether to publish.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from functools import lru_cache

from ctwatch.config import ScoringConfig
from ctwatch.names import DomainName
from ctwatch.permutations.homoglyph import ASCII_LOOKALIKES, load_confusables
from ctwatch.publicsuffix import split
from ctwatch.timeutil import utc_now

# A certificate issued within this window is treated as brand new.
FRESH_WINDOW = timedelta(days=7)
# Beyond this, issuance date says nothing useful about an ongoing operation.
STALE_WINDOW = timedelta(days=365)

CONTAINS_NAME_ONLY = 0.4

# Past this share of genuinely different characters, two names are simply two
# names. Without the gate, any long pair of unrelated words shares an accidental
# lookalike or two and picks up a score it has not earned.
LOOKALIKE_RELEVANCE_LIMIT = 0.34


def levenshtein(left: str, right: str) -> int:
    """Plain edit distance, with no allowance for characters that look alike."""

    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, left_character in enumerate(left, start=1):
        current = [i]
        for j, right_character in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (left_character != right_character),
                )
            )
        previous = current
    return previous[-1]


@lru_cache(maxsize=1)
def _single_character_lookalikes() -> frozenset[tuple[str, str]]:
    """Unordered pairs of characters a reader would not tell apart."""

    pairs: set[tuple[str, str]] = set()

    table = load_confusables()
    for target in table.targets():
        for confusable in table.substitutes(target):
            pairs.add((target, confusable.character))
            pairs.add((confusable.character, target))

    for fragment, replacements in ASCII_LOOKALIKES.items():
        if len(fragment) != 1:
            continue
        for replacement in replacements:
            if len(replacement) == 1:
                pairs.add((fragment, replacement))
                pairs.add((replacement, fragment))

    return frozenset(pairs)


@lru_cache(maxsize=1)
def _sequence_lookalikes() -> frozenset[tuple[str, str]]:
    """Pairs where one side is two characters standing in for one: rn for m."""

    pairs: set[tuple[str, str]] = set()
    for fragment, replacements in ASCII_LOOKALIKES.items():
        for replacement in replacements:
            if len(fragment) == 1 and len(replacement) == 2:
                pairs.add((replacement, fragment))
            elif len(fragment) == 2 and len(replacement) == 1:
                pairs.add((fragment, replacement))
    return frozenset(pairs)


def reads_alike(left: str, right: str) -> bool:
    return left == right or (left, right) in _single_character_lookalikes()


def confusable_distance(left: str, right: str) -> int:
    """Edit distance where a substitution nobody would notice is free.

    ``lemоnde`` written with a Cyrillic "о" is at distance zero from
    ``lemonde``: the two are different registrations that no reader can tell
    apart. ``lemondee`` is at distance one, because the extra letter is
    visible. That difference is what separates a disguise from a typo.
    """

    sequences = _sequence_lookalikes()
    rows, columns = len(left), len(right)

    # Full matrix rather than two rows: the two-for-one substitutions need to
    # reach back further than the previous line.
    distance = [[0] * (columns + 1) for _ in range(rows + 1)]
    for i in range(rows + 1):
        distance[i][0] = i
    for j in range(columns + 1):
        distance[0][j] = j

    for i in range(1, rows + 1):
        for j in range(1, columns + 1):
            substitution = 0 if reads_alike(left[i - 1], right[j - 1]) else 1
            best = min(
                distance[i - 1][j] + 1,
                distance[i][j - 1] + 1,
                distance[i - 1][j - 1] + substitution,
            )
            if i >= 2 and (left[i - 2 : i], right[j - 1]) in sequences:
                best = min(best, distance[i - 2][j - 1])
            if j >= 2 and (right[j - 2 : j], left[i - 1]) in sequences:
                best = min(best, distance[i - 1][j - 2])
            distance[i][j] = best

    return distance[rows][columns]


def lookalike_signal(candidate: str, reference: str) -> tuple[float, str]:
    """How much of the difference between two names is invisible to a reader."""

    plain = levenshtein(candidate, reference)
    if plain == 0:
        return 0.0, "identical to the watched name"

    disguised = confusable_distance(candidate, reference)
    longest = max(len(candidate), len(reference), 1)
    if disguised / longest > LOOKALIKE_RELEVANCE_LIMIT:
        return 0.0, f"too different from {reference!r} to be a disguise of it"

    hidden = (plain - disguised) / plain

    if hidden <= 0:
        return 0.0, "every difference from the watched name is visible"
    if disguised == 0:
        return 1.0, f"reads exactly as {reference!r} but is a different registration"
    return (
        hidden,
        f"{plain - disguised} of {plain} character difference(s) from {reference!r} "
        "would not be noticed by a reader",
    )


def name_similarity_signal(candidate: str, reference: str) -> tuple[float, str]:
    """Closeness as an edit distance, which is what catches ordinary typos."""

    longest = max(len(candidate), len(reference))
    if longest == 0:
        return 0.0, "nothing to compare"

    distance = levenshtein(candidate, reference)
    value = max(0.0, 1.0 - distance / longest)
    if distance == 0:
        return value, f"identical to {reference!r}"
    return (
        value,
        f"{distance} character edit(s) away from {reference!r}",
    )


def tld_risk_signal(name: DomainName, config: ScoringConfig) -> tuple[float, str]:
    """How much the suffix itself says about intent."""

    parts = split(name.ascii_name)
    if parts.is_private_suffix:
        return (
            1.0,
            f"hosted under {parts.suffix!r}, where subdomains are handed out freely",
        )

    tld = parts.tld
    if tld in config.tld_risk.high:
        return 1.0, f"{tld!r} is on the high-risk suffix list"
    if tld in config.tld_risk.medium:
        return 0.5, f"{tld!r} is on the medium-risk suffix list"
    return 0.0, f"{tld!r} is not on a risk list"


def certificate_age_signal(
    not_before: datetime | None, *, now: datetime | None = None
) -> tuple[float, str]:
    """Recent issuance is the signal worth waking up for.

    A certificate minted hours ago for a name resembling a newsroom is an
    operation being set up. One issued three years ago rarely is.
    """

    if not_before is None:
        return 0.0, "no certificate issuance date recorded"

    moment = now or utc_now()
    age = moment - not_before
    if age < timedelta(0):
        return 1.0, "certificate is not valid yet, which means it was just issued"
    if age <= FRESH_WINDOW:
        return 1.0, f"certificate issued {age.days} day(s) ago"
    if age >= STALE_WINDOW:
        return 0.0, f"certificate issued {age.days} day(s) ago, too long to be a signal"

    span = (STALE_WINDOW - FRESH_WINDOW).total_seconds()
    value = 1.0 - (age - FRESH_WINDOW).total_seconds() / span
    return value, f"certificate issued {age.days} day(s) ago"


def keyword_signal(
    candidate_label: str, reference_label: str, keywords: tuple[str, ...] | list[str]
) -> tuple[float, str]:
    """The brand plus a word that makes it sound like a publication."""

    if reference_label not in candidate_label:
        return 0.0, f"does not contain {reference_label!r}"

    found = [
        word
        for word in keywords
        if word and word in candidate_label.replace(reference_label, "", 1)
    ]
    if found:
        listed = ", ".join(repr(word) for word in found)
        return 1.0, f"contains {reference_label!r} together with {listed}"

    return CONTAINS_NAME_ONLY, f"contains {reference_label!r} but no watched keyword"
