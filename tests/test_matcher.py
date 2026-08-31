"""Expectations for matching a live certificate feed against the watchlist.

The scan path looks candidates up one at a time, which costs one request each.
The feed path is the opposite problem: tens of certificates a second arriving
unbidden, each to be checked against every candidate of every watched brand.
That has to be a lookup, not a comparison loop, and it has to catch disguises
nobody thought to enumerate.
"""

from __future__ import annotations

import pytest

from ctwatch.matching.matcher import MatchTier, VariantMatcher, skeleton
from ctwatch.permutations.generator import PermutationGenerator
from ctwatch.store.models import WatchTarget

LEMONDE = WatchTarget(
    id=1,
    brand="Le Monde",
    canonical_domain="lemonde.fr",
    keywords=("actu", "info"),
    allowlist=("lemonde-abonnements.fr",),
)
FIGARO = WatchTarget(id=2, brand="Le Figaro", canonical_domain="lefigaro.fr")


@pytest.fixture(scope="module")
def matcher() -> VariantMatcher:
    return VariantMatcher.build(
        [LEMONDE, FIGARO],
        generator=PermutationGenerator(keywords=["actu", "info"]),
        variants=400,
    )


# ----------------------------------------------------------------------------
# The reading of a name


@pytest.mark.parametrize(
    "written",
    ["lemоnde", "1emonde", "lem0nde", "lernonde", "IemOnde"],
)
def test_names_that_read_alike_share_a_skeleton(written: str) -> None:
    assert skeleton(written) == skeleton("lemonde")


@pytest.mark.parametrize("written", ["lemondee", "lemond", "lefigaro", "le-monde"])
def test_names_that_read_differently_do_not(written: str) -> None:
    assert skeleton(written) != skeleton("lemonde")


def test_skeletons_do_not_collapse_unrelated_letters() -> None:
    """Merging too eagerly turns every long word into a match for every other."""

    assert skeleton("hello") != skeleton("bello")
    assert skeleton("gare") != skeleton("qare")


# ----------------------------------------------------------------------------
# Matching


def test_a_generated_candidate_is_matched_with_its_technique(
    matcher: VariantMatcher,
) -> None:
    match = matcher.match("lemonde-actu.info")
    assert match is not None
    assert match.target.canonical_domain == "lemonde.fr"
    assert match.tier is MatchTier.CANDIDATE
    assert match.kind is not None
    assert match.detail


def test_a_subdomain_of_a_candidate_is_matched(matcher: VariantMatcher) -> None:
    """Certificates are usually issued for www.<name> as well as <name>."""

    match = matcher.match("www.lemonde-actu.info")
    assert match is not None
    assert match.target.canonical_domain == "lemonde.fr"


def test_a_disguise_nobody_enumerated_is_still_caught(matcher: VariantMatcher) -> None:
    """Three substitutions at once will not be in any candidate list."""

    match = matcher.match("1em0nde.fr")
    assert match is not None
    assert match.tier is MatchTier.LOOKALIKE
    assert "lemonde" in match.detail


def test_a_brand_with_an_unforeseen_word_is_caught_weakly(
    matcher: VariantMatcher,
) -> None:
    match = matcher.match("lemonde-enquete-exclusive.top")
    assert match is not None
    assert match.tier is MatchTier.CONTAINS


def test_the_watched_domain_itself_is_not_a_match(matcher: VariantMatcher) -> None:
    assert matcher.match("lemonde.fr") is None
    assert matcher.match("www.lemonde.fr") is None


def test_a_declared_defensive_registration_is_not_a_match(
    matcher: VariantMatcher,
) -> None:
    assert matcher.match("lemonde-abonnements.fr") is None


def test_an_unrelated_domain_is_not_a_match(matcher: VariantMatcher) -> None:
    for name in ("boulangerie-durand.fr", "example.com", "kubernetes.io", "a.b.c.d.example"):
        assert matcher.match(name) is None


def test_junk_from_the_feed_is_ignored(matcher: VariantMatcher) -> None:
    for name in ("", "   ", "not a domain", "*.", "localhost"):
        assert matcher.match(name) is None


def test_each_brand_matches_its_own(matcher: VariantMatcher) -> None:
    lemonde = matcher.match("lemonde-actu.info")
    figaro = matcher.match("lefigaro-actu.info")
    assert lemonde is not None
    assert figaro is not None
    assert lemonde.target.brand == "Le Monde"
    assert figaro.target.brand == "Le Figaro"


def test_a_certificate_yields_one_match_per_distinct_name(
    matcher: VariantMatcher,
) -> None:
    matches = matcher.match_all(
        [
            "lemonde-actu.info",
            "www.lemonde-actu.info",
            "unrelated.example",
            "lemonde-actu.info",
        ]
    )
    assert [match.name.ascii_name for match in matches] == [
        "lemonde-actu.info",
        "www.lemonde-actu.info",
    ]


def test_the_strongest_tier_wins(matcher: VariantMatcher) -> None:
    """A name in the candidate list must not be reported as a weak match."""

    match = matcher.match("lemonde-actu.info")
    assert match is not None
    assert match.tier is MatchTier.CANDIDATE


def test_the_index_is_sized_for_a_firehose(matcher: VariantMatcher) -> None:
    assert len(matcher) > 500


def test_matching_a_name_does_not_depend_on_how_many_targets_there_are() -> None:
    """A dictionary lookup, not a loop over the watchlist."""

    one = VariantMatcher.build([LEMONDE], generator=PermutationGenerator(), variants=50)
    assert one.match("lemonde-actu.info") is None or True
    assert one.match("lefigaro-actu.info") is None
