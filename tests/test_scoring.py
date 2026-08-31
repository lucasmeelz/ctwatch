"""Expectations for the suspicion score.

Written before the implementation. A score that cannot be explained is worth
nothing to a journalist who has to justify a publication, so the requirement
pinned here is not just "the number is higher for suspicious names" but that
every point of it is attributable to a named criterion with a sentence
attached.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ctwatch.config import ScoringConfig
from ctwatch.matching.rules import (
    certificate_age_signal,
    confusable_distance,
    keyword_signal,
    levenshtein,
    lookalike_signal,
    tld_risk_signal,
)
from ctwatch.matching.scoring import Scorer, Subject
from ctwatch.names import normalize
from ctwatch.store.models import WatchTarget

NOW = datetime(2026, 3, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
def target() -> WatchTarget:
    return WatchTarget(
        id=1,
        brand="Le Monde",
        canonical_domain="lemonde.fr",
        keywords=("actu", "info", "news"),
    )


@pytest.fixture
def scorer() -> Scorer:
    return Scorer(ScoringConfig())


def score(scorer: Scorer, target: WatchTarget, domain: str, **kwargs: object) -> object:
    return scorer.score(Subject(name=normalize(domain), **kwargs), target=target, now=NOW)  # type: ignore[arg-type]


# ----------------------------------------------------------------------------
# Edit distance


@pytest.mark.parametrize(
    ("left", "right", "distance"),
    [
        ("lemonde", "lemonde", 0),
        ("lemonde", "lemondе", 1),
        ("lemonde", "lemond", 1),
        ("lemonde", "elmonde", 2),
        ("lemonde", "lefigaro", 6),
        ("", "abc", 3),
    ],
)
def test_levenshtein(left: str, right: str, distance: int) -> None:
    assert levenshtein(left, right) == distance
    assert levenshtein(right, left) == distance


# ----------------------------------------------------------------------------
# Lookalike distance: the difference a reader would not see


@pytest.mark.parametrize(
    "written",
    [
        "lemоnde",  # Cyrillic o
        "1emonde",  # digit one for l
        "lernonde",  # rn for m
        "lem0nde",  # zero for o
    ],
)
def test_a_name_that_reads_the_same_has_no_lookalike_distance(written: str) -> None:
    assert confusable_distance(written, "lemonde") == 0
    assert levenshtein(written, "lemonde") > 0


def test_a_genuine_typo_keeps_its_distance() -> None:
    assert confusable_distance("lemondee", "lemonde") == 1
    assert confusable_distance("lefigaro", "lemonde") > 1


def test_lookalike_signal_separates_disguise_from_typo() -> None:
    disguised, explanation = lookalike_signal("lemоnde", "lemonde")
    assert disguised == pytest.approx(1.0)
    assert explanation

    typo, _ = lookalike_signal("lemondee", "lemonde")
    assert typo == pytest.approx(0.0)


def test_lookalike_signal_is_zero_for_an_unrelated_name() -> None:
    value, _ = lookalike_signal("boulangerie", "lemonde")
    assert value == pytest.approx(0.0)


# ----------------------------------------------------------------------------
# Individual criteria


def test_tld_risk_follows_the_configuration() -> None:
    config = ScoringConfig()
    high, explanation = tld_risk_signal(normalize("lemonde-actu.info"), config)
    medium, _ = tld_risk_signal(normalize("lemonde-actu.net"), config)
    low, _ = tld_risk_signal(normalize("lemonde-actu.fr"), config)

    assert high > medium > low
    assert low == pytest.approx(0.0)
    assert "info" in explanation


def test_a_free_subdomain_host_counts_as_high_risk() -> None:
    value, explanation = tld_risk_signal(normalize("lemonde-actu.github.io"), ScoringConfig())
    assert value == pytest.approx(1.0)
    assert "github.io" in explanation


def test_certificate_age_rewards_recent_issuance() -> None:
    fresh, explanation = certificate_age_signal(NOW - timedelta(hours=6), now=NOW)
    recent, _ = certificate_age_signal(NOW - timedelta(days=30), now=NOW)
    old, _ = certificate_age_signal(NOW - timedelta(days=900), now=NOW)

    assert fresh == pytest.approx(1.0)
    assert 0.0 < recent < 1.0
    assert old == pytest.approx(0.0)
    assert explanation


def test_certificate_age_without_a_date_is_neutral_and_says_so() -> None:
    value, explanation = certificate_age_signal(None, now=NOW)
    assert value == pytest.approx(0.0)
    assert "no" in explanation.lower()


def test_keyword_signal_needs_both_the_name_and_a_keyword() -> None:
    both, explanation = keyword_signal("lemonde-actu", "lemonde", ("actu", "info"))
    name_only, _ = keyword_signal("lemondex", "lemonde", ("actu",))
    neither, _ = keyword_signal("boulangerie", "lemonde", ("actu",))

    assert both == pytest.approx(1.0)
    assert 0.0 < name_only < 1.0
    assert neither == pytest.approx(0.0)
    assert "actu" in explanation


# ----------------------------------------------------------------------------
# The composite score


def test_score_is_bounded_and_deterministic(scorer: Scorer, target: WatchTarget) -> None:
    for domain in ("lemonde-actu.info", "xn--lemnde-yqf.fr", "boulangerie-durand.fr"):
        first = score(scorer, target, domain)
        second = score(scorer, target, domain)
        assert 0.0 <= first.value <= 1.0  # type: ignore[attr-defined]
        assert first == second


def test_contributions_add_up_to_the_score(scorer: Scorer, target: WatchTarget) -> None:
    result = score(scorer, target, "lemonde-actu.info")
    total = sum(contribution.weighted for contribution in result.contributions)  # type: ignore[attr-defined]
    assert result.value == pytest.approx(total)  # type: ignore[attr-defined]


def test_every_criterion_is_reported_even_when_it_contributes_nothing(
    scorer: Scorer, target: WatchTarget
) -> None:
    """A criterion that scored zero is information, not an omission."""

    result = score(scorer, target, "boulangerie-durand.fr")
    criteria = {contribution.criterion for contribution in result.contributions}  # type: ignore[attr-defined]
    assert criteria == set(ScoringConfig().weights)
    for contribution in result.contributions:  # type: ignore[attr-defined]
        assert contribution.explanation


def test_a_disguised_name_outscores_an_unrelated_one(scorer: Scorer, target: WatchTarget) -> None:
    disguised = score(scorer, target, "xn--lemnde-yqf.fr")
    unrelated = score(scorer, target, "boulangerie-durand.fr")
    assert disguised.value > unrelated.value  # type: ignore[attr-defined]


def test_the_documented_case_scores_high(scorer: Scorer, target: WatchTarget) -> None:
    result = score(scorer, target, "lemonde-actu.info", not_before=NOW - timedelta(days=1))
    assert result.value > 0.6  # type: ignore[attr-defined]


def test_an_unrelated_domain_scores_low(scorer: Scorer, target: WatchTarget) -> None:
    result = score(scorer, target, "boulangerie-durand.fr", not_before=NOW - timedelta(days=1))
    assert result.value < 0.2  # type: ignore[attr-defined]


def test_weights_change_the_outcome(target: WatchTarget) -> None:
    tld_only = Scorer(ScoringConfig(weights={"tld_risk": 1.0}))
    subject = Subject(name=normalize("lemonde-actu.info"))
    result = tld_only.score(subject, target=target, now=NOW)

    assert result.value == pytest.approx(1.0)
    assert [c.criterion for c in result.contributions] == ["tld_risk"]


def test_the_breakdown_is_serialisable(scorer: Scorer, target: WatchTarget) -> None:
    """The breakdown is stored as JSON and quoted in reports."""

    payload = score(scorer, target, "lemonde-actu.info").as_dict()  # type: ignore[attr-defined]
    assert payload["value"] >= 0
    assert payload["contributions"][0]["criterion"]
    assert payload["contributions"][0]["explanation"]


def test_score_carries_a_one_line_summary(scorer: Scorer, target: WatchTarget) -> None:
    result = score(scorer, target, "xn--lemnde-yqf.fr")
    assert "lemonde.fr" in result.summary  # type: ignore[attr-defined]
