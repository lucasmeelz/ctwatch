"""Detection quality, measured rather than asserted.

Every other test in this suite checks behaviour: this function returns that
value. None of them can tell whether the tool actually finds impersonating
domains, and that is the only question that matters. Without a measurement, any
attempt to reduce false positives can be "successful" by discarding true ones,
and nothing would go red.

The floors below are deliberately a little under the current numbers. They are
a ratchet against silent regression, not a target: raising them when the
measure improves is part of changing the algorithm.

The corpus itself lives in tests/fixtures/evaluation_corpus.py, where each entry
carries the reason for its label. Argue with the labels there, not here.
"""

from __future__ import annotations

import pytest

from tests.fixtures.evaluation_corpus import (
    CORPUS,
    MUST_DETECT,
    MUST_NOT_DETECT,
    evaluate,
    format_report,
    variant_matcher_assess,
)

# Measured 2026-08-31: precision 0.932, recall 0.944, f1 0.938.
MINIMUM_PRECISION = 0.90
MINIMUM_RECALL = 0.90
MINIMUM_F1 = 0.90


@pytest.fixture(scope="module")
def measurement() -> dict[str, object]:
    return evaluate(variant_matcher_assess())


def test_the_corpus_is_worth_measuring_against() -> None:
    positives = [entry for entry in CORPUS if entry.label == MUST_DETECT]
    negatives = [entry for entry in CORPUS if entry.label == MUST_NOT_DETECT]
    assert len(positives) >= 40
    assert len(negatives) >= 60
    assert all(entry.reason for entry in CORPUS)
    assert len({(entry.name, entry.watched) for entry in CORPUS}) == len(CORPUS)


def test_precision_does_not_regress(measurement: dict[str, object]) -> None:
    precision = float(measurement["precision"])  # type: ignore[arg-type]
    assert precision >= MINIMUM_PRECISION, format_report(measurement)  # type: ignore[arg-type]


def test_recall_does_not_regress(measurement: dict[str, object]) -> None:
    """The one a false-positive fix is most likely to break."""

    recall = float(measurement["recall"])  # type: ignore[arg-type]
    assert recall >= MINIMUM_RECALL, format_report(measurement)  # type: ignore[arg-type]


def test_f1_does_not_regress(measurement: dict[str, object]) -> None:
    f1 = float(measurement["f1"])  # type: ignore[arg-type]
    assert f1 >= MINIMUM_F1, format_report(measurement)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("name", "watched"),
    [
        ("lemonde.fr.paiement-secure.net", "lemonde.fr"),
        ("lemonde.paris-actu.com", "lemonde.fr"),
        ("service-public.fr.demarches-en-ligne.top", "service-public.fr"),
    ],
)
def test_the_brand_carried_in_a_third_party_subdomain_is_caught(name: str, watched: str) -> None:
    """Documented, and invisible to anything that reads only the registered label."""

    assert variant_matcher_assess()(name, watched) is True


@pytest.mark.parametrize(
    ("name", "watched"),
    [
        ("lemondeduvin.com", "lemonde.fr"),
        ("lemondedesenfants.fr", "lemonde.fr"),
        ("animal-liberation.org", "liberation.fr"),
        ("tax-liberation.co.uk", "liberation.fr"),
        ("sante.journaldesfemmes.com", "sante.gouv.fr"),
    ],
)
def test_ordinary_words_that_happen_to_be_brands_are_not_findings(name: str, watched: str) -> None:
    """Le Monde, Libération and Santé are also just French words."""

    assert variant_matcher_assess()(name, watched) is False
