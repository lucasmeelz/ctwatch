"""Expectations for keyword combinations.

The pattern this covers is the one named in every account of these campaigns:
a real brand plus a news-sounding word, registered under a cheap suffix.
`lemonde-actu.info` is the canonical shape.
"""

from __future__ import annotations

import pytest

from ctwatch.permutations.dictionary import KeywordGenerator
from ctwatch.permutations.model import PermutationKind


@pytest.fixture
def generator() -> KeywordGenerator:
    return KeywordGenerator(keywords=["actu", "info"])


def names(generator: KeywordGenerator, domain: str) -> set[str]:
    return {p.name.ascii_name for p in generator.variants(domain)}


def test_the_documented_shape_is_generated(generator: KeywordGenerator) -> None:
    assert "lemonde-actu.info" in names(generator, "lemonde.fr")


def test_all_four_join_patterns_are_covered(generator: KeywordGenerator) -> None:
    produced = names(generator, "lemonde.fr")
    assert "lemonde-actu.fr" in produced
    assert "actu-lemonde.fr" in produced
    assert "lemondeactu.fr" in produced
    assert "actulemonde.fr" in produced


def test_keywords_are_combined_with_other_suffixes(generator: KeywordGenerator) -> None:
    produced = names(generator, "lemonde.fr")
    assert "lemonde-actu.com" in produced
    assert "lemonde-info.xyz" in produced


def test_no_keywords_means_no_candidates() -> None:
    assert list(KeywordGenerator(keywords=[]).variants("lemonde.fr")) == []


def test_a_keyword_already_in_the_name_is_skipped() -> None:
    """francetvinfo already contains "info"; repeating it adds nothing."""

    generator = KeywordGenerator(keywords=["info"])
    produced = names(generator, "francetvinfo.fr")
    assert "francetvinfoinfo.fr" not in produced
    assert "francetvinfo-info.fr" in produced


def test_results_are_unique_and_explained(generator: KeywordGenerator) -> None:
    permutations = list(generator.variants("lemonde.fr"))
    produced = [p.name.ascii_name for p in permutations]
    assert len(produced) == len(set(produced))
    for permutation in permutations:
        assert permutation.kind is PermutationKind.KEYWORD
        assert permutation.detail
        assert permutation.base == "lemonde.fr"


def test_only_the_registrable_label_is_extended(generator: KeywordGenerator) -> None:
    for permutation in generator.variants("bbc.co.uk"):
        label = permutation.name.ascii_name.rsplit(".", 1)[0]
        assert "bbc" in label.replace(".", "")


def test_keywords_are_normalised() -> None:
    generator = KeywordGenerator(keywords=["  ACTU  ", "actu", ""])
    produced = names(generator, "lemonde.fr")
    assert "lemonde-actu.fr" in produced
    assert not any("ACTU" in name for name in produced)


def test_suffix_list_can_be_restricted() -> None:
    generator = KeywordGenerator(keywords=["actu"], tlds=["info"])
    produced = names(generator, "lemonde.fr")
    assert produced == {
        "lemonde-actu.fr",
        "actu-lemonde.fr",
        "lemondeactu.fr",
        "actulemonde.fr",
        "lemonde-actu.info",
        "actu-lemonde.info",
        "lemondeactu.info",
        "actulemonde.info",
    }
