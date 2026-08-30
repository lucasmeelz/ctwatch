"""Expectations for homoglyph generation and punycode handling.

This is the part of the tool that a substring search over Certificate
Transparency cannot replace. A domain registered with a Cyrillic "о" is stored
as `xn--` punycode, so no query built from the Latin spelling will ever match
it. Generating the variant first is the whole point, and the round-trip between
the two forms has to be exact.
"""

from __future__ import annotations

import idna
import pytest

from ctwatch.permutations.homoglyph import (
    ASCII_LOOKALIKES,
    ConfusableTable,
    HomoglyphGenerator,
    load_confusables,
)
from ctwatch.permutations.model import PermutationKind

CYRILLIC_O = "о"


@pytest.fixture(scope="module")
def table() -> ConfusableTable:
    return load_confusables()


@pytest.fixture(scope="module")
def generator() -> HomoglyphGenerator:
    return HomoglyphGenerator()


def names(generator: HomoglyphGenerator, domain: str) -> set[str]:
    return {p.name.ascii_name for p in generator.variants(domain)}


def unicode_names(generator: HomoglyphGenerator, domain: str) -> set[str]:
    return {p.name.unicode_name for p in generator.variants(domain)}


# ----------------------------------------------------------------------------
# The vendored table


def test_table_covers_the_letters_that_matter(table: ConfusableTable) -> None:
    for character in "aeioulmnrscd":
        assert table.substitutes(character), f"no confusable recorded for {character!r}"


def test_table_records_the_script_of_each_substitute(table: ConfusableTable) -> None:
    cyrillic = [s for s in table.substitutes("o") if s.character == CYRILLIC_O]
    assert cyrillic and cyrillic[0].script == "CYRILLIC"


def test_table_only_contains_characters_that_change_the_encoded_name(
    table: ConfusableTable,
) -> None:
    """A character that UTS #46 folds back to ASCII is not an attack."""

    for target in table.targets():
        for substitute in table.substitutes(target):
            encoded = idna.encode(f"a{substitute.character}a", uts46=True).decode()
            assert encoded.startswith("xn--")
            assert encoded != f"a{target}a"


# ----------------------------------------------------------------------------
# Generation


def test_cyrillic_substitution_produces_the_expected_punycode(
    generator: HomoglyphGenerator,
) -> None:
    produced = names(generator, "lemonde.fr")
    assert "xn--lemnde-yqf.fr" in produced


def test_every_variant_round_trips_between_both_forms(
    generator: HomoglyphGenerator,
) -> None:
    for permutation in generator.variants("lemonde.fr"):
        name = permutation.name
        assert idna.encode(name.unicode_name, uts46=True).decode() == name.ascii_name
        if name.ascii_name.startswith("xn--"):
            assert idna.decode(name.ascii_name) == name.unicode_name


def test_digit_lookalikes_are_generated(generator: HomoglyphGenerator) -> None:
    """The textbook case from every disinformation report: 1emonde.fr."""

    produced = names(generator, "lemonde.fr")
    assert "1emonde.fr" in produced
    assert "lem0nde.fr" in produced


def test_multi_character_lookalikes_are_generated(
    generator: HomoglyphGenerator,
) -> None:
    produced = names(generator, "lemonde.fr")
    assert "lernonde.fr" in produced  # "rn" reads as "m" at a glance


def test_ascii_lookalikes_are_not_flagged_as_internationalised(
    generator: HomoglyphGenerator,
) -> None:
    for permutation in generator.variants("lemonde.fr"):
        if permutation.name.ascii_name == "1emonde.fr":
            assert permutation.name.is_idn is False
            return
    pytest.fail("1emonde.fr was not generated")


def test_replacing_every_occurrence_is_offered(generator: HomoglyphGenerator) -> None:
    """Attackers usually swap every instance of a letter, not just one."""

    both = "lem" + CYRILLIC_O + "nde.fr"
    single = unicode_names(generator, "lemonde.fr")
    assert both in single

    produced = unicode_names(generator, "cocoa.fr")
    assert "c" + CYRILLIC_O + "c" + CYRILLIC_O + "a.fr" in produced


def test_whole_word_script_substitution_is_offered(
    generator: HomoglyphGenerator,
) -> None:
    produced = unicode_names(generator, "casa.fr")
    fully_cyrillic = [
        name
        for name in produced
        if all(ord(character) > 0x400 for character in name.removesuffix(".fr"))
    ]
    assert fully_cyrillic, "no variant with the whole name written in one other script"


def test_the_original_name_is_never_returned(generator: HomoglyphGenerator) -> None:
    assert "lemonde.fr" not in names(generator, "lemonde.fr")


def test_results_are_unique_and_deterministic(generator: HomoglyphGenerator) -> None:
    first = [p.name.ascii_name for p in generator.variants("lemonde.fr")]
    second = [p.name.ascii_name for p in generator.variants("lemonde.fr")]
    assert first == second
    assert len(first) == len(set(first))


def test_every_variant_explains_the_substitution(
    generator: HomoglyphGenerator,
) -> None:
    for permutation in generator.variants("lemonde.fr"):
        assert permutation.kind is PermutationKind.HOMOGLYPH
        assert permutation.detail
        assert permutation.base == "lemonde.fr"


def test_only_the_registrable_label_is_substituted(
    generator: HomoglyphGenerator,
) -> None:
    for permutation in generator.variants("bbc.co.uk"):
        assert permutation.name.ascii_name.endswith(".co.uk")


def test_ascii_lookalike_table_is_reciprocal() -> None:
    """If m can be written rn, then rn should also be readable as m."""

    assert "rn" in ASCII_LOOKALIKES["m"]
    assert "m" in ASCII_LOOKALIKES["rn"]
    assert "0" in ASCII_LOOKALIKES["o"]
    assert "o" in ASCII_LOOKALIKES["0"]


def test_unicode_substitutions_can_be_disabled() -> None:
    generator = HomoglyphGenerator(include_unicode=False)
    produced = names(generator, "lemonde.fr")
    assert "1emonde.fr" in produced
    assert not any(name.startswith("xn--") for name in produced)


def test_volume_stays_workable(generator: HomoglyphGenerator) -> None:
    """These names each cost one lookup against a rate-limited service."""

    assert 50 < len(names(generator, "lemonde.fr")) < 1500
