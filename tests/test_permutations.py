"""Expectations for the permutation engine.

Written before the implementation, on purpose. This engine is the difference
between a tool that finds impersonating domains and one that only confirms
what an analyst already suspected, so its behaviour is pinned down here rather
than described after the fact.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from ctwatch.names import normalize
from ctwatch.permutations.generator import (
    PermutationGenerator,
    PermutationKind,
    keyboard_neighbours,
)


@pytest.fixture(scope="module")
def generator() -> PermutationGenerator:
    return PermutationGenerator()


def names_of(permutations: Iterable[object], kind: PermutationKind | None = None) -> set[str]:
    selected = [p for p in permutations if kind is None or p.kind == kind]  # type: ignore[attr-defined]
    return {p.name.ascii_name for p in selected}  # type: ignore[attr-defined]


# ----------------------------------------------------------------------------
# Structural guarantees


def test_the_canonical_domain_is_never_returned(generator: PermutationGenerator) -> None:
    assert "lemonde.fr" not in names_of(generator.generate("lemonde.fr"))


def test_results_are_unique(generator: PermutationGenerator) -> None:
    permutations = list(generator.generate("lemonde.fr"))
    produced = [p.name.ascii_name for p in permutations]
    assert len(produced) == len(set(produced))


def test_every_result_is_a_valid_domain_name(generator: PermutationGenerator) -> None:
    for permutation in generator.generate("lemonde.fr"):
        # normalize() raises on anything a resolver would refuse.
        assert normalize(permutation.name.ascii_name).ascii_name == permutation.name.ascii_name


def test_every_result_explains_itself(generator: PermutationGenerator) -> None:
    for permutation in generator.generate("lemonde.fr"):
        assert permutation.kind in set(PermutationKind)
        assert permutation.detail
        assert permutation.base == "lemonde.fr"


def test_generation_is_deterministic(generator: PermutationGenerator) -> None:
    first = [p.name.ascii_name for p in generator.generate("lemonde.fr")]
    second = [p.name.ascii_name for p in generator.generate("lemonde.fr")]
    assert first == second


def test_limit_truncates_without_reordering(generator: PermutationGenerator) -> None:
    full = [p.name.ascii_name for p in generator.generate("lemonde.fr")]
    limited = [p.name.ascii_name for p in generator.generate("lemonde.fr", limit=25)]
    assert limited == full[:25]


def test_only_the_registrable_label_is_mutated(generator: PermutationGenerator) -> None:
    """bbc.co.uk must yield variants of "bbc", never of "co"."""

    results = [p for p in generator.generate("bbc.co.uk") if p.kind.preserves_suffix]
    assert results
    for permutation in results:
        assert permutation.name.ascii_name.endswith(".co.uk")
        label = permutation.name.ascii_name.removesuffix(".co.uk")
        assert "." not in label


def test_kinds_declare_whether_they_keep_the_suffix() -> None:
    assert PermutationKind.OMISSION.preserves_suffix is True
    assert PermutationKind.TLD_SWAP.preserves_suffix is False
    assert PermutationKind.SUFFIX_MERGE.preserves_suffix is False


def test_a_subdomain_is_ignored(generator: PermutationGenerator) -> None:
    """www.lemonde.fr is watched as lemonde.fr; the www adds nothing."""

    assert names_of(generator.generate("www.lemonde.fr")) == names_of(
        generator.generate("lemonde.fr")
    )


def test_a_bare_public_suffix_is_refused(generator: PermutationGenerator) -> None:
    with pytest.raises(ValueError, match="registrable"):
        list(generator.generate("co.uk"))


# ----------------------------------------------------------------------------
# Individual techniques


def test_character_omission(generator: PermutationGenerator) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.OMISSION)
    assert produced == {
        "emonde.fr",
        "lmonde.fr",
        "leonde.fr",
        "lemnde.fr",
        "lemode.fr",
        "lemone.fr",
        "lemond.fr",
    }


def test_character_repetition(generator: PermutationGenerator) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.REPETITION)
    assert produced == {
        "llemonde.fr",
        "leemonde.fr",
        "lemmonde.fr",
        "lemoonde.fr",
        "lemonnde.fr",
        "lemondde.fr",
        "lemondee.fr",
    }


def test_adjacent_transposition(generator: PermutationGenerator) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.TRANSPOSITION)
    assert produced == {
        "elmonde.fr",
        "lmeonde.fr",
        "leomnde.fr",
        "lemnode.fr",
        "lemodne.fr",
        "lemoned.fr",
    }


def test_hyphenation(generator: PermutationGenerator) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.HYPHENATION)
    assert produced == {
        "l-emonde.fr",
        "le-monde.fr",
        "lem-onde.fr",
        "lemo-nde.fr",
        "lemon-de.fr",
        "lemond-e.fr",
    }


def test_hyphenation_never_produces_a_leading_or_trailing_hyphen(
    generator: PermutationGenerator,
) -> None:
    for name in names_of(generator.generate("bbc.co.uk"), PermutationKind.HYPHENATION):
        label = name.removesuffix(".co.uk")
        assert not label.startswith("-")
        assert not label.endswith("-")


def test_vowel_swap(generator: PermutationGenerator) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.VOWEL_SWAP)
    assert "lamonde.fr" in produced
    assert "lemande.fr" in produced
    assert "lemonde.fr" not in produced


def test_keyboard_replacement_uses_physical_neighbours(
    generator: PermutationGenerator,
) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.REPLACEMENT)
    # "z" is next to "e" on azerty, "w" is next to "e" on qwerty.
    assert "lzmonde.fr" in produced
    assert "lwmonde.fr" in produced


def test_keyboard_insertion_adds_a_neighbouring_key(
    generator: PermutationGenerator,
) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.INSERTION)
    assert "lezmonde.fr" in produced
    assert "lzemonde.fr" in produced


def test_keyboard_neighbours_are_symmetric() -> None:
    assert "e" in keyboard_neighbours("r")
    assert "r" in keyboard_neighbours("e")
    assert keyboard_neighbours("-") == frozenset()


def test_bitsquatting_only_yields_legal_characters(
    generator: PermutationGenerator,
) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.BITSQUAT)
    assert produced
    for name in produced:
        label = name.removesuffix(".fr")
        assert all(character in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label)
    # A single flipped bit turns "l" (0x6c) into "m" (0x6d).
    assert "memonde.fr" in produced


def test_tld_swap_keeps_the_label(generator: PermutationGenerator) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.TLD_SWAP)
    assert "lemonde.info" in produced
    assert "lemonde.com" in produced
    assert "lemonde.fr" not in produced
    for name in produced:
        assert name.split(".", 1)[0] == "lemonde"


def test_extra_tlds_are_honoured() -> None:
    generator = PermutationGenerator(extra_tlds=["quebec"])
    assert "lemonde.quebec" in names_of(
        generator.generate("lemonde.fr"), PermutationKind.TLD_SWAP
    )


def test_suffix_merge_folds_the_suffix_into_the_label(
    generator: PermutationGenerator,
) -> None:
    produced = names_of(generator.generate("lemonde.fr"), PermutationKind.SUFFIX_MERGE)
    assert "lemondefr.com" in produced
    assert "lemonde-fr.com" in produced


def test_kinds_can_be_selected() -> None:
    generator = PermutationGenerator(kinds=[PermutationKind.OMISSION])
    kinds = {p.kind for p in generator.generate("lemonde.fr")}
    assert kinds == {PermutationKind.OMISSION}


def test_a_short_label_still_produces_something(generator: PermutationGenerator) -> None:
    results = list(generator.generate("bbc.co.uk"))
    assert len(results) > 10


def test_a_hyphenated_brand_is_handled(generator: PermutationGenerator) -> None:
    produced = names_of(generator.generate("service-public.fr"))
    assert "servicepublic.fr" in produced
    assert "service-publc.fr" in produced
