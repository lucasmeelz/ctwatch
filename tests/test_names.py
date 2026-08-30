from __future__ import annotations

import pytest

from ctwatch.names import DomainName, InvalidDomainNameError, normalize, normalize_all


def test_case_and_trailing_dot_are_normalised() -> None:
    assert normalize("  LeMonde.FR. ").ascii_name == "lemonde.fr"


def test_wildcard_is_recorded_separately_from_the_base_name() -> None:
    name = normalize("*.lemonde-actu.info")
    assert name.ascii_name == "lemonde-actu.info"
    assert name.is_wildcard is True


def test_unicode_name_round_trips_to_punycode() -> None:
    # Cyrillic "о" in place of the Latin one: the reason variants have to be
    # generated before querying, since a substring search will never find it.
    name = normalize("lemоnde.fr")
    assert name.ascii_name.startswith("xn--")
    assert name.unicode_name == "lemоnde.fr"
    assert name.is_idn is True


def test_punycode_input_is_decoded_for_display() -> None:
    ascii_form = normalize("lemоnde.fr").ascii_name
    name = normalize(ascii_form)
    assert name.ascii_name == ascii_form
    assert name.unicode_name == "lemоnde.fr"


def test_plain_ascii_name_is_not_flagged_as_idn() -> None:
    name = normalize("lemonde.fr")
    assert name.is_idn is False
    assert name.tld == "fr"


def test_undecodable_punycode_falls_back_to_ascii() -> None:
    name = normalize("xn--not-valid-punycode-at-all.fr")
    assert name.unicode_name == name.ascii_name


@pytest.mark.parametrize(
    "raw",
    ["", "   ", ".", "..", "*.", "a..b", "not a domain", "localhost", "-bad.fr", "lemonde.fr/path"],
)
def test_unusable_input_is_rejected(raw: str) -> None:
    with pytest.raises(InvalidDomainNameError):
        normalize(raw)


def test_batch_normalisation_deduplicates_and_drops_junk() -> None:
    names = normalize_all("lemonde.fr\nLEMONDE.FR\n\n*.lemonde.fr\nnot a domain\n")
    assert names == (
        DomainName("lemonde.fr", "lemonde.fr", is_wildcard=False),
        DomainName("lemonde.fr", "lemonde.fr", is_wildcard=True),
    )


def test_batch_normalisation_accepts_lists() -> None:
    assert normalize_all(["lemonde.fr", "lemonde.fr"]) == (DomainName("lemonde.fr", "lemonde.fr"),)
    assert normalize_all(None) == ()
