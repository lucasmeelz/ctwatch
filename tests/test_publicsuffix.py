"""Expectations for domain splitting.

The cases below are the ones that decide whether the permutation engine
mutates the right part of a name. Getting `lemonde.co.uk` wrong would mean
generating variants of "co" instead of "lemonde", which is silently useless.
"""

from __future__ import annotations

import pytest

from ctwatch.publicsuffix import PublicSuffixList, load_public_suffix_list, split


@pytest.fixture(scope="module")
def psl() -> PublicSuffixList:
    return load_public_suffix_list()


@pytest.mark.parametrize(
    ("domain", "suffix", "label", "subdomain"),
    [
        ("lemonde.fr", "fr", "lemonde", ""),
        ("www.lemonde.fr", "fr", "lemonde", "www"),
        ("a.b.lemonde.fr", "fr", "lemonde", "a.b"),
        ("lemonde.com", "com", "lemonde", ""),
        ("bbc.co.uk", "co.uk", "bbc", ""),
        ("news.bbc.co.uk", "co.uk", "bbc", "news"),
        ("globo.com.br", "com.br", "globo", ""),
        ("service-public.fr", "fr", "service-public", ""),
        (
            "something.unknown-tld-that-does-not-exist",
            "unknown-tld-that-does-not-exist",
            "something",
            "",
        ),
    ],
)
def test_common_splits(
    psl: PublicSuffixList, domain: str, suffix: str, label: str, subdomain: str
) -> None:
    result = psl.split(domain)
    assert result.suffix == suffix
    assert result.registrable_label == label
    assert result.subdomain == subdomain
    assert result.registrable_domain == f"{label}.{suffix}"


def test_wildcard_rule_is_honoured(psl: PublicSuffixList) -> None:
    # The list carries `*.compute.amazonaws.com`, so the label before it is
    # part of the suffix rather than something anyone can register.
    result = psl.split("shop.eu-west-3.compute.amazonaws.com")
    assert result.suffix == "eu-west-3.compute.amazonaws.com"
    assert result.registrable_label == "shop"


def test_private_suffixes_group_free_subdomain_hosts(psl: PublicSuffixList) -> None:
    """A lookalike on a free subdomain host is its own registrable name."""

    result = psl.split("lemonde-actu.github.io")
    assert result.suffix == "github.io"
    assert result.registrable_label == "lemonde-actu"
    # For risk scoring, what matters is the actual TLD behind it.
    assert result.icann_suffix == "io"
    assert result.is_private_suffix is True


def test_icann_suffix_matches_the_suffix_for_ordinary_domains(psl: PublicSuffixList) -> None:
    result = psl.split("lemonde.fr")
    assert result.icann_suffix == "fr"
    assert result.is_private_suffix is False


def test_a_public_suffix_alone_has_no_registrable_name(psl: PublicSuffixList) -> None:
    result = psl.split("co.uk")
    assert result.registrable_label == ""
    assert result.registrable_domain is None
    assert result.is_public_suffix is True


def test_splitting_is_case_and_dot_insensitive(psl: PublicSuffixList) -> None:
    assert psl.split("  WWW.LeMonde.FR. ").registrable_domain == "lemonde.fr"


def test_internationalised_name_is_split_on_its_ascii_form(psl: PublicSuffixList) -> None:
    result = psl.split("lemоnde.fr")
    assert result.suffix == "fr"
    assert result.registrable_label.startswith("xn--")


def test_module_level_helper_uses_the_shipped_list() -> None:
    assert split("bbc.co.uk").registrable_domain == "bbc.co.uk"


def test_shipped_list_looks_complete(psl: PublicSuffixList) -> None:
    assert len(psl) > 5000
    assert psl.icann_rule_count > 1000
    assert psl.private_rule_count > 1000
