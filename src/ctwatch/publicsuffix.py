"""Splitting a domain into the part someone registered and the part they did not.

Knowing that ``lemonde`` is the registered label of ``lemonde.fr`` — and that
``bbc`` is the registered label of ``bbc.co.uk``, not ``co`` — decides which
characters the permutation engine is allowed to mutate. Get it wrong and the
tool generates variants of a country's suffix instead of a brand's name.

A snapshot of the Public Suffix List is vendored rather than fetched at runtime:
tests stay deterministic, offline use keeps working, and a scan does not depend
on yet another service being up. Refresh it with
``scripts/refresh_public_suffix_list.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import idna

LIST_PATH = Path(__file__).resolve().parent / "data" / "public_suffix_list.dat"

_ICANN_BEGIN = "===BEGIN ICANN DOMAINS==="
_ICANN_END = "===END ICANN DOMAINS==="


@dataclass(frozen=True, slots=True)
class SplitDomain:
    """A domain broken into the three parts that matter for this tool."""

    subdomain: str
    registrable_label: str
    suffix: str
    icann_suffix: str

    @property
    def registrable_domain(self) -> str | None:
        """The name someone actually registered, or ``None`` for a bare suffix."""

        if not self.registrable_label:
            return None
        return f"{self.registrable_label}.{self.suffix}"

    @property
    def is_public_suffix(self) -> bool:
        return not self.registrable_label

    @property
    def is_private_suffix(self) -> bool:
        """True when the suffix comes from the list's private section.

        ``lemonde-actu.github.io`` is a name someone controls, but ``github.io``
        is not a TLD, and treating it as one when scoring TLD risk would be
        wrong. Both readings are kept.
        """

        return self.suffix != self.icann_suffix

    @property
    def tld(self) -> str:
        return self.icann_suffix.rsplit(".", 1)[-1]


class RuleSet:
    """The three kinds of rule the Public Suffix List defines."""

    __slots__ = ("exceptions", "normal", "wildcards")

    def __init__(self) -> None:
        self.normal: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()

    def add(self, rule: str) -> None:
        if rule.startswith("!"):
            self.exceptions.add(rule[1:])
        elif rule.startswith("*."):
            self.wildcards.add(rule[2:])
        else:
            self.normal.add(rule)

    def __len__(self) -> int:
        return len(self.normal) + len(self.wildcards) + len(self.exceptions)

    def suffix_labels(self, labels: tuple[str, ...]) -> int:
        """Number of trailing labels that form the public suffix.

        Implements the matching algorithm from publicsuffix.org: exception
        rules win outright, otherwise the rule with the most labels wins, and
        an unknown suffix is treated as a single label.
        """

        total = len(labels)
        best = 0
        for index in range(total):
            tail = ".".join(labels[index:])
            if tail in self.exceptions:
                return total - index - 1
            is_wildcard_match = (
                index + 1 < total and ".".join(labels[index + 1 :]) in self.wildcards
            )
            if tail in self.normal or is_wildcard_match:
                best = max(best, total - index)
        return best or 1


class PublicSuffixList:
    def __init__(self, rules: str) -> None:
        self._all = RuleSet()
        self._icann = RuleSet()

        in_icann = False
        for raw_line in rules.splitlines():
            line = raw_line.strip()
            if line.startswith("//"):
                if _ICANN_BEGIN in line:
                    in_icann = True
                elif _ICANN_END in line:
                    in_icann = False
                continue
            if not line:
                continue

            rule = _to_ascii(line)
            self._all.add(rule)
            if in_icann:
                self._icann.add(rule)

    def __len__(self) -> int:
        return len(self._all)

    @property
    def icann_rule_count(self) -> int:
        return len(self._icann)

    @property
    def private_rule_count(self) -> int:
        return len(self._all) - len(self._icann)

    def split(self, domain: str) -> SplitDomain:
        """Split a domain name, working on its ASCII form."""

        cleaned = _to_ascii(domain.strip().strip(".").lower())
        labels = tuple(part for part in cleaned.split(".") if part)
        if not labels:
            return SplitDomain(subdomain="", registrable_label="", suffix="", icann_suffix="")

        suffix_count = min(self._all.suffix_labels(labels), len(labels))
        icann_count = min(self._icann.suffix_labels(labels), len(labels))
        # A private suffix never reaches further left than the ICANN one it
        # sits under, but a malformed list entry should not produce nonsense.
        icann_count = min(icann_count, suffix_count)

        suffix = ".".join(labels[len(labels) - suffix_count :])
        icann_suffix = ".".join(labels[len(labels) - icann_count :])

        remaining = labels[: len(labels) - suffix_count]
        if not remaining:
            return SplitDomain(
                subdomain="", registrable_label="", suffix=suffix, icann_suffix=icann_suffix
            )

        return SplitDomain(
            subdomain=".".join(remaining[:-1]),
            registrable_label=remaining[-1],
            suffix=suffix,
            icann_suffix=icann_suffix,
        )


def _to_ascii(value: str) -> str:
    if value.isascii():
        return value
    try:
        return idna.encode(value, uts46=True, std3_rules=False).decode("ascii")
    except idna.IDNAError:
        return value


@lru_cache(maxsize=1)
def load_public_suffix_list(path: Path = LIST_PATH) -> PublicSuffixList:
    """Load the vendored snapshot, parsed once per process."""

    return PublicSuffixList(path.read_text(encoding="utf-8"))


def split(domain: str) -> SplitDomain:
    return load_public_suffix_list().split(domain)


def registrable_domain(domain: str) -> str | None:
    return split(domain).registrable_domain
