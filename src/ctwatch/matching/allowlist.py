"""Recognising the domains that belong to the brand being protected.

Newsrooms and institutions register lookalike domains themselves, defensively,
by the dozen. A tool that reports every one of them buries the handful that
matter, and the analyst stops reading. Suppressing them is not a refinement to
add later; it is what makes the output usable at all.

Two mechanisms, deliberately different in kind:

* what the operator declares — the watched domain, its subdomains, and any
  defensive registration listed in the configuration;
* what the certificates themselves show — a certificate covering both the
  watched domain and a lookalike was issued to whoever controls the watched
  domain, which settles the question without anyone having to declare anything.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ctwatch.names import DomainName, InvalidDomainNameError, normalize
from ctwatch.publicsuffix import split
from ctwatch.store.models import WatchTarget
from ctwatch.store.repository import Repository


@dataclass(frozen=True, slots=True)
class AllowlistDecision:
    """Whether a domain should be reported, and why."""

    allowed: bool
    reason: str
    rule: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def _covers(entry: str, candidate: str) -> bool:
    """Does an allowlist entry cover this name?

    A bare entry covers the name and everything under it. An entry written
    ``*.example.com`` covers the subdomains only, which is what someone means
    when they write it that way.
    """

    if entry.startswith("*."):
        suffix = entry[1:]
        return candidate.endswith(suffix) and candidate != entry[2:]
    return candidate == entry or candidate.endswith(f".{entry}")


class Allowlist:
    """The domains an operator has declared as legitimately theirs."""

    def __init__(self, *, canonical_domains: Iterable[str], entries: Iterable[str]) -> None:
        self._canonical = tuple(
            dict.fromkeys(item.strip().lower().rstrip(".") for item in canonical_domains if item)
        )
        self._entries = tuple(
            dict.fromkeys(item.strip().lower().rstrip(".") for item in entries if item)
        )

    @classmethod
    def for_target(cls, target: WatchTarget) -> Allowlist:
        return cls(canonical_domains=[target.canonical_domain], entries=target.allowlist)

    @property
    def entries(self) -> tuple[str, ...]:
        return self._entries

    def decide(self, name: DomainName) -> AllowlistDecision:
        candidate = name.ascii_name

        for canonical in self._canonical:
            if _covers(canonical, candidate):
                return AllowlistDecision(
                    allowed=True,
                    reason=f"{candidate} is {canonical} or a subdomain of it",
                    rule="canonical",
                )

        for entry in self._entries:
            if _covers(entry, candidate):
                return AllowlistDecision(
                    allowed=True,
                    reason=f"{candidate} is covered by the allowlist entry {entry!r}",
                    rule="explicit",
                )

        return AllowlistDecision(
            allowed=False, reason="not declared as belonging to the brand", rule=""
        )


class OwnershipIndex:
    """Ownership read off the certificates themselves.

    A single certificate listing both ``lemonde.fr`` and ``lemonde-abonnes.fr``
    was issued to whoever proved control of ``lemonde.fr``. The second name is
    the brand, not an impersonation of it, and no configuration was needed to
    establish that.
    """

    def __init__(self, repository: Repository, target: WatchTarget) -> None:
        self._repository = repository
        self._target = target
        self._canonical = target.canonical_domain

    def _belongs_to_brand(self, name: str) -> bool:
        return _covers(self._canonical, name)

    def decide(self, name: DomainName) -> AllowlistDecision:
        domain = self._repository.get_domain(name.ascii_name)
        if domain is None:
            return AllowlistDecision(
                allowed=False,
                reason="never observed in a certificate, so nothing links it to the brand",
            )

        for other in self._repository.names_sharing_certificate(domain.id):
            if other == name.ascii_name:
                continue
            if self._belongs_to_brand(other):
                return AllowlistDecision(
                    allowed=True,
                    reason=(
                        f"appears on the same certificate as {other}, "
                        "so it was issued to whoever controls the watched domain"
                    ),
                    rule="shared_certificate",
                )

        return AllowlistDecision(
            allowed=False, reason="shares no certificate with the watched domain"
        )


def registrable_or_none(name: str) -> str | None:
    """Convenience for grouping: the registered name behind a hostname."""

    try:
        normalized = normalize(name)
    except InvalidDomainNameError:
        return None
    return split(normalized.ascii_name).registrable_domain
