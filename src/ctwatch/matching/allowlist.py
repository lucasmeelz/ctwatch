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


# Past this many distinct registrations on one certificate, it is a provider's
# certificate rather than an organisation's. Measured on real data: media-group
# certificates carry 3 to 18 registrations, multi-tenant provider certificates
# carry one per name.
MAX_SHARED_REGISTRATIONS = 25

# Names per distinct registration. A group certificate lists many hosts of a few
# domains (measured: 5.2 to 6.3). A provider certificate lists one host each
# (measured: 1.00 to 1.02). The gap is wide enough to be a rule.
MINIMUM_NAMES_PER_REGISTRATION = 2.0

# Below this many registrations, spread means nothing — two names on one
# certificate have no distribution to speak of. A small certificate carrying the
# brand is overwhelmingly the brand's own, and demanding statistics of it would
# reject the very case the rule exists for.
SMALL_CERTIFICATE_REGISTRATIONS = 4


class OwnershipIndex:
    """Ownership read off the certificates themselves.

    A single certificate listing both ``lemonde.fr`` and ``lemonde-abonnes.fr``
    was issued to whoever proved control of ``lemonde.fr``. The second name is
    the brand, not an impersonation of it, and no configuration was needed to
    establish that.

    That reasoning holds only when the certificate belongs to an organisation.
    It fails completely on the certificates providers issue: one observed here
    carried a hundred names, of which exactly one was the brand's and
    ninety-nine belonged to unrelated businesses around the world. Taken at face
    value it declared all ninety-nine to be Le Figaro's — and, worse, would have
    silently suppressed a genuine impersonation that happened to sit behind the
    same provider. The guards below are what separate the two cases.
    """

    def __init__(self, repository: Repository, target: WatchTarget) -> None:
        self._repository = repository
        self._target = target
        self._canonical = target.canonical_domain
        self._allowlist = Allowlist.for_target(target)

    def _belongs_to_brand(self, name: str) -> bool:
        if _covers(self._canonical, name):
            return True
        # A defensive registration the operator declared can anchor an
        # inference just as well as the canonical name.
        return any(_covers(entry, name) for entry in self._allowlist.entries)

    def decide(self, name: DomainName) -> AllowlistDecision:
        domain = self._repository.get_domain(name.ascii_name)
        if domain is None:
            return AllowlistDecision(
                allowed=False,
                reason="never observed in a certificate, so nothing links it to the brand",
            )

        for names in self._repository.certificate_neighbourhoods(domain.id):
            brand_names = [other for other in names if self._belongs_to_brand(other)]
            if not brand_names:
                continue

            registrations = {registrable_or_none(other) or other for other in names}
            spread = len(names) / max(1, len(registrations))

            if len(registrations) > SMALL_CERTIFICATE_REGISTRATIONS:
                if len(registrations) > MAX_SHARED_REGISTRATIONS:
                    continue
                if spread < MINIMUM_NAMES_PER_REGISTRATION:
                    # One host per registration is what a provider's certificate
                    # looks like. Being a tenant of the same provider as the
                    # brand says nothing about who owns the name.
                    continue
                if len(brand_names) < 2:
                    # A lone brand host among many strangers is a tenancy, not a
                    # title deed.
                    continue

            return AllowlistDecision(
                allowed=True,
                reason=(
                    f"co-signed with {len(brand_names)} name(s) of the brand on a "
                    f"certificate covering {len(registrations)} registration(s), "
                    f"including {brand_names[0]}"
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
