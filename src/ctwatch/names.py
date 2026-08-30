"""Domain name normalisation.

Two forms of the same name matter, and confusing them is how homoglyph attacks
slip through tooling: the A-label (``xn--...``) is what appears in certificates
and queries, while the U-label is what a reader sees in a browser. Both are
kept, always, and the ASCII form is the one used as a key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import idna

WILDCARD_PREFIX = "*."
PUNYCODE_PREFIX = "xn--"


@dataclass(frozen=True, slots=True)
class DomainName:
    """A DNS name in both the form it travels in and the form people read."""

    ascii_name: str
    unicode_name: str
    is_wildcard: bool = False

    @property
    def is_idn(self) -> bool:
        return self.ascii_name != self.unicode_name

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(self.ascii_name.split("."))

    @property
    def tld(self) -> str:
        return self.labels[-1] if self.labels else ""

    def __str__(self) -> str:
        return self.ascii_name


class InvalidDomainNameError(ValueError):
    """Raised for input that cannot be interpreted as a DNS name."""


def _to_unicode(ascii_name: str) -> str:
    """Best-effort U-label rendering.

    Certificate Transparency carries a lot of malformed data, including names
    that no resolver would accept. A name we cannot decode is still worth
    recording, so decoding failures fall back to the ASCII form rather than
    dropping the observation.
    """

    if PUNYCODE_PREFIX not in ascii_name:
        return ascii_name
    try:
        return idna.decode(ascii_name)
    except idna.IDNAError:
        return ascii_name


def _to_ascii(name: str) -> str:
    try:
        # uts46 folding applies the same case and character mapping browsers
        # use, so our key matches what a victim's browser would resolve.
        return idna.encode(name, uts46=True, std3_rules=False).decode("ascii")
    except idna.IDNAError:
        return name


# Underscore is not legal in a hostname, but it does appear in certificates
# (service labels such as ``_dmarc``), and dropping those observations would
# lose real infrastructure links.
_ASCII_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$")


def _is_plausible(ascii_name: str) -> bool:
    labels = ascii_name.split(".")
    if len(labels) < 2:
        return False
    return all(_ASCII_LABEL.match(label) for label in labels)


def normalize(raw: str) -> DomainName:
    """Normalise a name coming from a certificate or from user input."""

    candidate = raw.strip().strip('"').lower().rstrip(".")
    if candidate.startswith(WILDCARD_PREFIX):
        is_wildcard = True
        candidate = candidate[len(WILDCARD_PREFIX) :].rstrip(".")
    else:
        is_wildcard = False

    if not candidate:
        msg = "domain name must not be empty"
        raise InvalidDomainNameError(msg)

    if candidate.isascii():
        ascii_name = candidate
        unicode_name = _to_unicode(candidate)
    else:
        ascii_name = _to_ascii(candidate)
        unicode_name = candidate

    if not _is_plausible(ascii_name):
        msg = f"not a usable domain name: {raw!r}"
        raise InvalidDomainNameError(msg)

    return DomainName(ascii_name=ascii_name, unicode_name=unicode_name, is_wildcard=is_wildcard)


def normalize_all(raw_names: object) -> tuple[DomainName, ...]:
    """Normalise a batch, dropping unusable entries and de-duplicating.

    Certificates commonly repeat the common name in the subject alternative
    names; a wildcard and its base name are kept separately because they are
    different facts about the certificate.
    """

    if isinstance(raw_names, str):
        candidates: list[str] = raw_names.splitlines()
    elif isinstance(raw_names, list | tuple):
        candidates = [str(item) for item in raw_names]
    else:
        candidates = []

    seen: dict[tuple[str, bool], DomainName] = {}
    for candidate in candidates:
        for part in candidate.replace(",", "\n").splitlines():
            try:
                name = normalize(part)
            except InvalidDomainNameError:
                continue
            seen.setdefault((name.ascii_name, name.is_wildcard), name)
    return tuple(seen.values())
