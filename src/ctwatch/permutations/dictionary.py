"""Brand plus keyword, which is how most of these domains are actually named.

Reports on coordinated impersonation campaigns describe the same construction
over and over: the real name of an outlet, a word that sounds like news, and a
suffix that costs a few euros. ``lemonde-actu.info`` is the shape, and it is
not something a typo generator will ever produce.

Keywords come from the watchlist, so an operator watching a ministry can list
``officiel`` and ``demarches`` instead of ``actu`` and ``live``.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ctwatch.names import InvalidDomainNameError, normalize
from ctwatch.permutations.model import Permutation, PermutationKind
from ctwatch.publicsuffix import split

# Where these registrations land in practice: cheap, unrestricted, and either
# neutral-sounding or actively news-flavoured.
DEFAULT_KEYWORD_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "info",
    "news",
    "live",
    "online",
    "site",
    "xyz",
    "top",
)


class KeywordGenerator:
    """Combines a watched name with the words an impersonator would append."""

    def __init__(
        self,
        *,
        keywords: Iterable[str],
        tlds: Iterable[str] = DEFAULT_KEYWORD_TLDS,
    ) -> None:
        self._keywords = tuple(
            dict.fromkeys(word.strip().lower() for word in keywords if word.strip())
        )
        self._tlds = tuple(dict.fromkeys(tld.strip().lower().lstrip(".") for tld in tlds))

    @property
    def keywords(self) -> tuple[str, ...]:
        return self._keywords

    def _labels(self, label: str, keyword: str) -> Iterator[tuple[str, str]]:
        """(label, explanation) for each way of joining a name and a word."""

        yield f"{label}-{keyword}", f"{keyword!r} appended with a hyphen"
        yield f"{keyword}-{label}", f"{keyword!r} prepended with a hyphen"
        if keyword not in label:
            # Running the two words together only reads as the brand when the
            # word is not already part of it: "francetvinfoinfo" fools nobody.
            yield f"{label}{keyword}", f"{keyword!r} appended"
            yield f"{keyword}{label}", f"{keyword!r} prepended"

    def variants(self, domain: str) -> Iterator[Permutation]:
        parts = split(domain)
        base = parts.registrable_domain
        if base is None:
            msg = (
                f"{domain!r} has no registrable part to extend; "
                "it is a public suffix, not a domain someone owns"
            )
            raise ValueError(msg)

        suffixes = tuple(dict.fromkeys([parts.suffix, *self._tlds]))
        seen: set[str] = {base}

        for keyword in self._keywords:
            for label, explanation in self._labels(parts.registrable_label, keyword):
                for suffix in suffixes:
                    full = f"{label}.{suffix}"
                    if full in seen:
                        continue
                    try:
                        name = normalize(full)
                    except InvalidDomainNameError:
                        seen.add(full)
                        continue
                    if name.ascii_name in seen:
                        continue
                    seen.add(full)
                    seen.add(name.ascii_name)

                    detail = explanation
                    if suffix != parts.suffix:
                        detail = f"{explanation}, registered under {suffix!r}"
                    yield Permutation(
                        name=name,
                        kind=PermutationKind.KEYWORD,
                        detail=detail,
                        base=base,
                    )
