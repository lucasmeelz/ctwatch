"""A labelled corpus for measuring detection quality, not behaviour.

The rest of the test suite asks whether the code does what it was written to
do. This file asks a different question: of the names ctwatch *could* see, which
ones must be reported and which must not. Without that, tightening the
algorithm is guesswork — every false positive removed might have taken a true
positive with it, and nothing would say so.

Why a Python module rather than JSON
------------------------------------
The scoring harness has to live in the same file, and the entries carry a
schema (label, reason, provenance, tags) that a dataclass documents better than
a bare object literal. Python also lets the reasons sit next to the names as
prose instead of as a string field nobody reads. Nothing here imports anything
outside the standard library, so the corpus and the harness stay usable from a
scratch script, a notebook, or CI.

Provenance
----------
``PROV_CT``     the name was actually observed in Certificate Transparency by
                this tool and is recorded in ``ctwatch.db`` (scans of
                lemonde.fr, lefigaro.fr, francetvinfo.fr, gouvernement.fr).
``PROV_PUBLIC`` a real domain whose ownership is a matter of public record and
                which is *not* an impersonation (e.g. the Luxembourg
                government's own site).
``PROV_SYNTH``  constructed by hand for this corpus, in a style that public
                reporting on media-impersonation operations describes — the
                "Doppelganger" / RRN operation documented by EU DisinfoLab and
                VIGINUM is the well-known example, and its recurring shapes are
                a brand name under a cheap suffix, a homoglyph or typo variant,
                and a brand name that appears only in the subdomain of a
                third-party registration.

                No synthetic name below is claimed to have been observed in any
                real campaign. They are plausible instances of a documented
                *shape*, nothing more. Treat them as a test of the algorithm's
                generalisation, not as indicators of compromise.

Labelling rule
--------------
``MUST_DETECT``      a reasonable analyst, shown this name against this watched
                     domain and nothing else, would want it on the desk.
``MUST_NOT_DETECT``  the same analyst would call it noise. Ownership by the
                     watched brand itself counts as noise: an alert on your own
                     infrastructure is a false positive even though the name
                     really does contain the brand.

The judgement is about the *name*, since that is all the matcher sees. Signals
that arrive later (RDAP age, DNS, page content) are out of scope here.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

MUST_DETECT = "MUST_DETECT"
MUST_NOT_DETECT = "MUST_NOT_DETECT"

PROV_CT = "ct_log"
PROV_PUBLIC = "public_record"
PROV_SYNTH = "synthetic"


@dataclass(frozen=True, slots=True)
class Entry:
    """One name, judged against one watched domain."""

    name: str
    watched: str
    label: str
    reason: str
    provenance: str
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def should_detect(self) -> bool:
        return self.label == MUST_DETECT


# The watchlist the corpus is written against — the one shipped in ctwatch.yaml.
# Exposed so a harness can build matchers without re-deriving it.
WATCHLIST: dict[str, tuple[str, ...]] = {
    "lemonde.fr": ("actu", "fr", "info", "live", "news"),
    "lefigaro.fr": ("actu", "fr", "info", "live", "news"),
    "liberation.fr": ("actu", "fr", "info", "live", "news"),
    "francetvinfo.fr": ("actu", "fr", "info", "live", "news"),
    "gouvernement.fr": ("fr", "gouv", "info", "officiel"),
    "service-public.fr": ("demarches", "fr", "gouv", "officiel"),
}


# ---------------------------------------------------------------------------
# NEGATIVES — names that must never be reported
# ---------------------------------------------------------------------------

# The brand's own hostnames under its own registrable domain. These dominate
# any real CT feed for a large newsroom and are the cheapest thing to get wrong.
_OWN_SUBDOMAINS: tuple[Entry, ...] = (
    Entry(
        "www.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "the watched domain itself, with the conventional www label",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "abonnements.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "subscription service on the watched domain — same registration",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "boutique.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "the brand's own shop, under the registrable domain it owns",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "journal.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "editorial host on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "moncompte.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "account portal on the watched domain — reads phishy, is not",
        PROV_CT,
        ("own_infra", "hard"),
    ),
    Entry(
        "stg-www.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "staging environment on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "dev.webserver.carnet.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "four-deep internal hostname, still the brand's own registration",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "conferences-epargne.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "event microsite on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "madame.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "the brand's magazine vertical, on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "immobilier.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "classifieds vertical on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "recruteurs-staging.emploi.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "staging host two levels down on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "programme.tvmag.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "TV listings vertical on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "preprod-api-fidji-private.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "internal pre-production API on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "www.francetvinfo.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "the watched domain itself",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "la1ere.francetvinfo.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "overseas-network vertical on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "api-back.regions.francetvinfo.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "backend API on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "login.francetvinfo.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "the real login host — the single most phishing-shaped legitimate name here",
        PROV_CT,
        ("own_infra", "hard"),
    ),
    Entry(
        "www.gouvernement.fr",
        "gouvernement.fr",
        MUST_NOT_DETECT,
        "the watched government domain itself",
        PROV_CT,
        ("own_infra",),
    ),
    Entry(
        "barometre.gouvernement.fr",
        "gouvernement.fr",
        MUST_NOT_DETECT,
        "policy-tracker microsite on the watched domain",
        PROV_CT,
        ("own_infra",),
    ),
)

# Wildcard certificates issued to the brand. A wildcard is a different fact
# about a certificate, not a different domain, and must not become a finding.
_OWN_WILDCARDS: tuple[Entry, ...] = (
    Entry(
        "*.blog.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "wildcard under the watched domain — the brand's own blog platform",
        PROV_CT,
        ("own_infra", "wildcard"),
    ),
    Entry(
        "*.directus.lemonde.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "wildcard on an internal CMS host of the watched domain",
        PROV_CT,
        ("own_infra", "wildcard"),
    ),
    Entry(
        "*.emploi.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "wildcard under the watched domain's jobs vertical",
        PROV_CT,
        ("own_infra", "wildcard"),
    ),
    Entry(
        "*.avis-vin.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "wildcard under the watched domain's wine vertical",
        PROV_CT,
        ("own_infra", "wildcard"),
    ),
    Entry(
        "*.go.lefigaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "wildcard on the brand's own redirector",
        PROV_CT,
        ("own_infra", "wildcard"),
    ),
    Entry(
        "*.francetvinfo.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "wildcard on the watched domain itself",
        PROV_CT,
        ("own_infra", "wildcard"),
    ),
)

# The same brand, registered under other suffixes, and the media group's other
# properties. Textually these look exactly like the impersonations; only
# ownership separates them, which is why they are the expensive false positives.
_SIBLING_PROPERTIES: tuple[Entry, ...] = (
    Entry(
        "directus.lemonde.io",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "Le Monde's own .io, seen on the same certificate as directus.lemonde.fr",
        PROV_CT,
        ("sibling_tld", "hard"),
    ),
    Entry(
        "hz.lefigaro.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "the group's defensive .com, sharing certificates with lefigaro.fr hosts",
        PROV_CT,
        ("sibling_tld", "hard"),
    ),
    Entry(
        "lefigaro.dev",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "the brand's own .dev, on a certificate with avis-vin.lefigaro.fr",
        PROV_CT,
        ("sibling_tld", "hard"),
    ),
    Entry(
        "expe.le-figaro.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "hyphenated defensive registration held by the group itself",
        PROV_CT,
        ("sibling_tld", "hard"),
    ),
    Entry(
        "lefig.net",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "the group's own link shortener, seen alongside lefigaro.fr hosts",
        PROV_CT,
        ("sibling_tld", "hard"),
    ),
    Entry(
        "media.figaro.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "figaro.fr is the group's own second brand domain, not an impersonation",
        PROV_CT,
        ("sibling_brand", "hard"),
    ),
    Entry(
        "f1g.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "the group's asset/CDN domain — a contraction it registered itself",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "figarocms.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "the group's CMS domain, brand-derived and brand-owned",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "visioconf.groupefigaro.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "the parent group's corporate domain",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "he.leparticulier.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "a separate title owned by the same group, no brand string in it",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "tvmag.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "group-owned magazine domain sharing certificates with lefigaro.fr",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "gala.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "another group title on the same certificates",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "franceinfo.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "France Info's own shorter brand domain, held by France Televisions",
        PROV_CT,
        ("shorter_genuine", "hard"),
    ),
    Entry(
        "www.franceinfo.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "same genuine shorter domain, www form",
        PROV_CT,
        ("shorter_genuine", "hard"),
    ),
    Entry(
        "francetv.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "the broadcaster's own group domain: a genuinely different, shorter "
        "registration by the same owner, not a truncation attack",
        PROV_CT,
        ("shorter_genuine", "hard"),
    ),
    Entry(
        "api-proximite.francetv.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "internal API on the broadcaster's group domain",
        PROV_CT,
        ("shorter_genuine", "hard"),
    ),
    Entry(
        "nl.francetvsport.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "sibling brand domain of the same broadcaster",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "nl.francetveducation.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "sibling brand domain of the same broadcaster",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "nl.france3.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "channel domain of the same broadcaster",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "nl.la1ere.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "overseas-network domain of the same broadcaster",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "nl.lumni.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "education brand of the same broadcaster",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "nl.culturebox.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "culture brand of the same broadcaster",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "desmotsdeminuit.ftvi-preprod.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "the broadcaster's own pre-production domain, abbreviated",
        PROV_CT,
        ("sibling_brand",),
    ),
    Entry(
        "newsletter.cultureprime.fr",
        "francetvinfo.fr",
        MUST_NOT_DETECT,
        "public-broadcasting joint offer, unrelated string to the watched name",
        PROV_CT,
        ("unrelated",),
    ),
)

# Infrastructure that shows up on the same certificates: CDNs, adtech, SaaS
# tenants, and partner sites. None of it impersonates anything.
_INFRASTRUCTURE: tuple[Entry, ...] = (
    Entry(
        "img-19.ccm2.net",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "image CDN of the group's technical platform",
        PROV_CT,
        ("cdn",),
    ),
    Entry(
        "static.ccmbg.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "static asset host of the same platform",
        PROV_CT,
        ("cdn",),
    ),
    Entry(
        "akm-creacdn.zebestof.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "third-party adtech CDN riding the same certificate",
        PROV_CT,
        ("cdn",),
    ),
    Entry(
        "lmo-lmo-webreader-production.twipemobile.com",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "SaaS e-paper reader tenant; 'lmo' is a customer code, not the brand",
        PROV_CT,
        ("saas", "hard"),
    ),
    Entry(
        "renderer.r-target.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "retargeting vendor host on a shared certificate",
        PROV_CT,
        ("saas",),
    ),
    Entry(
        "trackeffi.bsp-auto.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "affiliate tracking host of an unrelated advertiser",
        PROV_CT,
        ("saas",),
    ),
    Entry(
        "hz.commentcamarche.net",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated consumer-tech title on the same platform certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "www.qlf.linternaute.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated title, QA environment, same platform certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "cuisine.journaldesfemmes.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated title on the same platform certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "hz.meteoconsult.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "weather service on the same platform certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "pws.actualite.20minutes.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "a competing newspaper's own domain, sharing a syndication vendor",
        PROV_CT,
        ("competitor", "hard"),
    ),
    Entry(
        "pws.actualites.nouvelobs.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "another competing outlet on the same vendor certificate",
        PROV_CT,
        ("competitor", "hard"),
    ),
    Entry(
        "pws.lifestyle.marieclaire.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated magazine on the same vendor certificate",
        PROV_CT,
        ("competitor",),
    ),
    Entry(
        "partner.bestsecret.ch",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "e-commerce partner host on a shared affiliate certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "effinity.moto-axxe.fr",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "affiliate-network host for an unrelated retailer",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "figaro-lombard-odier.acseo-www00.evolix.eu",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "an agency staging host that carries the brand word in a SUBDOMAIN of a "
        "third-party registration — structurally identical to the impersonation "
        "pattern below, and benign; the discriminator has to be something other "
        "than the shape",
        PROV_CT,
        ("subdomain_carrier", "hard"),
    ),
)

# Names with no relation to any watched brand that nonetheless end up in the
# pipeline because they share a certificate with one.
_UNRELATED: tuple[Entry, ...] = (
    Entry(
        "butterish.org",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate; nine edits from 'lefigaro'",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "fello.in",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "www.tuneroom.org",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "srinivasaerp.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "kokkola-pietarsaarilentoasema.fi",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "Finnish airport site, unrelated, shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "backgammon-in-muenchen.de",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated German hobby site on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "sk8brd.in",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated short domain on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "wallwall.net",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "dominoharbor.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "abinpc.net",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "soundgrid.io",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
    Entry(
        "spnx.jp",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "unrelated tenant on a shared certificate",
        PROV_CT,
        ("unrelated",),
    ),
)

# The genuinely hard negatives: names that legitimately contain a watched label,
# or that are a different organisation with the same word.
_LEGITIMATE_SUBSTRING: tuple[Entry, ...] = (
    Entry(
        "gouvernement.lu",
        "gouvernement.fr",
        MUST_NOT_DETECT,
        "the Luxembourg government's own portal — a different sovereign state "
        "using the same French common noun, not an impersonation of France",
        PROV_PUBLIC,
        ("legit_substring", "hard"),
    ),
    Entry(
        "animal-liberation.org",
        "liberation.fr",
        MUST_NOT_DETECT,
        "'liberation' here is the English common noun; no relation to the paper",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "liberationtheology.net",
        "liberation.fr",
        MUST_NOT_DETECT,
        "theological movement; the brand string is incidental",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "liberationsociety.org",
        "liberation.fr",
        MUST_NOT_DETECT,
        "advocacy organisation using the common noun",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "tax-liberation.co.uk",
        "liberation.fr",
        MUST_NOT_DETECT,
        "financial-advice site; common noun, different language community",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "liberationbrewing.com",
        "liberation.fr",
        MUST_NOT_DETECT,
        "brewery; common noun again",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "lemondeduvin.com",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "'le monde du vin' — an ordinary French noun phrase that happens to "
        "start with the brand string",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "lemondedesenfants.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "'le monde des enfants' — same problem: French prose, not a brand",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "lemondeselection.com",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "a quality-award institute; 'lemonde' falls out of 'Monde Selection'",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "figaro-opera-tickets.com",
        "lefigaro.fr",
        MUST_NOT_DETECT,
        "Beaumarchais/Mozart's Figaro, not the newspaper — the brand word predates the brand",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "servicepublicdeleau.fr",
        "service-public.fr",
        MUST_NOT_DETECT,
        "'service public de l'eau' — a French administrative phrase used by "
        "water utilities, not the national portal",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
    Entry(
        "monde-diplomatique.fr",
        "lemonde.fr",
        MUST_NOT_DETECT,
        "a separate publication with its own name; shares a word, not an identity",
        PROV_SYNTH,
        ("legit_substring", "hard"),
    ),
)

NEGATIVES: tuple[Entry, ...] = (
    *_OWN_SUBDOMAINS,
    *_OWN_WILDCARDS,
    *_SIBLING_PROPERTIES,
    *_INFRASTRUCTURE,
    *_UNRELATED,
    *_LEGITIMATE_SUBSTRING,
)


# ---------------------------------------------------------------------------
# POSITIVES — names that must be reported
#
# All synthetic unless marked otherwise. Constructed in styles that public
# reporting on media-impersonation operations describes; none is asserted to
# have been observed anywhere.
# ---------------------------------------------------------------------------

# Shape 1: the exact brand label re-registered under a cheap or news-flavoured
# suffix. The signature move of the documented operations.
_SUFFIX_SWAP: tuple[Entry, ...] = (
    Entry(
        "lemonde.ltd",
        "lemonde.fr",
        MUST_DETECT,
        "exact brand label under .ltd, a suffix with no connection to the outlet",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "lefigaro.ltd",
        "lefigaro.fr",
        MUST_DETECT,
        "exact brand label under .ltd",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "liberation.ltd",
        "liberation.fr",
        MUST_DETECT,
        "exact brand label under .ltd",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "francetvinfo.ltd",
        "francetvinfo.fr",
        MUST_DETECT,
        "exact brand label under .ltd",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "lemonde.press",
        "lemonde.fr",
        MUST_DETECT,
        "brand label under a suffix chosen to read as journalism",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "lefigaro.news",
        "lefigaro.fr",
        MUST_DETECT,
        "brand label under .news",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "francetvinfo.info",
        "francetvinfo.fr",
        MUST_DETECT,
        "brand label under .info",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "liberation.media",
        "liberation.fr",
        MUST_DETECT,
        "brand label under .media",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "gouvernement.online",
        "gouvernement.fr",
        MUST_DETECT,
        "government brand label under a cheap generic suffix",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
    Entry(
        "service-public.top",
        "service-public.fr",
        MUST_DETECT,
        "public-services brand label under a bulk-registration suffix",
        PROV_SYNTH,
        ("suffix_swap",),
    ),
)

# Shape 2: brand plus a news-sounding word.
_BRAND_PLUS_WORD: tuple[Entry, ...] = (
    Entry(
        "lemonde-actu.info",
        "lemonde.fr",
        MUST_DETECT,
        "brand plus 'actu' under .info",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "lemonde-news.com",
        "lemonde.fr",
        MUST_DETECT,
        "brand plus 'news'",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "actu-lemonde.com",
        "lemonde.fr",
        MUST_DETECT,
        "news word prepended to the brand",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "lemondeinfo.click",
        "lemonde.fr",
        MUST_DETECT,
        "brand fused with 'info' under .click",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "lemonde-live.com",
        "lemonde.fr",
        MUST_DETECT,
        "brand plus 'live'",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "lefigaro-actu.top",
        "lefigaro.fr",
        MUST_DETECT,
        "brand plus 'actu' under .top",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "info-lefigaro.com",
        "lefigaro.fr",
        MUST_DETECT,
        "news word prepended to the brand",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "lefigarolive.com",
        "lefigaro.fr",
        MUST_DETECT,
        "brand fused with 'live'",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "liberation-news.info",
        "liberation.fr",
        MUST_DETECT,
        "brand plus 'news' under .info",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "francetvinfo-live.top",
        "francetvinfo.fr",
        MUST_DETECT,
        "brand plus 'live' under .top",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "gouvernement-info.com",
        "gouvernement.fr",
        MUST_DETECT,
        "government brand plus 'info'",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "gouvernement-officiel.info",
        "gouvernement.fr",
        MUST_DETECT,
        "brand plus 'officiel', the word that sells the forgery",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "service-public-demarches.online",
        "service-public.fr",
        MUST_DETECT,
        "brand plus 'demarches' — the shape used for benefits-fraud lures",
        PROV_SYNTH,
        ("brand_plus_word",),
    ),
    Entry(
        "figarolive.com",
        "lefigaro.fr",
        MUST_DETECT,
        "brand core word without the article, plus 'live' — still reads as the outlet",
        PROV_SYNTH,
        ("brand_plus_word", "hard"),
    ),
)

# Shape 3: brand plus a country/suffix token, and hyphen surgery.
_TOKEN_AND_HYPHEN: tuple[Entry, ...] = (
    Entry(
        "lemondefr.com",
        "lemonde.fr",
        MUST_DETECT,
        "the .fr suffix folded into the label, re-registered under .com",
        PROV_SYNTH,
        ("token_merge",),
    ),
    Entry(
        "lefigaro-fr.com",
        "lefigaro.fr",
        MUST_DETECT,
        "brand plus country token under .com",
        PROV_SYNTH,
        ("token_merge",),
    ),
    Entry(
        "gouvernement-fr.com",
        "gouvernement.fr",
        MUST_DETECT,
        "brand plus country token under .com",
        PROV_SYNTH,
        ("token_merge",),
    ),
    Entry(
        "service-public-fr.com",
        "service-public.fr",
        MUST_DETECT,
        "brand plus country token under .com",
        PROV_SYNTH,
        ("token_merge",),
    ),
    Entry(
        "le-monde.info",
        "lemonde.fr",
        MUST_DETECT,
        "hyphen inserted at the word boundary, cheap suffix",
        PROV_SYNTH,
        ("hyphenation",),
    ),
    Entry(
        "le-figaro.info",
        "lefigaro.fr",
        MUST_DETECT,
        "hyphen inserted at the word boundary, cheap suffix",
        PROV_SYNTH,
        ("hyphenation",),
    ),
    Entry(
        "francetv-info.com",
        "francetvinfo.fr",
        MUST_DETECT,
        "hyphen inserted between the two real words of the brand",
        PROV_SYNTH,
        ("hyphenation", "hard"),
    ),
    Entry(
        "france-tvinfo.com",
        "francetvinfo.fr",
        MUST_DETECT,
        "hyphen inserted at a different boundary of the same brand",
        PROV_SYNTH,
        ("hyphenation", "hard"),
    ),
    Entry(
        "servicepublic-fr.info",
        "service-public.fr",
        MUST_DETECT,
        "the brand's own hyphen removed and a country token hyphenated on",
        PROV_SYNTH,
        ("hyphenation", "hard"),
    ),
    Entry(
        "gouv-ernement.fr",
        "gouvernement.fr",
        MUST_DETECT,
        "hyphen inserted mid-word under the real suffix",
        PROV_SYNTH,
        ("hyphenation",),
    ),
)

# Shape 4: homoglyphs. Stored as A-labels, because that is what a certificate
# carries; the readable form is in the reason.
_HOMOGLYPH: tuple[Entry, ...] = (
    Entry(
        "xn--lemond-8of.com",
        "lemonde.fr",
        MUST_DETECT,
        "'lemondе.com' with a Cyrillic 'е' — indistinguishable in a browser",
        PROV_SYNTH,
        ("homoglyph", "idn"),
    ),
    Entry(
        "xn--lmonde-3of.news",
        "lemonde.fr",
        MUST_DETECT,
        "'lеmonde.news' with a Cyrillic 'е' in the first position",
        PROV_SYNTH,
        ("homoglyph", "idn"),
    ),
    Entry(
        "xn--lefigar-gjg.com",
        "lefigaro.fr",
        MUST_DETECT,
        "'lefigarо.com' with a Cyrillic 'о'",
        PROV_SYNTH,
        ("homoglyph", "idn"),
    ),
    Entry(
        "xn--frncetvinfo-zij.com",
        "francetvinfo.fr",
        MUST_DETECT,
        "'frаncetvinfo.com' with a Cyrillic 'а'",
        PROV_SYNTH,
        ("homoglyph", "idn"),
    ),
    Entry(
        "xn--liberatin-72h.top",
        "liberation.fr",
        MUST_DETECT,
        "'liberatiоn.top' with a Cyrillic 'о'",
        PROV_SYNTH,
        ("homoglyph", "idn"),
    ),
    Entry(
        "xn--lemond-gva.com",
        "lemonde.fr",
        MUST_DETECT,
        "'lemondé.com' — a Latin accented character, not another script; still "
        "a one-glance-identical disguise",
        PROV_SYNTH,
        ("homoglyph", "idn", "hard"),
    ),
    Entry(
        "xn--libration-d4a.info",
        "liberation.fr",
        MUST_DETECT,
        "'libération.info' — the accented spelling of the brand under a cheap suffix",
        PROV_SYNTH,
        ("homoglyph", "idn", "hard"),
    ),
    Entry(
        "xn--gouvernemnt-69a.fr",
        "gouvernement.fr",
        MUST_DETECT,
        "'gouvernemènt.fr' — one accent away from the government's own domain",
        PROV_SYNTH,
        ("homoglyph", "idn", "hard"),
    ),
    Entry(
        "1emonde.com",
        "lemonde.fr",
        MUST_DETECT,
        "digit one for lowercase L",
        PROV_SYNTH,
        ("homoglyph",),
    ),
    Entry(
        "iemonde.com",
        "lemonde.fr",
        MUST_DETECT,
        "lowercase i for lowercase L",
        PROV_SYNTH,
        ("homoglyph",),
    ),
    Entry(
        "lernonde.com",
        "lemonde.fr",
        MUST_DETECT,
        "'rn' rendering as 'm' at small sizes",
        PROV_SYNTH,
        ("homoglyph",),
    ),
    Entry(
        "lefigar0.com",
        "lefigaro.fr",
        MUST_DETECT,
        "digit zero for the letter o",
        PROV_SYNTH,
        ("homoglyph",),
    ),
    Entry(
        "lib3ration.com",
        "liberation.fr",
        MUST_DETECT,
        "digit three for the letter e",
        PROV_SYNTH,
        ("homoglyph",),
    ),
    Entry(
        "gouv3rnement.info",
        "gouvernement.fr",
        MUST_DETECT,
        "digit three for the letter e, cheap suffix",
        PROV_SYNTH,
        ("homoglyph",),
    ),
)

# Shape 5: ordinary typos — the registration that catches a mistyped URL.
_TYPO: tuple[Entry, ...] = (
    Entry(
        "lemondc.com",
        "lemonde.fr",
        MUST_DETECT,
        "final 'e' replaced by an adjacent key",
        PROV_SYNTH,
        ("typo", "hard"),
    ),
    Entry(
        "lemoned.com",
        "lemonde.fr",
        MUST_DETECT,
        "last two characters transposed",
        PROV_SYNTH,
        ("typo", "hard"),
    ),
    Entry(
        "lefigar.com",
        "lefigaro.fr",
        MUST_DETECT,
        "final character omitted",
        PROV_SYNTH,
        ("typo", "hard"),
    ),
    Entry(
        "lefigrao.com",
        "lefigaro.fr",
        MUST_DETECT,
        "two characters transposed mid-label",
        PROV_SYNTH,
        ("typo", "hard"),
    ),
    Entry(
        "liberaton.com",
        "liberation.fr",
        MUST_DETECT,
        "one character omitted",
        PROV_SYNTH,
        ("typo", "hard"),
    ),
    Entry(
        "gouvernemnt.fr",
        "gouvernement.fr",
        MUST_DETECT,
        "one character omitted under the real suffix",
        PROV_SYNTH,
        ("typo", "hard"),
    ),
    Entry(
        "francetvinof.com",
        "francetvinfo.fr",
        MUST_DETECT,
        "last two characters transposed",
        PROV_SYNTH,
        ("typo", "hard"),
    ),
    Entry(
        "servicepublic.info",
        "service-public.fr",
        MUST_DETECT,
        "the brand's hyphen dropped, cheap suffix",
        PROV_SYNTH,
        ("typo",),
    ),
)

# Shape 6: the brand appears only in the SUBDOMAIN of somebody else's
# registration. Documented reporting describes this repeatedly, and it is the
# shape a registrable-domain-only matcher structurally cannot see.
_SUBDOMAIN_CARRIER: tuple[Entry, ...] = (
    Entry(
        "lemonde-fr.example-host.com",
        "lemonde.fr",
        MUST_DETECT,
        "brand carried in the subdomain of a third-party registration",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "lemonde.paris-actu.com",
        "lemonde.fr",
        MUST_DETECT,
        "brand as the leftmost label of an unrelated news-sounding registration",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "lemonde.fr.actualite-live.com",
        "lemonde.fr",
        MUST_DETECT,
        "the full watched domain reproduced as a subdomain so the address bar "
        "reads 'lemonde.fr' first",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "abonnement.lemonde.fr.paiement-secure.net",
        "lemonde.fr",
        MUST_DETECT,
        "same trick with a payment lure in front",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "news-lemonde.z13.web.core.windows.net",
        "lemonde.fr",
        MUST_DETECT,
        "brand in a subdomain of a cloud object-storage host",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "cdn-lemonde.b-cdn.net",
        "lemonde.fr",
        MUST_DETECT,
        "brand in a subdomain of a CDN host, disguised as infrastructure",
        PROV_SYNTH,
        ("subdomain_carrier", "hard"),
    ),
    Entry(
        "lefigaro-fr.hosting-cheap.xyz",
        "lefigaro.fr",
        MUST_DETECT,
        "brand in the subdomain of a bulk-hosting registration",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "service-public.fr.demarches-en-ligne.top",
        "service-public.fr",
        MUST_DETECT,
        "full government domain reproduced as a subdomain of a lure registration",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "gouvernement.fr.aides-2026.online",
        "gouvernement.fr",
        MUST_DETECT,
        "same shape, benefits-scheme lure",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "francetvinfo.direct-tv.click",
        "francetvinfo.fr",
        MUST_DETECT,
        "brand as the leftmost label of an unrelated registration",
        PROV_SYNTH,
        ("subdomain_carrier",),
    ),
    Entry(
        "lemonde-fr.pages.dev",
        "lemonde.fr",
        MUST_DETECT,
        "brand under a free hosting platform whose suffix is a public suffix",
        PROV_SYNTH,
        ("subdomain_carrier", "hosting_psl"),
    ),
    Entry(
        "lemonde.netlify.app",
        "lemonde.fr",
        MUST_DETECT,
        "brand as a tenant name on a free hosting platform",
        PROV_SYNTH,
        ("subdomain_carrier", "hosting_psl"),
    ),
    Entry(
        "lemondefr.blogspot.com",
        "lemonde.fr",
        MUST_DETECT,
        "brand as a blog tenant — the cheapest possible staging ground",
        PROV_SYNTH,
        ("subdomain_carrier", "hosting_psl"),
    ),
)

# Shape 7: wildcards on impersonating registrations. A wildcard is not a reason
# to ignore a name.
_POSITIVE_WILDCARDS: tuple[Entry, ...] = (
    Entry(
        "*.lemonde-actu.com",
        "lemonde.fr",
        MUST_DETECT,
        "wildcard issued on an impersonating registration — must survive the "
        "same wildcard stripping that clears the brand's own wildcards",
        PROV_SYNTH,
        ("wildcard",),
    ),
    Entry(
        "*.lefigaro.ltd",
        "lefigaro.fr",
        MUST_DETECT,
        "wildcard on a brand label under a foreign suffix",
        PROV_SYNTH,
        ("wildcard",),
    ),
    Entry(
        "*.gouvernement-fr.info",
        "gouvernement.fr",
        MUST_DETECT,
        "wildcard on a government-impersonating registration",
        PROV_SYNTH,
        ("wildcard",),
    ),
)

POSITIVES: tuple[Entry, ...] = (
    *_SUFFIX_SWAP,
    *_BRAND_PLUS_WORD,
    *_TOKEN_AND_HYPHEN,
    *_HOMOGLYPH,
    *_TYPO,
    *_SUBDOMAIN_CARRIER,
    *_POSITIVE_WILDCARDS,
)

CORPUS: tuple[Entry, ...] = (*POSITIVES, *NEGATIVES)


# ---------------------------------------------------------------------------
# Scoring harness. Standard library only.
# ---------------------------------------------------------------------------


def evaluate(
    assess: Callable[[str, str], bool],
    corpus: Sequence[Entry] = CORPUS,
) -> dict[str, Any]:
    """Score a detector against the corpus.

    ``assess(name, watched) -> bool`` is called once per entry and must answer
    "would this name be reported against this watched domain".

    Returns a dict with ``precision``, ``recall``, ``f1``, the four counts, and
    ``misclassified`` — the entries that were got wrong, each paired with the
    kind of error, so a caller can see *what* changed and not only *how much*.
    Precision is defined as 1.0 when nothing was reported: an empty report has
    no false positives, and the recall figure is what says it is useless.
    """

    true_positive = 0
    false_positive: list[Entry] = []
    false_negative: list[Entry] = []
    true_negative = 0

    for entry in corpus:
        reported = bool(assess(entry.name, entry.watched))
        if entry.should_detect:
            if reported:
                true_positive += 1
            else:
                false_negative.append(entry)
        elif reported:
            false_positive.append(entry)
        else:
            true_negative += 1

    reported_total = true_positive + len(false_positive)
    expected_total = true_positive + len(false_negative)

    precision = true_positive / reported_total if reported_total else 1.0
    recall = true_positive / expected_total if expected_total else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positive": true_positive,
        "false_positive": len(false_positive),
        "false_negative": len(false_negative),
        "true_negative": true_negative,
        "total": len(corpus),
        "misclassified": [
            *(("false_positive", entry) for entry in false_positive),
            *(("false_negative", entry) for entry in false_negative),
        ],
    }


def format_report(result: dict[str, Any]) -> str:
    """A plain-text rendering of :func:`evaluate`'s output."""

    lines = [
        f"precision {result['precision']:.3f}   "
        f"recall {result['recall']:.3f}   "
        f"f1 {result['f1']:.3f}",
        f"TP {result['true_positive']}  FP {result['false_positive']}  "
        f"FN {result['false_negative']}  TN {result['true_negative']}  "
        f"(n={result['total']})",
    ]
    for kind, entry in result["misclassified"]:
        marker = "FP" if kind == "false_positive" else "FN"
        tags = ",".join(entry.tags) or "-"
        lines.append(f"  {marker}  {entry.name}  vs {entry.watched}  [{tags}]  {entry.reason}")
    return "\n".join(lines)


def variant_matcher_assess(variants: int = 500) -> Callable[[str, str], bool]:
    """An ``assess`` callable wrapping the current ``VariantMatcher``.

    Imported lazily so the corpus itself stays importable with nothing but the
    standard library. A name counts as reported when the matcher ties it to the
    watched domain the entry names — being matched to a *different* brand is
    not a detection of this one.
    """

    from ctwatch.matching.matcher import VariantMatcher
    from ctwatch.store.models import WatchTarget

    targets = [
        WatchTarget(id=index, brand=domain, canonical_domain=domain, keywords=keywords)
        for index, (domain, keywords) in enumerate(WATCHLIST.items(), start=1)
    ]
    matcher = VariantMatcher.build(targets, variants=variants)

    def assess(name: str, watched: str) -> bool:
        match = matcher.match(name)
        return match is not None and match.target.canonical_domain == watched

    return assess


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    print(format_report(evaluate(variant_matcher_assess())))
