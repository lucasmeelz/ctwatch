# ctwatch

Detect and document domains impersonating news outlets and public institutions,
using Certificate Transparency logs.

## The problem

Influence operations register domains that read like the real thing —
`lemonde.fr` becomes `lemonde-actu.info`, `1emonde.fr`, or a spelling with a
Cyrillic "о" — and publish fabricated articles under them. Because every
certificate authority must log the TLS certificates it issues to public,
append-only registries, these domains become observable at the moment the
certificate is issued, which is usually before any content goes live.

The difficulty is that you cannot search for what you cannot spell. A
substring search for `lemonde` will never match `lemоnde.fr`: that name is
stored as `xn--lemnde-yqf.fr`, and it shares no characters with the original.
ctwatch generates the candidate spellings first and looks each of them up, and
matches the live certificate feed against the way names *read* rather than the
way they are written.

## Three commands

```
uv run ctwatch init
uv run ctwatch scan --target lemonde.fr --variants 100
uv run ctwatch findings
```

`init` writes a configuration file, a database and an evidence directory, and
prints every host the tool is allowed to contact. Those three live in the
directory you run it from, the way a repository does — so run `init` in the
folder where you want to keep the investigation, not necessarily in the source
tree. Every later command reads them from the current directory, or from
wherever `--config` points. `scan` asks the Certificate
Transparency aggregators about the watched names and the generated variants.
`findings` lists what came back, scored and explained.

To see what a scan would look for without contacting anything at all:

```
uv run ctwatch permutations lemonde.fr --limit 20
```

## Installation

Requires Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```
git clone https://github.com/lucasmeelz/ctwatch
cd ctwatch
uv sync
uv run ctwatch init
```

No API key is required. See [Sources and their limits](#sources-and-their-limits)
for what that means in practice.

## What it does

**Generates candidates.** Around five hundred per watched brand: keyboard slips
on several layouts, omissions, transpositions, hyphenation, bit flips, suffix
swaps, brand-plus-keyword constructions, and lookalike spellings drawn from the
Unicode confusables table together with the plain ASCII ones no Unicode table
records (`1` for `l`, `rn` for `m`, `0` for `o`).

**Scores what it finds, and shows its working.** Every score is a sum of named
criteria, each with the sentence that justifies it:

| Criterion | Value | Weight | Contribution | Reason |
| --- | --- | --- | --- | --- |
| levenshtein | 0.58 | 0.30 | 0.175 | 5 character edit(s) away from 'lemonde' |
| homoglyph | 0.00 | 0.25 | 0.000 | every difference from the watched name is visible |
| keyword_combo | 1.00 | 0.20 | 0.200 | contains 'lemonde' together with 'actu' |
| tld_risk | 1.00 | 0.15 | 0.150 | 'info' is on the high-risk suffix list |
| cert_age | 1.00 | 0.10 | 0.100 | certificate issued 1 day(s) ago |

A criterion that scored nothing stays in the table: an absent signal is
information, not an omission.

**Suppresses the brand's own domains.** The watched domain and everything under
it are the brand's own site, and are never reported — the first real scan of
`lemonde.fr` turned up 87 of them, from `blog.lemonde.fr` to
`salon-artistique.lemonde.fr`, and a genuine finding would have been buried
among them. Beyond that, newsrooms register lookalike domains themselves,
defensively, by the dozen; those are recognised either from the `allowlist` in
the configuration or from appearing on the same certificate as the watched
name, which settles ownership without anyone having to declare anything. Unlike
subdomains, those suppressions are judgements, so they are kept and can be
inspected with `--all`: a suppression nobody can inspect is a suppression
nobody can trust.

**Rates confidence separately from suspicion.** An Admiralty-style code keeps
two questions apart that a single number conflates: how far the source can be
relied on (a letter) and how far the assessment can be believed (a digit).
`B2` is "usually reliable source, probably true". Neither `A` nor `1` is ever
assigned automatically — both mean corroborated, and that is a human's call.

**Enriches passively.** Registration data from the registry over RDAP,
resolution over DNS-over-HTTPS, and page renderings already performed by
urlscan.io. Then groups domains by what they share: address, nameserver,
certificate, hosting network, registrar. One lookalike is a nuisance; twenty on
one address, registered the same week through the same registrar, is a
campaign.

**Watches the live feed.** Looking one candidate up costs one request, so five
hundred candidates across six brands is an hour of polling. On the CertStream
feed, certificates arrive on their own and each is checked against the entire
candidate set in a single lookup. Nothing that fails to match is stored.

**Documents what it found.** A written report, a CSV, a single-file dashboard,
and an evidence bundle — a folder containing the raw responses, their digests,
and instructions to verify them with `sha256sum`. Nothing in this project is
needed to read it.

## Driving it

```
ctwatch init                                  # configuration, database, evidence directory
ctwatch target add --brand "Le Monde" --domain lemonde.fr --keyword actu
ctwatch target list

ctwatch permutations lemonde.fr --limit 50    # what a scan would look for. Contacts nothing.
ctwatch scan --target lemonde.fr --variants 100 --since 30d
ctwatch findings --min-score 0.4

ctwatch enrich --finding-id 42                # RDAP, DNS, urlscan, pivots
ctwatch review 42 --status confirmed --note "published 2026-03-12"

ctwatch dashboard --out dashboard.html --open
ctwatch report --target lemonde.fr --format markdown --out report.md
ctwatch evidence export 42

ctwatch monitor                               # follow the live feed
```

Every command accepts `--json`, so the tool can sit inside someone else's
pipeline. The table output is the convenience; the JSON is the contract.

### The dashboard

From the directory holding your `ctwatch.yaml`:

```
uv run ctwatch dashboard --min-score 0 --all --out dashboard.html --open
```

One HTML file with its data inside it. Sort by any column, filter by brand,
status or score, and select a row to see the score breakdown, the certificates,
the registration, the resolution, the pivots and the digests of the archived
responses. It works from the filesystem with no server and no network, so it
can live next to the evidence or be sent to someone who has neither Python nor
this repository.

## Sources and their limits

Three services, none of which requires payment, and all of which have bad days.
This was the state of all three on 31 August 2026, during development:

| Source | Key needed | What happened |
| --- | --- | --- |
| Cert Spotter | no, but see below | worked, then `429 rate_limited` once the free quota was spent |
| crt.sh | no | unavailable for the whole session — 502s and read timeouts |
| CertStream (public) | no | accepted the connection and then sent nothing at all |

None of this is unusual, and the tool is built around it. Sources are tried in
order and the first that answers wins, so a scan keeps working while one is
down. A service that answers "you have exceeded the rate limit" is not asked
again for the rest of the run. A feed that goes quiet is treated as
disconnected rather than healthy, and the monitor falls back to polling instead
of sitting silently on a dead socket.

For sustained use, two things are worth doing:

- **A Cert Spotter API key** (`CERTSPOTTER_API_KEY`), free to obtain, which
  raises the quota considerably.
- **A self-hosted CertStream server**, pointed at with `sources.certstream.url`.
  The public one cannot be relied on for anything running unattended.

Neither is required to use the tool. Both are the difference between a scan
that finishes and a scan that gives up.

## The watchlist

`ctwatch init` ships a starting watchlist of about seventy organisations whose
impersonation is already public record: French national press and broadcast,
the news agency, government portals — including the tax, health and identity
services that are copied for fraud as often as for influence — defence and
cyber-security bodies, European and international institutions, and the foreign
outlets cloned by the same operations that target French ones.

It is a starting point, not a recommendation. Cut it down to what you actually
care about, because the two ways of using it cost very different things:

- **A few targets you follow closely.** `ctwatch scan --target lemonde.fr
  --variants 200` looks up two hundred candidate names, which is two hundred
  requests. Scan warns you before making a number of requests a free quota will
  not absorb.
- **A long list you want covered broadly.** `ctwatch monitor` checks every
  certificate that goes past against the entire watchlist in one lookup —
  roughly 34,000 candidate names across seventy brands, matched in about
  thirteen microseconds each. Coverage costs nothing per name here, which is
  the whole reason the live feed exists.

## Configuration

`ctwatch.yaml`, written by `ctwatch init`:

```yaml
targets:
  - brand: "Le Monde"
    canonical_domains: ["lemonde.fr"]
    allowlist: ["lemonde-abonnements.fr"]   # known defensive registrations
    keywords: ["actu", "info", "news", "live"]

scoring:
  weights:
    levenshtein: 0.3
    homoglyph: 0.25
    keyword_combo: 0.2
    tld_risk: 0.15
    cert_age: 0.1
  review_threshold: 0.5

sources:
  order: ["certspotter", "crtsh"]
  strategy: "failover"
```

No secret is ever stored in it. API keys are read from the environment;
`.env.example` documents which.

## What it does not do

These limits are structural. They are the reason the tool can be used safely by
someone whose safety depends on not being noticed.

- **It never contacts a domain it is investigating.** Not once, not to check
  whether it resolves, not to see what is on it. This is enforced by the
  network layer rather than by discipline: every request passes through a host
  allowlist built from the configuration, and any host outside it is refused,
  redirects included. Page renderings are performed by urlscan.io so that the
  analyst's address never appears in the operator's logs.
- **It does not report, notify a registrar, or file a takedown.** It produces
  documents. A person decides what to do with them.
- **It does not collect personal data.** Domains, certificates, infrastructure
  addresses. Not people.
- **It has no offensive capability**, including for testing.
- **It respects published rate limits**, and stops asking a service that has
  told it to stop.

Read [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) before using this against
anything real.

## Verifying a finding

Every response that feeds a finding is archived when it is retrieved, with the
endpoint, the UTC timestamp, and the SHA-256 of the uncompressed body. To hand
someone a finding they can check themselves:

```
uv run ctwatch evidence export 42
cd exports/finding-42
sha256sum -c MANIFEST.sha256
```

The archive is plain gzip and the digests are plain SHA-256. Nothing in this
project is required to verify them, which is the point.

## Development

```
uv sync
uv run pytest
uv run ruff check .
uv run mypy
```

The test suite runs entirely on recorded responses and fails if anything opens
a network connection. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for the third-party data this
project vendors.
