# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The error raised when no configuration is found now says where ctwatch
  looked and that its state is per-directory. Telling someone to run `init`
  is unhelpful when they have already run it somewhere else.

## [0.1.0] — 2026-08-31

First release.

### Added

- Candidate generation from a watched domain: keyboard slips across several
  layouts, omission, transposition, repetition, insertion, hyphenation, vowel
  swaps, bit flips, suffix folding and TLD swaps, over the registrable label
  only.
- Homoglyph generation from a reduced Unicode confusables table, together with
  the plain ASCII lookalikes no Unicode table records — `1` for `l`, `rn` for
  `m`, `0` for `o` — plus whole-word substitution into a single script.
- Certificate Transparency sources: Cert Spotter, which returns certificate
  fingerprints, and crt.sh. Sources are tried in order and the first that
  answers wins.
- Composite scoring with a per-criterion breakdown, each criterion carrying the
  sentence that justifies it, and an Admiralty-style confidence rating that
  keeps source reliability separate from information credibility.
- Suppression of the watched brand's own domains, from the configuration and
  from shared certificates.
- Passive enrichment: RDAP over hosts read from IANA's bootstrap document, DNS
  over HTTPS, and urlscan.io archive search. Pivots by address, nameserver,
  mail exchange, certificate, hosting network and registrar.
- Live monitoring of the CertStream feed, with matching against the whole
  candidate set in a single lookup, and a polling fallback when the feed cannot
  be kept open.
- Console, JSON Lines and webhook notifiers.
- `ctwatch review`, recording a human verdict on a finding that survives every
  later rescan and rescore.
- Reports in Markdown and CSV, a single-file HTML dashboard, and self-contained
  evidence bundles verifiable with `sha256sum` alone.
- A host allowlist enforced by the network transport, reporting the origin of
  every permitted host.

[Unreleased]: https://github.com/lucasmeelz/ctwatch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lucasmeelz/ctwatch/releases/tag/v0.1.0
