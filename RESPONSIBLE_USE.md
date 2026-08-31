# Responsible use

ctwatch exists because people who investigate coordinated impersonation are
themselves targets. Everything below follows from that, and none of it is
optional.

## What the tool guarantees

**It never contacts a domain under investigation.** No HTTP request, no port
scan, no crawl, not even a DNS lookup sent in the clear. This is not a
convention that a future contributor might forget: every outbound request
passes through a host allowlist assembled from the configuration file, and any
host outside it is refused before the connection is opened, redirects included.
Run `ctwatch init` to print the full list.

The one case that could not be listed in advance is RDAP, where several hundred
registries each run their own server. Those hosts are read from IANA's
bootstrap document and added with that origin recorded, so every permitted host
can be traced to something that is not the domain being investigated. The
allowlist reports where each of its entries came from.

**Page renderings go through a third party.** urlscan.io renders suspicious
pages from its own infrastructure. The analyst's address never reaches the
operator, and the operator learns nothing about who is looking.

Note that submitting a page to urlscan is a different act from searching its
archive. A submission is a real visit and, if public, is visible to anyone
watching urlscan — including the operator. ctwatch only searches. Submission is
deliberately not implemented.

## What the tool refuses to do

- Report domains, contact registrars, or file takedown requests. It produces
  documents; a person decides what happens next.
- Collect information about people. It handles domains, certificates and
  infrastructure.
- Anything offensive, including for testing.
- Exceed published rate limits. A service that answers "you have exceeded the
  rate limit" is not asked again for the rest of the run.

If you find yourself wanting to add any of these, the answer is no. That is not
a matter of taste: a tool that occasionally touches its targets is a tool that
cannot be trusted by the people who most need it.

## What it asks of you

**Do not open the domains you find.** The tool is careful so that your
investigation stays invisible; loading a page in your own browser undoes that
in one click. Use the urlscan links in the report.

**Do not treat a score as a verdict.** The score says a name resembles a
watched brand and the certificate is recent. It says nothing about who
registered it or why. Newsrooms register lookalike domains defensively;
so do squatters with no political intent; so do people who simply have a
similar name. `ctwatch review` exists so that a human judgement can be recorded
and preserved.

**Check before you publish.** The evidence bundle exists to be checked, by you
first. `sha256sum -c MANIFEST.sha256` takes a second and is the difference
between a claim and a documented claim.

**Consider who else is exposed.** A report naming domains may also name the
hosting provider, the registrar, and other customers who share an address with
the operation. They are not the subject of the investigation.

## Data you accumulate

The database and the evidence directory hold everything the tool retrieved.
They are excluded from version control by default. They contain no personal
data, but they do document what you were looking at and when, which in some
circumstances is sensitive about *you*. Store them accordingly.

## Reporting a problem with this tool

Security issues: see [SECURITY.md](SECURITY.md). If you believe ctwatch has
contacted something it should not have, that is a serious defect and we want to
know immediately.
