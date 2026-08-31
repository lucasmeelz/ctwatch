# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's private vulnerability
reporting on this repository, rather than by opening a public issue.

Include what you did, what happened, and what you expected. A proof of concept
helps; it does not need to be polished.

You should get an acknowledgement within a few days. If a fix is warranted, we
will agree a disclosure timeline with you before publishing.

## What counts, and what counts most

Ordinary vulnerability classes apply — anything that lets an attacker run code,
read files, or escalate through a ctwatch installation.

Two categories matter more here than they would in most projects:

**Anything that causes ctwatch to contact a domain under investigation.** The
tool's central promise is that looking at a domain does not touch it. A path
that breaks that — a bypass of the host allowlist, a redirect that escapes it,
a code path that resolves or fetches a watched name directly — is a serious
defect even if it looks harmless, because it can expose the person running the
tool. Report it as a security issue.

**Anything that lets untrusted input change what a report says.** Domain names
and certificate contents come from Certificate Transparency logs, which anyone
can write to. If a crafted name can inject content into a report, a dashboard
or an evidence bundle, that is a security issue: these artefacts are used to
support published claims.

## Out of scope

- The third-party services ctwatch queries. Report those to their operators.
- Rate limiting or availability of those services.
- Findings produced by the tool. A false positive is a bug, not a
  vulnerability; please open an ordinary issue.
