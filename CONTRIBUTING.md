# Contributing

Thank you for considering it. A few things are worth knowing before you start.

## The one rule that is not negotiable

ctwatch must never contact a domain it is investigating. Not to check whether
it resolves, not to fetch a favicon, not "just for testing". People use this
tool in situations where being noticed has consequences.

Practically, this means every outbound request goes through
`ctwatch.net.client.PassiveHttpClient` and its host allowlist. If you find
yourself wanting to bypass that, or to add a host that is not declared in the
configuration or read from an authoritative bootstrap document, please open an
issue and describe the problem rather than the workaround.

The same applies to the other boundaries described in
[RESPONSIBLE_USE.md](RESPONSIBLE_USE.md): no reporting or takedown automation,
no personal data, nothing offensive.

## Getting set up

```
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

`pre-commit install` will run the same checks before each commit.

## Tests

The suite runs entirely on recorded responses. An autouse fixture fails any
test that opens a network connection, which is deliberate: a test that reaches
the internet is either flaky or contacting something it should not.

New responses go in `tests/fixtures/` as files, hand-written where possible.
Please do not paste real data about a third party's infrastructure into a
fixture; the existing ones use invented lookalike domains for that reason.

Two areas are written test-first, because getting them subtly wrong produces a
tool that looks like it works:

- **Permutations and homoglyphs.** Every technique has its expected output
  pinned before it is implemented. If a name can be reached by more than one
  technique, it is attributed to the most plausible one.
- **Scoring.** The requirement is not that suspicious names score higher. It is
  that every point of a score is attributable to a named criterion with a
  sentence attached, and that a criterion scoring zero still appears.

## Explanations are part of the output

Any rule that produces a number must also produce the sentence that justifies
it, in language a journalist can put in an article and defend. `0.42` is not a
finding. "contains 'lemonde' together with 'actu'" is.

If you add a scoring criterion, add it to `SCORING_CRITERIA` in `config.py` so
that a typo in a configuration file fails at load time rather than silently
dropping a signal.

## Commits

Conventional prefixes: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`.
One change per commit. The message should say why, not what — the diff already
says what.

## Third-party data

Two data files are vendored: the Unicode confusables table and the Public
Suffix List. Both have refresh scripts in `scripts/`. Run the script, review
the diff, and commit it; do not edit the files by hand, and please keep
[NOTICE](NOTICE) accurate if the sources change.
