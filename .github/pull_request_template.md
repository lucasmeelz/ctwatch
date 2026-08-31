## What this changes

<!-- Why, rather than what. The diff already says what. -->

## Checklist

- [ ] `uv run pytest` passes, and no test opens a network connection
- [ ] `uv run ruff check .` and `uv run mypy` pass
- [ ] Any new scoring criterion is declared in `SCORING_CRITERIA`
- [ ] Any new rule that produces a number also produces the sentence that
      justifies it
- [ ] No new outbound host, or the host is declared in configuration or read
      from an authoritative bootstrap document
- [ ] `CHANGELOG.md` updated under Unreleased if this is user-visible
