# Helto - Agent instructions

## Coding instructions

- When writing commit messages, never auto-add the agent as co-author.
- When making technical decisions, do not give much weight to development costs.
- Apply that same high standard to engineering excellence: lint, test failures,
  and test flakiness. If you see one, even if it is not caused by what you are
  working on right now, still get it fixed.
- Use `gh-axi` for GitHub and `chrome-devtools-axi` for browser automation.

## Agent skills

### Issue tracker

Issues are tracked as local Markdown under `.scratch/`; external PRs are not a
triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default five-role triage vocabulary. See
`docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. See `docs/agents/domain.md`.
