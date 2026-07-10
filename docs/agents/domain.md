# Domain Docs

This is a single-context repository. Engineering skills should use the domain
documentation below when exploring or changing the codebase.

## Before exploring, read these

- `CONTEXT.md` at the repository root, when it exists.
- ADRs under `docs/adr/` that touch the area being explored.

If either location does not exist, proceed silently. The `/domain-modeling`
skill creates these files lazily when terminology or architectural decisions
are actually resolved.

## File structure

```text
/
├── CONTEXT.md
├── docs/
│   └── adr/
│       ├── 0001-example-decision.md
│       └── 0002-another-decision.md
└── helto_privacy/
```

## Use the glossary's vocabulary

When output names a domain concept in an issue title, proposal, hypothesis, or
test, use the term defined in `CONTEXT.md`. Do not drift to synonyms the
glossary explicitly avoids.

If a needed concept is missing, reconsider whether the codebase already uses a
different term or record the gap for `/domain-modeling`.

## Flag ADR conflicts

If proposed work contradicts an existing ADR, surface the conflict explicitly
instead of silently overriding the decision.
