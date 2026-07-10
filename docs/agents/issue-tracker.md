# Issue tracker: Local Markdown

Issues and PRDs for this repo live as Markdown files in `.scratch/`.

## Conventions

- One feature per directory: `.scratch/<feature-slug>/`
- The PRD is `.scratch/<feature-slug>/PRD.md`.
- Implementation issues are
  `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`.
- Triage state is recorded as a `Status:` line near the top of each issue file.
- Comments and conversation history append to the bottom of the file under a
  `## Comments` heading.

## When a skill says "publish to the issue tracker"

Create a new file under `.scratch/<feature-slug>/`, creating the directory if
needed.

## When a skill says "fetch the relevant ticket"

Read the file at the referenced path. The user will normally pass the path or
issue number directly.

## Wayfinding operations

The `/wayfinder` skill represents a map as one file with one child file per
ticket.

- **Map:** `.scratch/<effort>/map.md` contains the destination, notes,
  decisions so far, fog, and out-of-scope sections.
- **Child ticket:** `.scratch/<effort>/issues/NN-<slug>.md`, numbered from `01`,
  contains the question. A `Type:` line records `research`, `prototype`,
  `grilling`, or `task`; a `Status:` line records `open`, `claimed`, or
  `resolved`.
- **Blocking:** a `Blocked by: NN, NN` line appears near the top. A ticket is
  unblocked when every listed ticket is `resolved`.
- **Frontier:** scan the effort's `issues/` directory for tickets that are open,
  unblocked, and unclaimed. The first ticket by number wins.
- **Claim:** set `Status: claimed` and save before starting work.
- **Resolve:** append the answer under `## Answer`, set `Status: resolved`, then
  append a gist and link to the map's **Decisions so far** section.
