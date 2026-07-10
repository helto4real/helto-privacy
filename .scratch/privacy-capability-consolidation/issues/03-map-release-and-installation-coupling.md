# Map release and installation coupling

Type: research
Status: resolved
Blocked by: none

## Question

How do the four consumer packs pin, import, register, and fall back around
`helto-privacy`, and what release, load-order, and installation constraints must
the specification account for during a coordinated cutover?

Capture the findings as a linked Markdown research asset; do not design the
migration sequence yet.

## Answer

Research asset: [Release and installation coupling](../research/release-and-installation-coupling.md)

All consumer packs use one installed `helto_privacy` distribution and one
module instance inside a ComfyUI process; their dependency pins do not create
isolated copies. The declarations are already inconsistent: Utils, AIO, and
Smart Prompt pin `v0.3.0`, while Director pins `v0.2.0` and omits the package
from its `pyproject.toml`. The older release lacks the shared recovery browser
contract used by the other consumers.

ComfyUI imports custom nodes sequentially in unsorted directory order. Shared
route registration is first-successful-call wins and idempotent, but every
consumer registers only once and browser wrappers memoize failed module loads.
The supported cutover therefore cannot depend on a pack loading first and must
provide a guaranteed registration/retry lifecycle.

Missing-package behavior is also inconsistent: Utils and Smart Prompt are hard
dependencies, Director silently falls back to a vendored keystore and parallel
privacy surface, and AIO keeps loading while replacing a missing token guard
with authorization success. That AIO behavior is a current fail-open
installation hazard.

The specification must require one machine-readable shared protocol/capability
contract, synchronized immutable dependency declarations and install docs,
strict missing/incompatible-package failures for every private operation, an
explicit decision on Director's fallback boundary, release identity for the
five-repository supported set, and clean-environment/load-order acceptance.
These are constraints for the later migration/release decision; this ticket
does not choose their implementation order.
