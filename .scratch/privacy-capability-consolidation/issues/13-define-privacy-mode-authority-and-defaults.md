# Define privacy-mode authority and defaults

Type: grilling
Status: resolved
Blocked by: 05

## Question

What shared privacy policy should determine the default mode, the meaning of an
explicit public opt-out, and resolution of global versus node-local privacy
settings across workflow storage, queued execution, artifacts, routes, and UI?

Keep fail-closed enforcement in `helto-privacy` while letting each consumer
integration declare the product setting that supplies privacy mode and map any
legacy setting shapes.

## Comments

### Current behavior compared

- `comfyui-utils` defaults most privacy-capable nodes, selector state, load/save
  previews, and queue-manager persistence to private. Those choices are separate
  booleans, however, and several backend routes trust a request's `privacy`
  query/body value when deciding whether to create a plaintext or encrypted
  derivative. Some private-to-public transitions lack one shared authorization,
  confirmation, and rewrite contract.
- AIO Generate and the Ideogram prompt builder default their node-local
  `privacy_mode` widgets to false. Krea's private prompt correctly inherits the
  linked Generate node instead of adding another toggle, and prompt-library
  saves inherit the builder mode in the UI, but the backend still ultimately
  accepts a caller-supplied private/public choice.
- Smart Prompt defaults `privacyMode` to false. Disabling it requires a warning
  confirmation and writes plaintext; imports preserve the destination mode, but
  mode semantics remain embedded in Smart Prompt's product state rather than a
  shared policy resolver.
- Director is closest to the target: its global setting defaults and normalizes
  to private, explicit `false` remains durable, requests may strengthen but not
  weaken the global mode, disabling requires authorization, and enabling first
  purges known plaintext caches. Some direct view routes and product-specific UI
  still sit outside that authority boundary.
- `helto-privacy` currently defaults recovery descriptors to private but has no
  canonical mode resolver or transition service. Its HTTP guard is also a no-op
  before a keystore exists, which cannot remain the behavior for an operation
  whose effective mode is private after the coordinated cutover.

### Recommended contract

Adopt one shared declared/effective policy model owned by `helto-privacy`:

1. Every consumer privacy source maps to a three-state **declared privacy mode**:
   `inherit`, `private`, or `public`. New privacy-capable state declares
   `inherit`; the shared base default is private. Missing, malformed, unknown,
   or incompletely registered mode data therefore resolves private and never
   public by accident.
2. A known legacy `true` maps to declared private and a known explicit `false`
   maps to a durable explicit public opt-out. Absence is not an opt-out. Public
   examples and intentionally inspectable fixtures must declare public
   explicitly rather than relying on an old default.
3. A scoped global policy supplies both a default and, when private, a
   **privacy floor**. Global public is a default that local private state may
   strengthen; global private is a floor that no node, route, request, or local
   public declaration may weaken. Without a scoped global declaration, the
   shared private base default applies but an explicit local public opt-out is
   allowed when no floor exists.
4. Protected resources and data flow create floors too. Any private upstream
   input, parent state, loaded private record, privacy artifact, or active
   private execution snapshot forces derived state private. Multiple inputs use
   the most protective result. A request may opt into stronger protection for
   one operation but `privacy=false` can never weaken the server-resolved mode.
5. The **effective privacy mode** is resolved server-side from the applicable
   base/scoped default, declared local mode, active floors, and the current
   protection state of the data. Frontend code displays that result and its
   sources but is not authoritative. Missing packages, registrations, settings,
   or keystores block private operations instead of degrading to public.
6. An explicit public opt-out is a request to declassify, not permission to
   silently reinterpret existing ciphertext or artifacts as public. Moving
   private data to public requires an authorized, warned, all-or-nothing
   declassification that rewrites protected storage and retires private
   derivatives. Failure leaves the effective state private. A previously
   suppressed public declaration cannot auto-declassify data when a global or
   upstream floor later disappears.
7. Moving public data to private is likewise transactional: encrypt every
   registered sensitive value, migrate or replace artifacts, and remove every
   registered plaintext derivative before the UI reports private. Failure enters
   a blocked transition state where save, queue, and serving are refused until
   the user completes the protection or explicitly returns to the prior public
   state; the system never claims protection it did not achieve.
8. Records and artifacts retain the effective mode captured when written;
   queued execution retains the mode in its privacy snapshot. Later toggle
   changes do not retroactively weaken them. Reuse, preview, export, and derived
   writes resolve mode again and may only preserve or strengthen protection
   unless an explicit declassification succeeds.
9. Shared UI shows declared mode, effective mode, inheritance source, and every
   active floor, and owns confirmations and transition status. Consumer UIs may
   mount the common control beside product settings but must not restate its
   semantics or implement a weaker toggle.

`helto-privacy` owns the base default, scoped policy/floor resolution, mode
normalization, transition transactions, server enforcement, status UI, and
fail-closed errors. Consumer integrations own only the location of their product
setting, its scope and parent/upstream relationships, legacy-shape mapping,
sensitive-state projection, and the domain rewrite callbacks invoked by the
shared transition.

## Answer

The user chose private as the canonical default. New privacy-capable state,
missing or malformed declarations, incomplete registrations, and inherited
state without a nearer valid declaration therefore resolve to private. A
known, explicit `false` remains a durable public opt-out when no privacy floor
applies; public is never inferred from absence, failure, or an old product
default.

Every consumer maps its existing setting to `inherit`, `private`, or `public`,
but `helto-privacy` resolves the effective mode on the server. A scoped private
global policy and any private upstream input, parent state, loaded record,
artifact, or execution snapshot impose a privacy floor that local state and
request parameters cannot weaken. Requests may strengthen public state to
private for an operation, but cannot use `privacy=false` to bypass an effective
private result.

Changing effective protection is a transaction, not a presentation toggle.
Private-to-public declassification requires authorization, a warning, and a
complete rewrite and retirement of protected derivatives; failure leaves the
state private. Public-to-private protection must encrypt all registered values,
migrate artifacts, and purge registered plaintext derivatives before reporting
success. Incomplete transitions block save, queue, serving, and execution
rather than claiming a mode the system has not established.

Records, artifacts, and queued executions retain the effective mode captured
when they were created. Later setting changes cannot weaken that captured mode.
Shared UI displays declared and effective modes, inheritance sources, active
floors, and transition state, while the server remains authoritative across
storage, routes, artifacts, serialization, and execution. The durable rationale
is recorded in
[ADR 0007](../../../docs/adr/0007-default-private-and-resolve-mode-server-side.md).
