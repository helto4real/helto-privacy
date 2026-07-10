# Place consumer-specific privacy metadata

Type: grilling
Status: resolved
Blocked by: 01

## Question

Where should concrete node types, sensitive-field definitions, schema names,
runtime reset hooks, and other consumer-specific privacy metadata live: in a
first-party catalog owned by `helto-privacy`, in thin registrations owned by
consumer packs, or behind another shared boundary?

Resolve this with the human after the capability inventory makes the real
variation visible.

## Comments

### Placement prompt

Three placements were compared against the current recovery descriptors,
release coupling, and the agreed ownership boundary:

- A first-party catalog inside `helto-privacy` gives one visible list, but
  couples the shared package to every consumer node rename, widget layout, and
  runtime reset change. Product callbacks would also force the shared package
  to know consumer UI internals.
- Thin consumer registrations keep product facts beside the product code while
  `helto-privacy` owns the metadata contract, validation, registry, registration
  lifecycle, privacy behavior, and generic UI. The shared package can reject
  invalid or incompatible registrations without knowing concrete node names.
- A hybrid static catalog plus consumer callbacks splits one declaration
  across repositories, creating two sources of truth without adding a real
  adapter.

Recommended placement: thin consumer-owned registrations across a shared,
order-independent registration seam. Production `helto-privacy` stays generic;
consumer node names may appear only in shared contract fixtures, examples, and
documentation. Exact legacy format readers remain shared capabilities, while
consumer registrations identify the product locations to which they apply.

## Answer

The user approved the recommended placement: consumer privacy metadata lives
with each consumer pack as a thin registration across an interface owned by
`helto-privacy`.

`helto-privacy` owns the registration contract and version, validation,
duplicate/conflict handling, order-independent lifecycle, registry and
introspection, shared privacy behavior, and generic UI. Invalid or incompatible
registrations must fail readably, and absence of a required registration must
never weaken a private operation.

Each consumer registration owns only its product facts and adapters: source and
node identifiers, sensitive field/property locations and defaults, privacy-mode
source, schema and purpose identifiers, product state projections, and runtime
reset behavior. These declarations change with the product and stay beside the
product code.

Production `helto-privacy` must not hard-code the four current packs' node
names, widget layouts, or runtime objects. Such names are allowed in shared
contract fixtures, examples, and documentation. Exact legacy decoders remain
shared capabilities because their privacy semantics need one implementation;
consumer registrations identify the product locations where those readers may
apply.

A shared first-party catalog was rejected because a consumer-only rename or
reset change would require a shared-package release. A hybrid static catalog
was rejected because it would split one declaration across repositories and
create two sources of truth. The durable rationale is recorded in
[ADR 0003](../../../docs/adr/0003-keep-consumer-privacy-metadata-with-consumers.md).
