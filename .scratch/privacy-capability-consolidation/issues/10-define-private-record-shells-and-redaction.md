# Define private record shells and redaction

Type: grilling
Status: resolved
Blocked by: 02, 05

## Question

What privacy contract should govern record libraries and metadata projections:
which fields are sensitive, what may appear in a locked/listed public shell,
when use or preview operations may decrypt, what remains possible when decrypt
fails, and how should paths, logs, errors, filenames, and diagnostic metadata
be redacted?

Resolve the policy across AIO prompt-library records, Director project and
character records, take metadata, private media routes, and analogous future
records without defining their product schemas.

## Comments

### Current behavior compared

- The AIO prompt library encrypts the prompt state, name, description, and tags,
  and lists a fixed `Private Ideogram Prompt` shell without decrypting. Explicit
  use, duplicate, and edit paths decrypt; delete can remain available when
  decryption fails.
- The Director library follows the same general shape, but some locked shells
  retain timestamps, tags, rich summary counts, validation state, character
  labels, and media-derived details. Those projections can disclose private
  activity or content even though the primary payload is encrypted.
- Director take metadata already replaces private paths and filenames, strips
  embedded media, and can reduce debug UI output to a private marker. It still
  carries operational IDs, hashes, model details, dimensions, durations, and
  similar fields whose safety currently depends on each call site.
- Private media routes require authorization and use non-cacheable responses,
  but route implementations do not yet share one rule for sanitized logging,
  error messages, or download filenames.

### Recommended contract

Adopt a sensitive-by-default, allowlist-only contract owned by `helto-privacy`:

1. A locked list shell contains only an opaque generated record ID, record kind,
   private flag, and fixed generic label. Shared schema/version or capability
   booleans may be added only when they reveal no consumer data.
2. User-authored values, timestamps and activity, summaries and counts, paths,
   filenames, hashes, media-derived details, and diagnostics are private unless
   a consumer registration explicitly classifies a projection as safe.
3. Listing never decrypts. Only an explicit authorized use, preview, or details
   operation may request decryption.
4. If decryption fails, the opaque shell remains listable and the record remains
   deletable. An explicitly confirmed destructive replacement may also be
   supported. Use, preview, duplicate, merge, edit, and metadata reveal fail
   closed.
5. Private responses and logs use stable error codes and generic messages. They
   never include raw exception text, tokens, prompts, names, tags, workflow JSON,
   paths, or original filenames. Diagnostics are limited to coarse allowlisted
   stage/count/boolean data plus a fresh correlation ID.
6. Private media responses use `Cache-Control: private, no-store`, opaque handles,
   and generic download filenames unless a filename is explicitly classified as
   safe for that authorized response.

`helto-privacy` should provide the shell builder, field-classification and
redaction primitives, decrypt/authorization gate, safe diagnostics, and common
failure behavior. Consumers should supply only thin record-field classifications
and product-specific projections through the shared registration contract.

## Answer

The user approved the strict minimal-shell contract. Private record data is
sensitive by default; consumer metadata may only widen a projection through an
explicit safe-field allowlist interpreted and validated by `helto-privacy`.

A locked list shell exposes only an opaque generated record ID, record kind,
private flag, and fixed generic label. A shared schema/version marker or
capability boolean may be added only when it contains no consumer-derived data.
Names, descriptions, tags, timestamps, activity, summaries, counts, paths,
filenames, hashes, media-derived details, and diagnostics are hidden by default.
Listing must never decrypt.

Only explicit authorized use, preview, or details operations may decrypt. If
decryption fails, the opaque shell remains listable and the record remains
deletable; an explicitly confirmed destructive replacement may also be offered.
Use, preview, duplicate, merge, edit, and metadata reveal must fail closed.

Private responses and logs use stable error codes and generic messages rather
than raw exception text or protected values. Safe diagnostics are limited to
coarse allowlisted stage/count/boolean data and a fresh correlation ID. Private
media uses opaque handles, `Cache-Control: private, no-store`, and generic
download filenames unless a filename is explicitly safe for that authorized
response.

`helto-privacy` owns shell construction, field classification and validation,
redaction, authorization/decryption gating, safe diagnostics, media response
defaults, and common failure behavior. Consumer packs own only their record
schema, domain validation, sensitive-field declarations, explicitly safe
product projections, and product behavior after successful authorized decrypt.
The durable policy is recorded in
[ADR 0004](../../../docs/adr/0004-use-minimal-private-record-shells.md).
