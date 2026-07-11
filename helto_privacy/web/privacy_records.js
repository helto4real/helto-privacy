// Dependency-neutral browser primitives for private record identifiers and
// locked-shell redaction. This module retains no consumer metadata.

const PRIVATE_RECORD_ID = /^hp-rec-[A-Za-z0-9_-]{32}$/;
const PRIVATE_RECORD_KIND = /^[a-z0-9][a-z0-9._-]*$/;
const PRIVATE_RECORD_LABEL = "Private record";

export function isOpaquePrivateRecordId(value) {
  return PRIVATE_RECORD_ID.test(String(value || ""));
}

// Rebuild rather than mask: discarded fields cannot reappear on hover/focus.
export function redactPrivateRecordShell(value) {
  const id = String(value?.id || "");
  const kind = String(value?.kind || "");
  if (
    !isOpaquePrivateRecordId(id)
    || !PRIVATE_RECORD_KIND.test(kind)
    || value?.private !== true
  ) return null;
  return Object.freeze({
    id,
    kind,
    private: true,
    label: PRIVATE_RECORD_LABEL,
  });
}
