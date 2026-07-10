# Use minimal private record shells

Private record fields are sensitive by default. A locked list shell contains
only an opaque generated record ID, record kind, private flag, and fixed generic
label, and listing never decrypts. Only an explicit authorized use, preview, or
details operation may decrypt or return a consumer-declared safe projection.
If decryption fails, list and delete remain available while reveal, use, edit,
duplicate, and merge fail closed. `helto-privacy` owns the allowlist validation,
shell construction, redaction, safe diagnostics, private-media defaults, and
generic failure behavior; consumer packs declare their schemas and narrowly
allowlisted product projections without weakening those invariants.
