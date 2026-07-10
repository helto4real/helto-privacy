# Retire legacy readers with sealed audits

Legacy formats remain available only through exact per-format read-only units
that create protected migration obligations, while current writers issue a
receipt only after an all-or-nothing rewrite and read-back verification of both
state and durable referenced artifacts. A reader becomes removal-eligible only
after the user explicitly seals the declared audit scope, later use invalidates
that seal, plaintext source keys are removed after verified wrapped import, and
wrapped historical-key pruning remains a separate authorized irreversible act;
automatic inactivity retirement was rejected because ComfyUI cannot discover
every workflow or export the user may possess.
