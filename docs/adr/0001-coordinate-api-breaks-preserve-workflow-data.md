# Coordinate API breaks while preserving workflow data

Consumer-facing source APIs may change because all known consumer packs will be
updated as one coordinated migration. Existing encrypted workflow data must
remain readable through isolated legacy read paths until the workflows have
been checked and re-saved; new writes use only the replacement contracts so the
legacy paths can be removed cleanly after that compatibility window.
