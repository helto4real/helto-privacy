// Shared fail-closed lifecycle for protected product operations.

export class PrivacyProtectedOperationError extends Error {
  constructor(code = "PRIVACY_PROTECTED_OPERATION_BLOCKED") {
    super("Protected privacy operation could not complete.");
    this.name = "PrivacyProtectedOperationError";
    this.code = code;
  }
}

export function createProtectedDisplayController({
  adapter,
  invoke,
  project,
  failureCode = "PRIVACY_PROTECTED_OPERATION_BLOCKED",
}) {
  if (
    typeof adapter?.readProtected !== "function"
    || typeof adapter?.writeProtected !== "function"
    || typeof adapter?.apply !== "function"
    || typeof adapter?.clear !== "function"
    || typeof adapter?.block !== "function"
    || typeof invoke !== "function"
    || typeof project !== "function"
  ) {
    throw new PrivacyProtectedOperationError(failureCode);
  }

  return Object.freeze({
    async display(owner, protectedValue, context) {
      let previous = "";
      let candidateWritten = false;
      try {
        previous = adapter.readProtected(owner, context);
        if (typeof protectedValue !== "string") {
          throw new PrivacyProtectedOperationError(failureCode);
        }
        adapter.writeProtected(owner, protectedValue, context);
        candidateWritten = true;
        const result = await invoke(protectedValue);
        const revealed = project(result);
        adapter.apply(owner, revealed, context);
        return revealed;
      } catch {
        let cleanupFailed = false;
        try {
          if (
            candidateWritten
            && adapter.readProtected(owner, context) === protectedValue
          ) {
            adapter.writeProtected(owner, previous, context);
          }
        } catch {
          cleanupFailed = true;
        }
        try {
          adapter.clear(owner, context);
        } catch {
          cleanupFailed = true;
        }
        if (cleanupFailed) {
          try {
            adapter.block(owner, context);
          } catch {
            throw new PrivacyProtectedOperationError(
              "PRIVACY_PROTECTED_OPERATION_CLEANUP_FAILED",
            );
          }
        }
        throw new PrivacyProtectedOperationError(failureCode);
      }
    },
  });
}
