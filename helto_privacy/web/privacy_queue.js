// Shared settled-capture and fresh-replay orchestration for protected queues.

export class PrivacyQueueError extends Error {
  constructor(code) {
    super("Protected queue operation could not complete.");
    this.name = "PrivacyQueueError";
    this.code = code;
  }
}

export function createPrivacyQueueCoordinator({
  workflow,
  capturePrompt,
  submitPrompt,
  rebuildPrompt,
}) {
  if (
    typeof workflow?.runWithSnapshot !== "function"
    || typeof capturePrompt !== "function"
    || typeof submitPrompt !== "function"
    || typeof rebuildPrompt !== "function"
  ) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_ADAPTER_INVALID");
  }

  const captureOne = async (options = {}) => {
    return sanitized("PRIVACY_QUEUE_CAPTURE_FAILED", async () => {
      const before = optionalCallback(options.beforeSnapshot);
      const after = optionalCallback(options.afterSubmit);
      await before(options);
      const result = await workflow.runWithSnapshot(
        "queue-manager",
        async (transaction) => {
          const prompt = await capturePrompt(transaction, options);
          requirePrompt(prompt);
          return submitPrompt(prompt, Object.freeze({ ...options, replay: false }));
        },
      );
      await after(options, result);
      return result;
    });
  };

  const captureBatches = async (options = {}) => {
    const count = batchCount(options.batchCount);
    const results = [];
    for (let index = 0; index < count; index += 1) {
      results.push(await captureOne(Object.freeze({ ...options, batchIndex: index })));
    }
    return results;
  };

  const replay = async (storedSnapshot, options = {}) => {
    requirePrompt(storedSnapshot);
    const storedGrants = executionGrants(storedSnapshot);
    return sanitized("PRIVACY_QUEUE_REPLAY_FAILED", () => (
      workflow.runWithSnapshot("replay", async (transaction) => {
        // The product adapter must rebuild from durable workflow state. Stored
        // executable payloads and their session grants are never submitted.
        const prompt = await rebuildPrompt(storedSnapshot, transaction, options);
        requirePrompt(prompt);
        if (prompt === storedSnapshot) {
          throw new PrivacyQueueError("PRIVACY_QUEUE_REPLAY_NOT_REBUILT");
        }
        requireFreshExecutionGrants(storedGrants, executionGrants(prompt));
        return submitPrompt(prompt, Object.freeze({ ...options, replay: true }));
      })
    ));
  };

  return Object.freeze({ captureOne, captureBatches, replay });
}

function optionalCallback(value) {
  if (value === undefined || value === null) return async () => {};
  if (typeof value !== "function") {
    throw new PrivacyQueueError("PRIVACY_QUEUE_ADAPTER_INVALID");
  }
  return value;
}

function requirePrompt(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_SNAPSHOT_INVALID");
  }
}

function batchCount(value) {
  const count = Number(value ?? 1);
  if (!Number.isFinite(count) || count < 1) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_BATCH_INVALID");
  }
  return Math.floor(count);
}

async function sanitized(code, operation) {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof PrivacyQueueError
      || (
        error?.name === "PrivacySnapshotError"
        && typeof error?.code === "string"
        && error.code.startsWith("PRIVACY_SNAPSHOT_")
      )
    ) {
      throw error;
    }
    throw new PrivacyQueueError(code);
  }
}

function executionGrants(value) {
  const grants = [];
  const visited = new WeakSet();
  const visit = (candidate) => {
    if (!candidate || typeof candidate !== "object") return;
    if (visited.has(candidate)) return;
    visited.add(candidate);
    if (candidate.schema === "helto.private-execution-reference") {
      if (typeof candidate.grant !== "string" || !candidate.grant) {
        throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID");
      }
      grants.push(candidate.grant);
      return;
    }
    for (const item of Array.isArray(candidate) ? candidate : Object.values(candidate)) {
      visit(item);
    }
  };
  visit(value);
  if (new Set(grants).size !== grants.length) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID");
  }
  return Object.freeze(grants);
}

function requireFreshExecutionGrants(stored, rebuilt) {
  // Pre-cutover queue snapshots have no shared references. Their regenerated
  // prompt may legitimately introduce current grants for the first time.
  if (!stored.length) return;
  if (stored.length !== rebuilt.length) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING");
  }
  const expired = new Set(stored);
  if (rebuilt.some((grant) => expired.has(grant))) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_GRANT_STALE");
  }
}
