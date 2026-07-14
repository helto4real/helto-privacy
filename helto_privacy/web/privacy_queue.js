// Shared settled-capture and fresh-replay orchestration for protected queues.

export class PrivacyQueueError extends Error {
  constructor(code) {
    super("Protected queue operation could not complete.");
    this.name = "PrivacyQueueError";
    this.code = code;
  }
}

const EXECUTION_REFERENCE_MARKERS = Object.freeze([
  "helto.private-execution-reference",
  "helto.subject-mode-reference",
]);
const EXECUTION_REFERENCE_SCAN_LIMIT = 16384;

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
  const references = [];
  const visited = new WeakSet();
  const visit = (candidate, path = [], parsedValue = false) => {
    if (typeof candidate === "string") {
      if (parsedValue && !isJsonContainerText(candidate)) return;
      if (
        candidate.length <= EXECUTION_REFERENCE_SCAN_LIMIT
        && isJsonContainerText(candidate)
      ) {
        try {
          visit(JSON.parse(candidate), path, true);
          return;
        } catch (error) {
          if (error instanceof PrivacyQueueError) throw error;
          if (!hasDecodedExecutionReferenceMarker(candidate)) return;
        }
      } else if (!hasDecodedExecutionReferenceMarker(candidate)) {
        return;
      }
      throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID");
    }
    if (!candidate || typeof candidate !== "object") return;
    if (
      candidate.schema === "helto.private-execution-reference"
      || candidate.schema === "helto.subject-mode-reference"
    ) {
      const validVersion = candidate.schema === "helto.private-execution-reference"
        ? candidate.version === 2 && /^[0-9a-f]{64}$/.test(candidate.subject)
        : candidate.version === 2
          && /^[0-9a-f]{64}$/.test(candidate.profileFingerprint)
          && /^[0-9a-f]{64}$/.test(candidate.subject)
          && typeof candidate.bindingId === "string"
          && !!candidate.bindingId;
      if (
        !validVersion
        || typeof candidate.grant !== "string"
        || !candidate.grant
      ) {
        throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID");
      }
      references.push(Object.freeze({
        schema: candidate.schema,
        version: candidate.version,
        path: JSON.stringify(path),
        grant: candidate.grant,
      }));
      return;
    }
    if (visited.has(candidate)) return;
    visited.add(candidate);
    if (Array.isArray(candidate)) {
      candidate.forEach((item, index) => (
        visit(item, [...path, ["array", index]], parsedValue)
      ));
    } else {
      for (const [key, item] of Object.entries(candidate)) {
        visit(item, [...path, ["object", key]], parsedValue);
      }
    }
  };
  visit(value);
  if (
    new Set(references.map((item) => item.grant)).size !== references.length
    || new Set(references.map((item) => `${item.schema}:${item.path}`)).size
      !== references.length
  ) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID");
  }
  return Object.freeze(references);
}

function isJsonContainerText(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) continue;
    return code === 0x7b || code === 0x5b;
  }
  return false;
}

function hasDecodedExecutionReferenceMarker(value) {
  const progress = EXECUTION_REFERENCE_MARKERS.map(() => 0);
  const feed = (character) => {
    for (let index = 0; index < EXECUTION_REFERENCE_MARKERS.length; index += 1) {
      const marker = EXECUTION_REFERENCE_MARKERS[index];
      const next = progress[index];
      progress[index] = character === marker[next]
        ? next + 1
        : (character === marker[0] ? 1 : 0);
      if (progress[index] === marker.length) return true;
    }
    return false;
  };
  for (let index = 0; index < value.length; index += 1) {
    let character = value[index];
    if (character === "\\" && index + 1 < value.length) {
      const escape = value[index + 1];
      if (escape === "u" && index + 5 < value.length) {
        let code = 0;
        let valid = true;
        for (let offset = 2; offset <= 5; offset += 1) {
          const unit = value.charCodeAt(index + offset);
          const nibble = unit >= 0x30 && unit <= 0x39
            ? unit - 0x30
            : unit >= 0x41 && unit <= 0x46
              ? unit - 0x41 + 10
              : unit >= 0x61 && unit <= 0x66
                ? unit - 0x61 + 10
                : -1;
          if (nibble < 0) {
            valid = false;
            break;
          }
          code = (code << 4) | nibble;
        }
        if (valid) {
          character = String.fromCharCode(code);
          index += 5;
        }
      } else if (
        escape === "\"" || escape === "\\" || escape === "/"
        || escape === "b" || escape === "f" || escape === "n"
        || escape === "r" || escape === "t"
      ) {
        character = escape === "b" ? "\b"
          : escape === "f" ? "\f"
            : escape === "n" ? "\n"
              : escape === "r" ? "\r"
                : escape === "t" ? "\t"
                  : escape;
        index += 1;
      }
    }
    if (feed(character)) return true;
  }
  return false;
}

function requireFreshExecutionGrants(stored, rebuilt) {
  // Pre-cutover queue snapshots have no shared references. Their regenerated
  // prompt may legitimately introduce current grants for the first time.
  if (!stored.length) return;
  if (stored.length !== rebuilt.length) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING");
  }
  const byLocation = (items) => [...items]
    .sort((left, right) => `${left.schema}:${left.path}`.localeCompare(
      `${right.schema}:${right.path}`,
    ));
  const expired = byLocation(stored);
  const fresh = byLocation(rebuilt);
  if (expired.some((item, index) => (
    item.schema !== fresh[index].schema
    || item.version !== fresh[index].version
    || item.path !== fresh[index].path
  ))) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING");
  }
  const expiredGrants = new Set(expired.map((item) => item.grant));
  if (fresh.some((item) => expiredGrants.has(item.grant))) {
    throw new PrivacyQueueError("PRIVACY_QUEUE_EXECUTION_GRANT_STALE");
  }
}
