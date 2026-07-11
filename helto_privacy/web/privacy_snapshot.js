// Runtime-only privacy snapshot coordination and graph-wide serialization gates.

export const ENVELOPE_DISPOSITION = Object.freeze({
  VERIFIED_CURRENT: "verified-current",
  LOCKED_CURRENT: "locked-current",
  FAILED_CURRENT: "failed-current",
  READABLE_LEGACY: "readable-legacy",
  UNSUPPORTED: "unsupported",
});

const DISPOSITIONS = new Set(Object.values(ENVELOPE_DISPOSITION));
const BARRIER_REASONS = new Set([
  "autosave",
  "direct-queue",
  "export",
  "graph-to-prompt",
  "manual-save",
  "partial-execution",
  "queue",
  "queue-manager",
  "replay",
  "serialize",
  "subgraph",
]);
const EXECUTION_BARRIER_REASONS = new Set([
  "direct-queue",
  "graph-to-prompt",
  "partial-execution",
  "queue",
  "queue-manager",
  "replay",
  "subgraph",
]);
const APP_BARRIERS = new WeakMap();
const TRANSACTION_RECORDS = new WeakMap();
const GRAPH_SERIALIZE_WRAPPED = Symbol("heltoPrivacySerializeWrapped");

export class PrivacySnapshotError extends Error {
  constructor(code) {
    super("Privacy snapshot operation could not complete.");
    this.name = "PrivacySnapshotError";
    this.code = code;
  }
}

export function createPrivacySnapshotCoordinator({
  packId,
  fields,
  adapters,
  transport,
  timeoutMs = 5000,
  blocked = false,
  resolvePrivate = async () => true,
}) {
  const id = stableId(packId, "PRIVACY_SNAPSHOT_PACK_INVALID");
  const declarations = normalizeFields(fields);
  const adapterMap = adapters && typeof adapters === "object" ? adapters : {};
  if (
    typeof transport?.disposition !== "function"
    || typeof transport?.protect !== "function"
    || typeof resolvePrivate !== "function"
    || !Number.isFinite(timeoutMs)
    || timeoutMs <= 0
  ) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_COORDINATOR_INVALID");
  }
  for (const field of declarations) validateAdapter(adapterMap[field.browserAdapter]);

  const owners = new Map();
  let snapshotRevision = 0;
  let sessionEpoch = 0;
  let latestTransaction = null;
  let activeTransaction = null;

  function reserveNode(owner) {
    if (!owner || typeof owner !== "object") return false;
    const matching = declarations.filter((field) => field.nodeTypes.includes(nodeType(owner)));
    if (!matching.length) return false;
    let entries = owners.get(owner);
    if (!entries) {
      entries = new Map();
      owners.set(owner, entries);
    }
    for (const field of matching) {
      if (entries.has(field.id)) continue;
      const adapter = adapterMap[field.browserAdapter];
      const entry = {
        packId: id,
        owner,
        field,
        adapter,
        context: Object.freeze({
          packId: id,
          fieldId: field.id,
          workflowResourceId: field.workflowResourceId,
        }),
        generation: 0,
        settledGeneration: -1,
        disposition: ENVELOPE_DISPOSITION.UNSUPPORTED,
        envelope: "",
        canonical: null,
        edited: false,
        pending: null,
        initialization: null,
        initialized: false,
        private: true,
      };
      entries.set(field.id, entry);
    }
    return true;
  }

  async function registerNode(owner) {
    if (!reserveNode(owner)) return false;
    const entries = owners.get(owner);
    for (const entry of entries.values()) {
      if (entry.initialized) continue;
      if (!entry.initialization) {
        entry.initialization = initializeEntry(entry);
      }
      const initialization = entry.initialization;
      try {
        await initialization;
      } finally {
        if (entry.initialization === initialization) entry.initialization = null;
      }
    }
    return true;
  }

  async function initializeEntry(entry) {
    entry.envelope = readProtected(entry);
    if (!blocked) {
      await refreshMode(entry, { initial: true });
      if (entry.private) {
        await refreshDisposition(entry);
        if (!entry.envelope) {
          entry.edited = true;
          await prepareEntry(entry, { allowUninitialized: true });
        }
      }
    }
    entry.initialized = true;
  }

  async function refreshDisposition(entry) {
    let result;
    try {
      result = await transport.disposition(entry.field.id, entry.envelope);
    } catch {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_DISPOSITION_FAILED");
    }
    const disposition = String(result?.disposition || "");
    if (!DISPOSITIONS.has(disposition)) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_DISPOSITION_INVALID");
    }
    entry.disposition = disposition;
    if (disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY) {
      const replacement = serializeEnvelope(result?.replacementEnvelope);
      if (!replacement) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
      writeProtected(entry, replacement);
      entry.envelope = replacement;
      entry.disposition = ENVELOPE_DISPOSITION.VERIFIED_CURRENT;
    }
    if (
      entry.disposition === ENVELOPE_DISPOSITION.VERIFIED_CURRENT
      || entry.disposition === ENVELOPE_DISPOSITION.LOCKED_CURRENT
      || entry.disposition === ENVELOPE_DISPOSITION.FAILED_CURRENT
    ) {
      entry.settledGeneration = entry.generation;
      entry.edited = false;
    }
    return entry.disposition;
  }

  function markEdited(owner, fieldId) {
    const entry = requireEntry(owner, fieldId);
    requireEntryInitialized(entry);
    if (!entry.private) {
      entry.generation += 1;
      entry.envelope = readProtected(entry);
      entry.settledGeneration = entry.generation;
      entry.edited = false;
      return entry.generation;
    }
    if (
      entry.disposition === ENVELOPE_DISPOSITION.LOCKED_CURRENT
      || entry.disposition === ENVELOPE_DISPOSITION.FAILED_CURRENT
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_REPLACEMENT_BLOCKED");
    }
    if (entry.disposition === ENVELOPE_DISPOSITION.UNSUPPORTED && entry.envelope) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSUPPORTED");
    }
    entry.generation += 1;
    entry.edited = true;
    entry.settledGeneration = -1;
    const pending = prepareEntry(entry);
    pending.catch(() => {});
    return entry.generation;
  }

  async function prepareEntry(entry, { allowUninitialized = false } = {}) {
    if (!allowUninitialized) requireEntryInitialized(entry);
    if (entry.settledGeneration === entry.generation && !entry.edited) return entry.envelope;
    if (
      (entry.disposition === ENVELOPE_DISPOSITION.LOCKED_CURRENT
        || entry.disposition === ENVELOPE_DISPOSITION.FAILED_CURRENT)
      && !entry.edited
    ) {
      entry.settledGeneration = entry.generation;
      return entry.envelope;
    }
    if (entry.disposition === ENVELOPE_DISPOSITION.UNSUPPORTED && entry.envelope) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSUPPORTED");
    }

    const generation = entry.generation;
    const normalized = normalizeLive(entry);
    const canonical = canonicalValue(normalized);
    if (entry.canonical === canonical && entry.envelope) {
      entry.settledGeneration = generation;
      entry.edited = false;
      return entry.envelope;
    }
    if (
      entry.pending
      && entry.pending.generation === generation
      && entry.pending.canonical === canonical
    ) return entry.pending.promise;

    const pendingRecord = { generation, canonical, promise: null };
    pendingRecord.promise = (async () => {
      let result;
      try {
        result = await transport.protect(entry.field.id, normalized);
      } catch {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_PROTECTION_FAILED");
      }
      if (
        result?.disposition
        && result.disposition !== ENVELOPE_DISPOSITION.VERIFIED_CURRENT
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_PROTECTION_FAILED");
      }
      const envelope = serializeEnvelope(result?.envelope ?? result);
      if (!envelope) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_PROTECTION_FAILED");
      }
      if (entry.generation !== generation || entry.pending !== pendingRecord) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
      }
      writeProtected(entry, envelope);
      entry.envelope = envelope;
      entry.canonical = canonical;
      entry.disposition = ENVELOPE_DISPOSITION.VERIFIED_CURRENT;
      entry.settledGeneration = generation;
      entry.edited = false;
      return envelope;
    })().finally(() => {
      if (entry.pending === pendingRecord) entry.pending = null;
    });
    entry.pending = pendingRecord;
    return pendingRecord.promise;
  }

  async function settle(reason = "manual-save") {
    if (blocked) throw new PrivacySnapshotError("PRIVACY_SUITE_BLOCKED");
    const safeReason = barrierReason(reason);
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const entries = allEntries();
      await withDeadline(
        Promise.all(entries.map((entry) => entry.initialization).filter(Boolean)),
        deadline,
      );
      for (const entry of entries) requireEntryInitialized(entry);
      await withDeadline(
        Promise.all(entries.map((entry) => refreshMode(entry))),
        deadline,
      );
      const generations = new Map(entries.map((entry) => [entry, entry.generation]));
      const outcomes = await withDeadline(
        Promise.allSettled(entries.map((entry) => prepareEntry(entry))),
        deadline,
      );
      const changed = entries.some(
        (entry) => generations.get(entry) !== entry.generation,
      );
      if (changed) {
        if (Date.now() >= deadline) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TIMEOUT");
        }
        continue;
      }
      const failed = outcomes.find((outcome) => outcome.status === "rejected");
      if (failed) {
        const code = String(failed.reason?.code || "");
        throw new PrivacySnapshotError(
          code.startsWith("PRIVACY_SNAPSHOT_")
            ? code
            : "PRIVACY_SNAPSHOT_SETTLEMENT_FAILED",
        );
      }
      requireSettled(safeReason);
      if (
        EXECUTION_BARRIER_REASONS.has(safeReason)
        && entries.some((entry) => (
          entry.private
          && entry.disposition !== ENVELOPE_DISPOSITION.VERIFIED_CURRENT
        ))
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
      }
      snapshotRevision += 1;
      const transaction = Object.freeze({
        packId: id,
        reason: safeReason,
        revision: snapshotRevision,
        sessionEpoch,
        fields: Object.freeze(entries.map((entry) => Object.freeze({
          fieldId: entry.field.id,
          generation: entry.generation,
          disposition: entry.disposition,
          protected: entry.private,
        }))),
      });
      TRANSACTION_RECORDS.set(
        transaction,
        new Map(entries.map((entry) => [entry, Object.freeze({
          generation: entry.generation,
          disposition: entry.disposition,
          envelope: entry.envelope,
          private: entry.private,
        })])),
      );
      latestTransaction = transaction;
      return transaction;
    }
  }

  function requireSettled(reason = "serialize") {
    if (blocked) throw new PrivacySnapshotError("PRIVACY_SUITE_BLOCKED");
    barrierReason(reason);
    if (activeTransaction) return true;
    for (const entry of allEntries()) {
      requireEntryInitialized(entry);
      if (!entry.private) continue;
      if (entry.disposition === ENVELOPE_DISPOSITION.UNSUPPORTED) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSUPPORTED");
      }
      if (
        entry.pending
        || entry.edited
        || entry.settledGeneration !== entry.generation
        || !entry.envelope
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSETTLED");
      }
    }
    return true;
  }

  function workflowProjection(owner, fieldId) {
    const entry = requireEntry(owner, fieldId);
    const { record } = transactionState(entry);
    if (record.disposition === ENVELOPE_DISPOSITION.UNSUPPORTED) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSUPPORTED");
    }
    return record.envelope;
  }

  function executionProjection(owner, fieldId) {
    const entry = requireEntry(owner, fieldId);
    const { record, transaction } = transactionState(entry);
    if (
      record.private
      && (
        record.disposition !== ENVELOPE_DISPOSITION.VERIFIED_CURRENT
        || transaction.sessionEpoch !== sessionEpoch
      )
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    return record.envelope;
  }

  function transactionState(entry) {
    requireEntryInitialized(entry);
    const transaction = activeTransaction || latestTransaction;
    const record = TRANSACTION_RECORDS.get(transaction)?.get(entry);
    if (
      !record
      || (!activeTransaction && record.generation !== entry.generation)
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSETTLED");
    }
    return { record, transaction };
  }

  function activateTransaction(transaction) {
    if (
      activeTransaction
      || transaction?.packId !== id
      || !TRANSACTION_RECORDS.has(transaction)
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TRANSACTION_INVALID");
    }
    activeTransaction = transaction;
  }

  function releaseTransaction(transaction) {
    if (activeTransaction !== transaction) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TRANSACTION_INVALID");
    }
    activeTransaction = null;
  }

  function requireActiveTransaction(reason) {
    const safeReason = barrierReason(reason);
    const records = TRANSACTION_RECORDS.get(activeTransaction);
    if (!activeTransaction || !records) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TRANSACTION_INVALID");
    }
    for (const [entry, record] of records) {
      if (
        record.generation !== entry.generation
        || activeTransaction.sessionEpoch !== sessionEpoch
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TRANSACTION_STALE");
      }
      if (
        EXECUTION_BARRIER_REASONS.has(safeReason)
        && record.private
        && record.disposition !== ENVELOPE_DISPOSITION.VERIFIED_CURRENT
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
      }
    }
    return true;
  }

  async function onSessionChange(session) {
    const state = String(session?.state || "unknown");
    if (state === "locked" || state === "unlocked") sessionEpoch += 1;
    if (state === "locked") {
      for (const entry of allEntries()) {
        if (!entry.initialized || !entry.private) continue;
        entry.generation += 1;
        entry.pending = null;
        entry.canonical = null;
        entry.edited = false;
        if (entry.disposition === ENVELOPE_DISPOSITION.VERIFIED_CURRENT) {
          entry.disposition = ENVELOPE_DISPOSITION.LOCKED_CURRENT;
        }
        entry.settledGeneration = entry.envelope ? entry.generation : -1;
      }
      return;
    }
    if (state === "unlocked") {
      await Promise.all(
        allEntries()
          .filter((entry) => entry.initialized && entry.private)
          .map((entry) => refreshDisposition(entry)),
      );
    }
  }

  function requireEntry(owner, fieldId) {
    const entry = owners.get(owner)?.get(String(fieldId || ""));
    if (!entry) throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_FIELD_INVALID");
    return entry;
  }

  function allEntries() {
    return [...owners.values()].flatMap((entries) => [...entries.values()]);
  }

  async function refreshMode(entry, { initial = false } = {}) {
    let nextPrivate;
    try {
      nextPrivate = await resolvePrivate(entry.field) !== false;
    } catch {
      throw new PrivacySnapshotError("PRIVACY_MODE_STATE_UNAVAILABLE");
    }
    if (!initial && nextPrivate === entry.private) return;
    entry.private = nextPrivate;
    if (!initial) entry.generation += 1;
    entry.pending = null;
    entry.canonical = null;
    entry.edited = false;
    entry.envelope = readProtected(entry);
    if (!nextPrivate) {
      entry.disposition = ENVELOPE_DISPOSITION.VERIFIED_CURRENT;
      entry.settledGeneration = entry.generation;
      return;
    }
    entry.settledGeneration = -1;
    if (!initial) await refreshDisposition(entry);
  }

  async function refreshModes() {
    if (blocked) throw new PrivacySnapshotError("PRIVACY_SUITE_BLOCKED");
    await Promise.all(
      allEntries()
        .filter((entry) => entry.initialized)
        .map((entry) => refreshMode(entry)),
    );
  }

  return Object.freeze({
    packId: id,
    reserveNode,
    registerNode,
    markEdited,
    settle,
    requireSettled,
    workflowProjection,
    executionProjection,
    onSessionChange,
    refreshModes,
    activateTransaction,
    releaseTransaction,
    requireActiveTransaction,
  });
}

export function installGraphSerializationBarrier(app, getCoordinators) {
  if (!app || typeof getCoordinators !== "function") {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_BARRIER_INVALID");
  }
  const existing = APP_BARRIERS.get(app);
  if (existing) {
    existing.getCoordinators = getCoordinators;
    existing.wrapGraphs();
    return existing.public;
  }

  const state = {
    getCoordinators,
    wrapGraphs: null,
    public: null,
    operationTail: Promise.resolve(),
  };
  let originalGraphToPrompt = null;
  const coordinators = () => {
    const values = state.getCoordinators();
    return Array.isArray(values) ? values : [...(values || [])];
  };
  const settleAll = async (reason) => {
    return Promise.all(
      coordinators().map((coordinator) => coordinator.settle(reason)),
    );
  };
  const requireAll = (reason) => {
    for (const coordinator of coordinators()) coordinator.requireSettled(reason);
  };
  const runWithTransaction = async (reason, operation) => {
    const current = coordinators();
    const transactions = await Promise.all(
      current.map((coordinator) => coordinator.settle(reason)),
    );
    let activated = 0;
    try {
      for (; activated < current.length; activated += 1) {
        current[activated].activateTransaction(transactions[activated]);
      }
      const operationContext = Object.freeze({
        graphToPrompt: async (...args) => {
          if (!originalGraphToPrompt) {
            throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
          }
          for (const coordinator of current) {
            coordinator.requireActiveTransaction("graph-to-prompt");
          }
          return originalGraphToPrompt.apply(app, args);
        },
      });
      return await operation(operationContext);
    } finally {
      for (let index = activated - 1; index >= 0; index -= 1) {
        current[index].releaseTransaction(transactions[index]);
      }
    }
  };
  const runExclusive = (reason, operation) => {
    const result = state.operationTail.then(
      () => runWithTransaction(reason, operation),
    );
    state.operationTail = result.catch(() => {});
    return result;
  };

  if (typeof app.graphToPrompt === "function") {
    originalGraphToPrompt = app.graphToPrompt;
    app.graphToPrompt = async function heltoPrivacyGraphToPrompt(...args) {
      state.wrapGraphs();
      return runExclusive(
        "graph-to-prompt",
        () => originalGraphToPrompt.apply(this, args),
      );
    };
  }

  state.wrapGraphs = () => wrapGraphAndSubgraphs(app.rootGraph || app.graph, requireAll);
  state.public = Object.freeze({
    settle: settleAll,
    requireSettled: requireAll,
    refreshGraphs: () => state.wrapGraphs(),
    runWithSnapshot: (reason, operation) => {
      if (typeof operation !== "function") {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
      }
      state.wrapGraphs();
      return runExclusive(reason, operation);
    },
  });
  APP_BARRIERS.set(app, state);
  state.wrapGraphs();
  return state.public;
}

function wrapGraphAndSubgraphs(graph, requireAll) {
  if (!graph || typeof graph !== "object") return;
  if (typeof graph.serialize === "function" && !graph[GRAPH_SERIALIZE_WRAPPED]) {
    const original = graph.serialize;
    graph.serialize = function heltoPrivacySerialize(...args) {
      requireAll("serialize");
      return original.apply(this, args);
    };
    Object.defineProperty(graph, GRAPH_SERIALIZE_WRAPPED, { value: true });
  }
  const subgraphs = graph.subgraphs;
  const values = typeof subgraphs?.values === "function"
    ? subgraphs.values()
    : (Array.isArray(subgraphs) ? subgraphs : []);
  for (const subgraph of values) wrapGraphAndSubgraphs(subgraph, requireAll);
}

function normalizeFields(fields) {
  if (!Array.isArray(fields)) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_FIELDS_INVALID");
  }
  const seen = new Set();
  return Object.freeze(fields.map((field) => {
    const id = stableId(field?.id, "PRIVACY_SNAPSHOT_FIELD_INVALID");
    const workflowResourceId = stableId(
      field?.workflowResourceId,
      "PRIVACY_SNAPSHOT_FIELD_INVALID",
    );
    const scopeId = stableId(
      field?.scopeId || "default",
      "PRIVACY_SNAPSHOT_FIELD_INVALID",
    );
    const browserAdapter = stableId(
      field?.browserAdapter,
      "PRIVACY_SNAPSHOT_FIELD_INVALID",
    );
    const nodeTypes = Object.freeze(
      (Array.isArray(field?.nodeTypes) ? field.nodeTypes : [])
        .map((value) => String(value || ""))
        .filter(Boolean),
    );
    if (!nodeTypes.length || seen.has(id)) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_FIELD_INVALID");
    }
    seen.add(id);
    return Object.freeze({ id, workflowResourceId, scopeId, browserAdapter, nodeTypes });
  }));
}

function validateAdapter(adapter) {
  if (
    typeof adapter?.normalize !== "function"
    || typeof adapter?.readProtected !== "function"
    || typeof adapter?.writeProtected !== "function"
  ) throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_ADAPTER_INVALID");
}

function normalizeLive(entry) {
  try {
    return entry.adapter.normalize(entry.owner, entry.context);
  } catch {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_NORMALIZATION_FAILED");
  }
}

function readProtected(entry) {
  try {
    const value = entry.adapter.readProtected(entry.owner, entry.context);
    if (typeof value !== "string") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_READ_FAILED");
    }
    return value;
  } catch {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_READ_FAILED");
  }
}

function writeProtected(entry, envelope) {
  try {
    entry.adapter.writeProtected(entry.owner, envelope, entry.context);
    const written = readProtected(entry);
    if (written !== envelope) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_WRITE_FAILED");
    }
  } catch {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_WRITE_FAILED");
  }
}

function requireEntryInitialized(entry) {
  if (!entry.initialized) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSETTLED");
  }
}

function barrierReason(value) {
  const reason = String(value || "");
  if (!BARRIER_REASONS.has(reason)) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_REASON_INVALID");
  }
  return reason;
}

function nodeType(node) {
  return String(node?.comfyClass || node?.type || node?.constructor?.type || "");
}

function stableId(value, code) {
  const normalized = String(value || "");
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(normalized)) {
    throw new PrivacySnapshotError(code);
  }
  return normalized;
}

function serializeEnvelope(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return "";
  try {
    return JSON.stringify(stableValue(value));
  } catch {
    return "";
  }
}

function canonicalValue(value) {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  return JSON.stringify(stableValue(value));
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    const result = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) result[key] = stableValue(value[key]);
    }
    return result;
  }
  if (["function", "symbol", "undefined"].includes(typeof value)) return null;
  return value;
}

async function withDeadline(promise, deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TIMEOUT");
  let timeoutId;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeoutId = setTimeout(
          () => reject(new PrivacySnapshotError("PRIVACY_SNAPSHOT_TIMEOUT")),
          remaining,
        );
      }),
    ]);
  } finally {
    clearTimeout(timeoutId);
  }
}
