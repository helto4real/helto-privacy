// Runtime-only privacy snapshot coordination and graph-wide serialization gates.

import {
  createPrivacyPromptSubmissionService,
  installPrivacySubmissionOwnership,
} from "./privacy_submission.js";

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
  "mode-transition",
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
const APP_CONNECTION_GATES = new WeakMap();
const TRANSACTION_RECORDS = new WeakMap();
const GRAPH_SERIALIZE_WRAPPED = Symbol("heltoPrivacySerializeWrapped");
const GRAPH_CONNECTION_INTERCEPTOR = Symbol("heltoPrivacyConnectionInterceptor");

export class PrivacySnapshotError extends Error {
  constructor(code) {
    super("Privacy snapshot operation could not complete.");
    this.name = "PrivacySnapshotError";
    this.code = code;
  }
}

/**
 * Close every known workflow serialization path before profile attestation starts.
 * The installed accessors remain in place after hand-off so later method
 * replacements cannot bypass the active snapshot barrier.
 */
export function installPrivacyConnectionSerializationGate(app) {
  if (!app || (typeof app !== "object" && typeof app !== "function")) {
    throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
  }
  const existing = APP_CONNECTION_GATES.get(app);
  if (existing) {
    return beginConnectionAttempt(existing);
  }

  const state = {
    phase: "connecting",
    nextAttempt: 1,
    pendingAttempts: new Set(),
    ownershipWaiters: new Set(),
    failed: false,
    app,
    submissionOwnership: null,
    serializeRequirement: null,
    serializeProjection: null,
    conflictHandler: null,
    subgraphCollections: new WeakMap(),
    refreshGraphs: null,
    controller: null,
  };
  state.refreshGraphs = () => {
    const graph = dataPropertyWithoutGet(app, "rootGraphInternal")
      || dataPropertyWithoutGet(app, "rootGraph")
      || dataPropertyWithoutGet(app, "graph");
    wrapConnectionGraphAndSubgraphs(graph, state);
  };
  state.submissionOwnership = installPrivacySubmissionOwnership({
    app,
    createError: (code) => new PrivacySnapshotError(code),
    requireAvailable: () => requireConnectionGate(state),
    onConflict: () => failConnectionGate(state),
    refresh: () => state.refreshGraphs(),
  });
  state.controller = Object.freeze({
    installBarrierHandlers({
      graphToPrompt,
      appQueuePrompt,
      apiQueuePrompt,
      fetchApi,
      requireSerialize,
      projectSerialization,
      onConflict,
    }) {
      if (
        typeof requireSerialize !== "function"
        || typeof projectSerialization !== "function"
        || typeof onConflict !== "function"
      ) {
        state.phase = "unavailable";
        notifyConnectionGateConflict(state);
        throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      state.submissionOwnership.installHandlers({
        graphToPrompt,
        appQueuePrompt,
        apiQueuePrompt,
        fetchApi,
      });
      state.serializeRequirement = requireSerialize;
      state.serializeProjection = projectSerialization;
      state.conflictHandler = onConflict;
      state.refreshGraphs();
    },
    refreshGraphs() {
      state.refreshGraphs();
    },
  });
  registerConnectionGateLifecycleRefresh(state);
  APP_CONNECTION_GATES.set(app, state);
  return beginConnectionAttempt(state);
}

function registerConnectionGateLifecycleRefresh(state) {
  const { app } = state;
  if (typeof app?.registerExtension !== "function") return;
  const refresh = () => state.refreshGraphs();
  app.registerExtension({
    name: "helto.privacy.connection-serialization-gate",
    setup: refresh,
    beforeRegisterNodeDef: refresh,
    nodeCreated: refresh,
    loadedGraphNode: refresh,
  });
}

function beginConnectionAttempt(state) {
  const token = state.nextAttempt;
  state.nextAttempt += 1;
  state.pendingAttempts.add(token);
  if (!state.failed) state.phase = "connecting";
  state.refreshGraphs?.();
  let settled = false;
  return Object.freeze({
    markUnavailable() {
      if (settled) return;
      settled = true;
      state.pendingAttempts.delete(token);
      state.failed = true;
      state.phase = "unavailable";
      notifyConnectionGateConflict(state);
      state.refreshGraphs();
      rejectConnectionOwnershipWaiters(state);
    },
    coalesce() {
      if (settled) return;
      settled = true;
      state.pendingAttempts.delete(token);
      openConnectionGateIfReady(state);
    },
    async takeOwnership() {
      if (settled) {
        throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      settled = true;
      state.pendingAttempts.delete(token);
      try {
        await state.submissionOwnership?.verifyCompatibility?.();
      } catch {
        state.failed = true;
        state.phase = "unavailable";
        notifyConnectionGateConflict(state);
        rejectConnectionOwnershipWaiters(state);
        throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      if (
        state.failed
        || !state.submissionOwnership?.ready
        || typeof state.serializeRequirement !== "function"
        || typeof state.serializeProjection !== "function"
        || typeof state.conflictHandler !== "function"
      ) {
        state.failed = true;
        state.phase = "unavailable";
        notifyConnectionGateConflict(state);
        rejectConnectionOwnershipWaiters(state);
        throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      state.refreshGraphs();
      if (!state.pendingAttempts.size) {
        openConnectionGateIfReady(state);
        return;
      }
      await new Promise((resolve, reject) => {
        state.ownershipWaiters.add({ resolve, reject });
      });
    },
  });
}

function dataPropertyWithoutGet(instance, propertyName) {
  let owner = instance;
  while (owner && owner !== Object.prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, propertyName);
    if (descriptor) {
      return Object.hasOwn(descriptor, "value") ? descriptor.value : null;
    }
    owner = Object.getPrototypeOf(owner);
  }
  return null;
}

function openConnectionGateIfReady(state) {
  if (state.failed || state.pendingAttempts.size) return;
  if (
    !state.submissionOwnership?.ready
    || typeof state.serializeRequirement !== "function"
    || typeof state.serializeProjection !== "function"
    || typeof state.conflictHandler !== "function"
  ) return;
  state.phase = "open";
  for (const waiter of state.ownershipWaiters) waiter.resolve();
  state.ownershipWaiters.clear();
}

function rejectConnectionOwnershipWaiters(state) {
  const error = new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
  for (const waiter of state.ownershipWaiters) waiter.reject(error);
  state.ownershipWaiters.clear();
}

function requireConnectionGate(state) {
  if (state.phase === "connecting") {
    throw new PrivacySnapshotError("PRIVACY_PROFILE_CONNECTING");
  }
  if (state.phase !== "open") {
    throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
  }
}

function wrapConnectionGraphAndSubgraphs(graph, state, visited = new WeakSet()) {
  if (!graph || typeof graph !== "object" || visited.has(graph)) return;
  visited.add(graph);
  let interceptor = graph[GRAPH_CONNECTION_INTERCEPTOR];
  if (!interceptor) {
    const descriptor = Object.getOwnPropertyDescriptor(graph, "serialize");
    const subgraphsDescriptor = Object.getOwnPropertyDescriptor(graph, "subgraphs");
    if (
      (descriptor && descriptor.configurable === false)
      || (subgraphsDescriptor && subgraphsDescriptor.configurable === false)
    ) {
      failConnectionGate(state);
    }
    interceptor = {
      original: typeof graph.serialize === "function" ? graph.serialize : null,
      subgraphs: protectSubgraphCollection(graph.subgraphs, state),
    };
    const guardedSerialize = function heltoPrivacyConnectingSerialize(...args) {
      requireConnectionGate(state);
      if (typeof state.serializeRequirement !== "function") {
        throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      state.serializeRequirement("serialize");
      if (typeof interceptor.original !== "function") {
        throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
      }
      const serialized = interceptor.original.apply(this, args);
      return state.serializeProjection(serialized, this);
    };
    Object.defineProperty(graph, "serialize", {
      configurable: false,
      enumerable: descriptor?.enumerable ?? true,
      get() {
        return guardedSerialize;
      },
      set(value) {
        interceptor.original = typeof value === "function" ? value : null;
      },
    });
    Object.defineProperty(graph, "subgraphs", {
      configurable: false,
      enumerable: subgraphsDescriptor?.enumerable ?? true,
      get() {
        return interceptor.subgraphs;
      },
      set(value) {
        const protectedCollection = protectSubgraphCollection(value, state);
        for (const subgraph of subgraphCollectionValues(protectedCollection)) {
          wrapConnectionGraphAndSubgraphs(subgraph, state);
        }
        interceptor.subgraphs = protectedCollection;
      },
    });
    Object.defineProperty(graph, GRAPH_CONNECTION_INTERCEPTOR, {
      value: interceptor,
    });
  }
  for (const subgraph of subgraphCollectionValues(interceptor.subgraphs)) {
    wrapConnectionGraphAndSubgraphs(subgraph, state, visited);
  }
}

function protectSubgraphCollection(collection, state) {
  if (!collection || typeof collection !== "object") return collection;
  const existing = state.subgraphCollections.get(collection);
  if (existing) return existing;
  if (Array.isArray(collection)) {
    const liveCollection = [...collection];
    Object.freeze(collection);
    const protectedArray = new Proxy(liveCollection, {
      set(target, property, value, receiver) {
        if (/^(0|[1-9][0-9]*)$/.test(String(property))) {
          wrapConnectionGraphAndSubgraphs(value, state);
        }
        return Reflect.set(target, property, value, receiver);
      },
    });
    state.subgraphCollections.set(collection, protectedArray);
    state.subgraphCollections.set(liveCollection, protectedArray);
    state.subgraphCollections.set(protectedArray, protectedArray);
    return protectedArray;
  }
  if (collection instanceof Map && typeof collection.set === "function") {
    const original = collection.set;
    Object.defineProperty(collection, "set", {
      configurable: false,
      value(key, graph) {
        wrapConnectionGraphAndSubgraphs(graph, state);
        return original.call(this, key, graph);
      },
    });
  } else if (collection instanceof Set && typeof collection.add === "function") {
    const original = collection.add;
    Object.defineProperty(collection, "add", {
      configurable: false,
      value(graph) {
        wrapConnectionGraphAndSubgraphs(graph, state);
        return original.call(this, graph);
      },
    });
  }
  state.subgraphCollections.set(collection, collection);
  return collection;
}

function subgraphCollectionValues(collection) {
  if (Array.isArray(collection)) return collection;
  if (collection instanceof Map || collection instanceof Set) return collection.values();
  return [];
}

function failConnectionGate(state) {
  state.failed = true;
  state.phase = "unavailable";
  notifyConnectionGateConflict(state);
  rejectConnectionOwnershipWaiters(state);
  throw new PrivacySnapshotError("PRIVACY_PROFILE_UNAVAILABLE");
}

function notifyConnectionGateConflict(state) {
  try {
    state.conflictHandler?.();
  } catch {
    /* The gate remains permanently unavailable even if status propagation fails. */
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
  refreshModeFence = async () => {},
  requireModeFence = () => true,
  executionProjections = [],
  prepareExecution = null,
  subjectModeBindings = [],
  prepareSubjectMode = null,
  revokeSubmissionReferences = null,
}) {
  const id = stableId(packId, "PRIVACY_SNAPSHOT_PACK_INVALID");
  const declarations = normalizeFields(fields);
  const projections = normalizeExecutionProjections(executionProjections);
  const subjectBindings = normalizeSubjectModeBindings(subjectModeBindings);
  const adapterMap = adapters && typeof adapters === "object" ? adapters : {};
  if (
    typeof transport?.disposition !== "function"
    || typeof transport?.protect !== "function"
    || typeof resolvePrivate !== "function"
    || typeof refreshModeFence !== "function"
    || typeof requireModeFence !== "function"
    || !Number.isFinite(timeoutMs)
    || timeoutMs <= 0
  ) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_COORDINATOR_INVALID");
  }
  for (const field of declarations) {
    validateAdapter(adapterMap[field.browserAdapter], field);
  }

  const owners = new Map();
  const subjectOwners = new Set();
  let snapshotRevision = 0;
  let sessionEpoch = 0;
  let sessionState = "unlocked";
  let latestTransaction = null;
  let activeTransaction = null;
  let invalidateActiveSubmission = () => {};

  function invalidateSubmission() {
    try {
      invalidateActiveSubmission();
    } catch {
      /* Freshness checks remain authoritative if cancellation propagation fails. */
    }
  }

  function setSubmissionInvalidator(invalidator) {
    if (typeof invalidator !== "function") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_COORDINATOR_INVALID");
    }
    invalidateActiveSubmission = invalidator;
  }

  function reserveNode(owner) {
    if (!owner || typeof owner !== "object") return false;
    const matching = declarations.filter((field) => field.nodeTypes.includes(nodeType(owner)));
    const subjectMatching = subjectBindings.some(
      (binding) => binding.nodeTypes.includes(nodeType(owner)),
    );
    if (subjectMatching) subjectOwners.add(owner);
    if (!matching.length) return subjectMatching;
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
        stagedEnvelope: "",
        migrationObligationId: null,
        legacySourceEnvelope: "",
        canonical: null,
        edited: false,
        pending: null,
        initialization: null,
        initialized: false,
        private: true,
        modeDirty: false,
      };
      entries.set(field.id, entry);
    }
    return true;
  }

  async function registerNode(owner) {
    if (!reserveNode(owner)) return false;
    const entries = owners.get(owner);
    if (!entries) return true;
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
        if (
          (entry.disposition === ENVELOPE_DISPOSITION.VERIFIED_CURRENT
            || entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY)
          && typeof entry.adapter.apply === "function"
        ) {
          await revealEntry(entry);
        }
      } else if (typeof entry.adapter.apply === "function") {
        entry.adapter.apply(entry.owner, entry.envelope, adapterContext(entry));
      }
    }
    entry.initialized = true;
  }

  async function refreshDisposition(entry) {
    const freshness = captureAsyncFreshness(entry, {
      protectedSource: entry.envelope,
    });
    let result;
    try {
      result = await transport.disposition(entry.field.id, entry.envelope);
    } catch {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_DISPOSITION_FAILED");
    }
    requireAsyncFreshness(entry, freshness);
    const disposition = String(result?.disposition || "");
    if (!DISPOSITIONS.has(disposition)) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_DISPOSITION_INVALID");
    }
    if (
      disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
      && sessionState !== "unlocked"
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
    }
    entry.disposition = disposition;
    if (disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY) {
      const replacement = serializeEnvelope(result?.replacementEnvelope);
      const obligationId = String(result?.migrationObligationId || "");
      if (!replacement || !/^hp-obligation-[A-Za-z0-9_-]+$/.test(obligationId)) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
      if (entry.legacySourceEnvelope === entry.envelope && entry.stagedEnvelope) {
        if (entry.migrationObligationId !== obligationId) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
        }
      } else {
        entry.legacySourceEnvelope = entry.envelope;
        entry.stagedEnvelope = replacement;
        entry.migrationObligationId = obligationId;
      }
    } else {
      clearLegacyStage(entry);
    }
    if (
      entry.disposition === ENVELOPE_DISPOSITION.VERIFIED_CURRENT
      || entry.disposition === ENVELOPE_DISPOSITION.LOCKED_CURRENT
      || entry.disposition === ENVELOPE_DISPOSITION.FAILED_CURRENT
      || entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
    ) {
      entry.settledGeneration = entry.generation;
      entry.edited = false;
    }
    return entry.disposition;
  }

  async function revealEntry(entry) {
    if (typeof transport?.reveal !== "function") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_REVEAL_FAILED");
    }
    const revealSource = entry.stagedEnvelope || entry.envelope;
    const freshness = captureAsyncFreshness(entry, {
      protectedSource: entry.envelope,
      projectionSource: revealSource,
      requireUnlocked: true,
    });
    let result;
    try {
      result = await transport.reveal(
        entry.field.id,
        revealSource,
      );
      requireAsyncFreshness(entry, freshness);
      if (!result || !("value" in result) || typeof entry.adapter.apply !== "function") {
        throw new Error("invalid reveal");
      }
      entry.adapter.apply(entry.owner, result.value, adapterContext(entry));
    } catch {
      if (typeof entry.adapter.clear === "function") {
        entry.adapter.clear(entry.owner, adapterContext(entry));
      }
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_REVEAL_FAILED");
    }
  }

  function markEdited(owner, fieldId) {
    const entry = requireEntry(owner, fieldId);
    requireEntryInitialized(entry);
    invalidateSubmission();
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

  function notifyModeChange() {
    invalidateSubmission();
    for (const entry of allEntries()) entry.modeDirty = true;
    return true;
  }

  async function reload(owner, fieldId) {
    const entry = requireEntry(owner, fieldId);
    requireEntryInitialized(entry);
    if (activeTransaction) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TRANSACTION_INVALID");
    }
    invalidateSubmission();
    const exact = readProtected(entry);
    entry.generation += 1;
    entry.pending = null;
    entry.canonical = null;
    entry.edited = false;
    entry.envelope = exact;
    entry.settledGeneration = -1;
    clearLegacyStage(entry);
    if (!entry.private) {
      entry.disposition = ENVELOPE_DISPOSITION.VERIFIED_CURRENT;
      entry.settledGeneration = entry.generation;
      if (typeof entry.adapter.apply === "function") {
        entry.adapter.apply(entry.owner, exact, adapterContext(entry));
      }
      return exact;
    }
    await refreshDisposition(entry);
    if (
      sessionState === "unlocked"
      && (
        entry.disposition === ENVELOPE_DISPOSITION.VERIFIED_CURRENT
        || entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
      )
      && typeof entry.adapter.apply === "function"
    ) {
      await revealEntry(entry);
    }
    return exact;
  }

  async function prepareEntry(entry, { allowUninitialized = false } = {}) {
    if (!allowUninitialized) requireEntryInitialized(entry);
    if (entry.settledGeneration === entry.generation && !entry.edited) {
      return entry.stagedEnvelope || entry.envelope;
    }
    if (
      (entry.disposition === ENVELOPE_DISPOSITION.LOCKED_CURRENT
        || entry.disposition === ENVELOPE_DISPOSITION.FAILED_CURRENT)
      && !entry.edited
    ) {
      entry.settledGeneration = entry.generation;
      return entry.stagedEnvelope || entry.envelope;
    }
    if (entry.disposition === ENVELOPE_DISPOSITION.UNSUPPORTED && entry.envelope) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSUPPORTED");
    }

    const generation = entry.generation;
    const normalized = normalizeLive(entry);
    const canonical = canonicalValue(normalized);
    if (entry.canonical === canonical && (entry.stagedEnvelope || entry.envelope)) {
      entry.settledGeneration = generation;
      entry.edited = false;
      return entry.stagedEnvelope || entry.envelope;
    }
    if (
      entry.pending
      && entry.pending.generation === generation
      && entry.pending.canonical === canonical
    ) return entry.pending.promise;

    const pendingRecord = {
      generation,
      canonical,
      freshness: Object.freeze({
        sessionEpoch,
        initialization: entry.initialization,
        protectedSource: readProtected(entry),
        envelope: entry.envelope,
        stagedEnvelope: entry.stagedEnvelope,
        migrationObligationId: entry.migrationObligationId,
        legacySourceEnvelope: entry.legacySourceEnvelope,
        disposition: entry.disposition,
        private: entry.private,
        edited: entry.edited,
      }),
      promise: null,
    };
    if (
      pendingRecord.freshness.protectedSource !== pendingRecord.freshness.envelope
      || sessionState !== "unlocked"
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
    }
    pendingRecord.promise = (async () => {
      let result;
      try {
        result = await transport.protect(entry.field.id, normalized);
      } catch {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_PROTECTION_FAILED");
      }
      requireProtectionFreshness(entry, pendingRecord);
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
      if (entry.legacySourceEnvelope && entry.migrationObligationId) {
        if (readProtected(entry) !== entry.legacySourceEnvelope) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
        }
        entry.stagedEnvelope = envelope;
      } else {
        writeProtected(entry, envelope);
        entry.envelope = envelope;
        clearLegacyStage(entry);
        entry.disposition = ENVELOPE_DISPOSITION.VERIFIED_CURRENT;
      }
      entry.canonical = canonical;
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
    await withDeadline(Promise.resolve(refreshModeFence()), deadline);
    requireModeFence();
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
          && !(entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
            && entry.stagedEnvelope)
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
          migrationObligationId: entry.migrationObligationId,
        }))),
      });
      TRANSACTION_RECORDS.set(
        transaction,
        new Map(entries.map((entry) => [entry, Object.freeze({
          generation: entry.generation,
          disposition: entry.disposition,
          envelope: entry.envelope,
          stagedEnvelope: entry.stagedEnvelope,
          migrationObligationId: entry.migrationObligationId,
          private: entry.private,
        })])),
      );
      latestTransaction = transaction;
      return transaction;
    }
  }

  function requireSettled(reason = "serialize") {
    if (blocked) throw new PrivacySnapshotError("PRIVACY_SUITE_BLOCKED");
    requireModeFence();
    barrierReason(reason);
    if (activeTransaction) return requireActiveTransaction(reason);
    for (const entry of allEntries()) {
      requireEntryInitialized(entry);
      if (entry.modeDirty) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSETTLED");
      }
      if (!entry.private) continue;
      if (entry.disposition === ENVELOPE_DISPOSITION.UNSUPPORTED) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSUPPORTED");
      }
      if (
        entry.pending
        || entry.edited
        || entry.settledGeneration !== entry.generation
        || !entry.envelope
        || (entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
          && (!entry.stagedEnvelope || !entry.migrationObligationId))
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSETTLED");
      }
    }
    return true;
  }

  function workflowProjection(owner, fieldId) {
    const entry = requireEntry(owner, fieldId);
    const record = workflowRecord(entry);
    if (record.disposition === ENVELOPE_DISPOSITION.UNSUPPORTED) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSUPPORTED");
    }
    return record.stagedEnvelope || record.envelope;
  }

  function executionProjection(owner, fieldId) {
    const entry = requireEntry(owner, fieldId);
    const { record, transaction } = transactionState(entry);
    if (
      record.private
      && (
        (
          record.disposition !== ENVELOPE_DISPOSITION.VERIFIED_CURRENT
          && !(record.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
            && record.stagedEnvelope)
        )
        || transaction.sessionEpoch !== sessionEpoch
      )
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    return record.stagedEnvelope || record.envelope;
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

  function workflowRecord(entry) {
    requireEntryInitialized(entry);
    if (activeTransaction) return transactionState(entry).record;
    const recorded = TRANSACTION_RECORDS.get(latestTransaction)?.get(entry);
    if (recorded?.generation === entry.generation) return recorded;
    if (
      entry.pending
      || entry.edited
      || entry.settledGeneration !== entry.generation
      || !entry.envelope
      || (entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
        && (!entry.stagedEnvelope || !entry.migrationObligationId))
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSETTLED");
    }
    return Object.freeze({
      generation: entry.generation,
      disposition: entry.disposition,
      envelope: entry.envelope,
      stagedEnvelope: entry.stagedEnvelope,
      migrationObligationId: entry.migrationObligationId,
      private: entry.private,
    });
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
        && !(record.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
          && record.stagedEnvelope)
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
      }
    }
    return true;
  }

  function requireActiveExecutionTransaction() {
    if (
      !activeTransaction
      || !EXECUTION_BARRIER_REASONS.has(activeTransaction.reason)
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_TRANSACTION_INVALID");
    }
    return requireActiveTransaction(activeTransaction.reason);
  }

  function projectSerializedWorkflow(serializedWorkflow, serializationOwner = null) {
    requireSettled("serialize");
    const legacyEntries = allEntries().filter((entry) => (
      entry.private
      && entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY
    ));
    if (!legacyEntries.length) return serializedWorkflow;

    const projectedWorkflow = cloneWorkflowSerialization(serializedWorkflow);
    const graphContainers = collectSerializedGraphContainers(projectedWorkflow);
    if (!graphContainers.length) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
    }
    const projectedRecords = [];
    for (const entry of legacyEntries) {
      const record = workflowRecord(entry);
      projectedRecords.push(record);
      const containers = serializedContainersForEntry(
        entry,
        serializationOwner,
        graphContainers,
      );
      if (containers === null) continue;
      if (!record.stagedEnvelope || !record.migrationObligationId) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
      const candidates = containers.flatMap(({ value }) => value.nodes.filter((node) => (
          node
          && typeof node === "object"
          && String(node.id) === String(entry.owner?.id)
          && (!node.type || String(node.type) === nodeType(entry.owner))
        )));
      if (candidates.length !== 1) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
      try {
        const result = entry.adapter.writeWorkflowProjection(
          entry.owner,
          candidates[0],
          record.stagedEnvelope,
          adapterContext(entry),
        );
        if (result && typeof result.then === "function") {
          throw new Error("asynchronous projection");
        }
      } catch {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
      if (
        containsExactValue(candidates[0], record.envelope)
        || !containsExactValue(candidates[0], record.stagedEnvelope)
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
      if (readProtected(entry) !== record.envelope) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
      workflowRecord(entry);
    }
    for (const record of projectedRecords) {
      if (containsExactValue(projectedWorkflow, record.envelope)) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
      }
    }
    requireSettled("serialize");
    return projectedWorkflow;
  }

  async function onSessionChange(session) {
    const state = String(session?.state || "unknown");
    if (state === "unknown") return;
    if (!["locked", "unlocked", "setup-required"].includes(state)) return;
    invalidateSubmission();
    sessionState = state;
    sessionEpoch += 1;
    if (state === "locked" || state === "setup-required") {
      for (const entry of allEntries()) {
        entry.generation += 1;
        entry.pending = null;
        entry.canonical = null;
        entry.edited = false;
        clearLegacyStage(entry);
        entry.disposition = entry.envelope
          ? ENVELOPE_DISPOSITION.LOCKED_CURRENT
          : ENVELOPE_DISPOSITION.UNSUPPORTED;
        entry.settledGeneration = entry.envelope ? entry.generation : -1;
        if (typeof entry.adapter.clear === "function") {
          entry.adapter.clear(entry.owner, adapterContext(entry));
        }
      }
      return;
    }
    if (state === "unlocked") {
      await Promise.all(
        allEntries()
          .filter((entry) => entry.initialized && entry.private)
          .map(async (entry) => {
            if (entry.pending || entry.edited) return;
            await refreshDisposition(entry);
            if (
              (entry.disposition === ENVELOPE_DISPOSITION.VERIFIED_CURRENT
                || entry.disposition === ENVELOPE_DISPOSITION.READABLE_LEGACY)
              && typeof entry.adapter.apply === "function"
            ) {
              await revealEntry(entry);
            }
          }),
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

  function captureAsyncFreshness(entry, {
    protectedSource,
    projectionSource = null,
    requireUnlocked = false,
  }) {
    if (requireUnlocked && sessionState !== "unlocked") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
    }
    if (readProtected(entry) !== protectedSource) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
    }
    return Object.freeze({
      sessionEpoch,
      generation: entry.generation,
      protectedSource,
      projectionSource,
      initialization: entry.initialization,
      requireUnlocked,
    });
  }

  function requireAsyncFreshness(entry, freshness) {
    if (
      freshness.sessionEpoch !== sessionEpoch
      || freshness.generation !== entry.generation
      || freshness.initialization !== entry.initialization
      || freshness.protectedSource !== entry.envelope
      || readProtected(entry) !== freshness.protectedSource
      || (freshness.projectionSource !== null
        && (entry.stagedEnvelope || entry.envelope) !== freshness.projectionSource)
      || (freshness.requireUnlocked && sessionState !== "unlocked")
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
    }
  }

  function requireProtectionFreshness(entry, pendingRecord) {
    const freshness = pendingRecord.freshness;
    let currentCanonical;
    let protectedSource;
    try {
      currentCanonical = canonicalValue(normalizeLive(entry));
      protectedSource = readProtected(entry);
    } catch {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
    }
    if (
      freshness.sessionEpoch !== sessionEpoch
      || sessionState !== "unlocked"
      || pendingRecord.generation !== entry.generation
      || pendingRecord.canonical !== currentCanonical
      || pendingRecord !== entry.pending
      || freshness.initialization !== entry.initialization
      || freshness.protectedSource !== protectedSource
      || freshness.envelope !== entry.envelope
      || freshness.stagedEnvelope !== entry.stagedEnvelope
      || freshness.migrationObligationId !== entry.migrationObligationId
      || freshness.legacySourceEnvelope !== entry.legacySourceEnvelope
      || freshness.disposition !== entry.disposition
      || freshness.private !== entry.private
      || freshness.edited !== entry.edited
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_STALE");
    }
  }

  async function prepareSubmission(promptData, onMint = () => {}) {
    if (typeof onMint !== "function") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    const stripped = stripDeclaredSubmissionReferences(promptData);
    return injectExecutionReferencesInternal(stripped, onMint);
  }

  async function injectExecutionReferences(promptData) {
    return (await prepareSubmission(promptData)).promptData;
  }

  function sanitizePromptExport(promptData) {
    return stripDeclaredSubmissionReferences(promptData);
  }

  async function revokePreparedReferences(references) {
    if (!references.length || typeof revokeSubmissionReferences !== "function") return;
    await revokeSubmissionReferences(references.map((item) => item.reference));
  }

  async function injectExecutionReferencesInternal(promptData, onMint = () => {}) {
    if (!projections.length && !subjectBindings.length) {
      return Object.freeze({ promptData, references: Object.freeze([]) });
    }
    requireActiveExecutionTransaction();
    if (projections.length && typeof prepareExecution !== "function") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    const output = promptData?.output;
    if (!output || typeof output !== "object") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    const assignments = [];
    const bindingModes = new Map();
    for (const binding of subjectBindings) {
      if (typeof prepareSubjectMode !== "function") {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
      }
      for (const owner of subjectOwners) {
        if (!binding.nodeTypes.includes(nodeType(owner))) continue;
        const nodeOutput = output[String(owner?.id)];
        if (!nodeOutput || typeof nodeOutput !== "object") continue;
        const prepared = await prepareSubjectMode(binding, owner);
        requireActiveExecutionTransaction();
        if (!prepared?.reference || typeof prepared.reference !== "object") {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        const minted = Object.freeze({ reference: prepared.reference });
        onMint(minted);
        const modeKey = `${String(owner.id)}:${binding.id}`;
        if (bindingModes.has(modeKey) || !["private", "public"].includes(prepared.effective)) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        bindingModes.set(modeKey, prepared.effective);
        let serializedReference;
        try {
          serializedReference = JSON.stringify(prepared.reference);
        } catch {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        const assignment = Object.freeze({
          nodeId: String(owner.id),
          inputName: binding.inputName,
          serializedReference,
          reference: prepared.reference,
        });
        assignments.push(assignment);
      }
    }
    for (const projection of projections) {
      const binding = subjectBindings.find(
        (item) => item.id === projection.subjectModeBindingId,
      );
      if (!binding) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
      }
      for (const [owner, entries] of owners.entries()) {
        if (!binding.nodeTypes.includes(nodeType(owner))) continue;
        const fields = [...entries.values()].filter((entry) => (
          entry.field.workflowResourceId === projection.workflowResourceId
          && entry.field.execution
        ));
        if (!fields.length) continue;
        const mode = bindingModes.get(`${String(owner?.id)}:${binding.id}`);
        if (!mode) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        if (mode === "public") continue;
        if (fields.some((entry) => !entry.initialized || entry.private === false)) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        const nodeOutput = output[String(owner?.id)];
        if (!nodeOutput || typeof nodeOutput !== "object") continue;
        const prepared = await prepareExecution(projection, owner, fields);
        if (!prepared?.reference || typeof prepared.reference !== "object") {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        const minted = Object.freeze({ reference: prepared.reference });
        onMint(minted);
        requireActiveExecutionTransaction();
        let serializedReference;
        try {
          serializedReference = JSON.stringify(prepared.reference);
        } catch {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        if (typeof serializedReference !== "string") {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        assignments.push(Object.freeze({
          nodeId: String(owner?.id),
          inputName: projection.inputName,
          serializedReference,
          reference: prepared.reference,
        }));
      }
    }
    requireActiveExecutionTransaction();
    if (!assignments.length) {
      return Object.freeze({ promptData, references: Object.freeze([]) });
    }
    const protectedOutput = { ...output };
    const protectedNodes = new Map();
    for (const assignment of assignments) {
      let protectedNode = protectedNodes.get(assignment.nodeId);
      if (!protectedNode) {
        const originalNode = output[assignment.nodeId];
        if (!originalNode || typeof originalNode !== "object") {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        protectedNode = {
          ...originalNode,
          inputs: { ...(originalNode.inputs || {}) },
        };
        protectedNodes.set(assignment.nodeId, protectedNode);
        protectedOutput[assignment.nodeId] = protectedNode;
      }
      protectedNode.inputs[assignment.inputName] = assignment.serializedReference;
    }
    requireActiveExecutionTransaction();
    return Object.freeze({
      promptData: { ...promptData, output: protectedOutput },
      references: Object.freeze(assignments),
    });
  }

  function stripDeclaredSubmissionReferences(promptData) {
    const output = promptData?.output;
    if (!output || typeof output !== "object" || Array.isArray(output)) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    const protectedOutput = { ...output };
    for (const owner of new Set([...owners.keys(), ...subjectOwners])) {
      const nodeId = String(owner?.id);
      const originalNode = output[nodeId];
      if (!originalNode || typeof originalNode !== "object") continue;
      const inputNames = new Set();
      for (const projection of projections) {
        const entries = owners.get(owner);
        if ([...(entries?.values() || [])].some((entry) => (
          entry.field.execution
          && entry.field.workflowResourceId === projection.workflowResourceId
        ))) inputNames.add(projection.inputName);
      }
      for (const binding of subjectBindings) {
        if (binding.nodeTypes.includes(nodeType(owner))) inputNames.add(binding.inputName);
      }
      if (!inputNames.size) continue;
      const inputs = { ...(originalNode.inputs || {}) };
      for (const inputName of inputNames) delete inputs[inputName];
      protectedOutput[nodeId] = { ...originalNode, inputs };
    }
    return { ...promptData, output: protectedOutput };
  }

  async function refreshMode(entry, { initial = false } = {}) {
    let nextPrivate;
    try {
      nextPrivate = await resolvePrivate(entry.field, entry.owner) !== false;
    } catch {
      throw new PrivacySnapshotError("PRIVACY_MODE_STATE_UNAVAILABLE");
    }
    if (!initial && nextPrivate === entry.private) {
      entry.modeDirty = false;
      return;
    }
    if (!initial) invalidateSubmission();
    const priorPrivate = entry.private;
    const externallyTransitioned = !initial
      && !priorPrivate
      && nextPrivate
      && readProtected(entry) !== entry.envelope;
    if (!initial && !priorPrivate && nextPrivate && !externallyTransitioned) {
      // Public browser-owned storage is plaintext by definition. Move it into
      // the adapter's live-memory slot and clear the serialized slot before
      // protection starts so a concurrent synchronous serialization fails
      // closed instead of persisting the old public value.
      writeProtected(entry, "");
    }
    let publicValue = null;
    if (!initial && priorPrivate && !nextPrivate && typeof entry.adapter.writePublic === "function") {
      publicValue = entry.adapter.writePublic(
        entry.owner,
        Object.freeze({ ...entry.context, effectiveMode: "public" }),
      );
      if (typeof publicValue !== "string" || readProtected(entry) !== publicValue) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_WRITE_FAILED");
      }
    }
    entry.private = nextPrivate;
    if (!initial) entry.generation += 1;
    entry.pending = null;
    entry.canonical = null;
    entry.edited = false;
    entry.envelope = readProtected(entry);
    clearLegacyStage(entry);
    if (!nextPrivate) {
      if (publicValue !== null) entry.envelope = publicValue;
      entry.disposition = ENVELOPE_DISPOSITION.VERIFIED_CURRENT;
      entry.settledGeneration = entry.generation;
      if (typeof entry.adapter.apply === "function") {
        entry.adapter.apply(entry.owner, entry.envelope, adapterContext(entry));
      }
      entry.modeDirty = false;
      return;
    }
    entry.settledGeneration = -1;
    if (!initial && (priorPrivate || externallyTransitioned)) await refreshDisposition(entry);
    if (!initial && !priorPrivate && !externallyTransitioned) {
      entry.disposition = ENVELOPE_DISPOSITION.UNSUPPORTED;
      entry.edited = true;
    }
    entry.modeDirty = false;
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
    notifyModeChange,
    reload,
    settle,
    requireSettled,
    workflowProjection,
    projectSerializedWorkflow,
    executionProjection,
    onSessionChange,
    refreshModes,
    activateTransaction,
    releaseTransaction,
    requireActiveTransaction,
    requireActiveExecutionTransaction,
    setSubmissionInvalidator,
    prepareSubmission,
    injectExecutionReferences,
    sanitizePromptExport,
    revokePreparedReferences,
  });
}

function normalizeSubjectModeBindings(bindings) {
  if (!Array.isArray(bindings)) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_FIELDS_INVALID");
  }
  return Object.freeze(bindings.map((binding) => Object.freeze({
    id: stableId(binding?.id, "PRIVACY_SNAPSHOT_FIELD_INVALID"),
    scopeId: stableId(binding?.scopeId, "PRIVACY_SNAPSHOT_FIELD_INVALID"),
    inputName: stableId(binding?.inputName, "PRIVACY_SNAPSHOT_FIELD_INVALID"),
    nodeTypes: Object.freeze(
      (Array.isArray(binding?.nodeTypes) ? binding.nodeTypes : [])
        .map((value) => String(value || ""))
        .filter(Boolean),
    ),
  })));
}

function normalizeExecutionProjections(values) {
  if (!Array.isArray(values)) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_FIELDS_INVALID");
  }
  return Object.freeze(values.map((projection) => Object.freeze({
    id: stableId(projection?.id, "PRIVACY_SNAPSHOT_FIELD_INVALID"),
    executionResourceId: stableId(
      projection?.executionResourceId,
      "PRIVACY_SNAPSHOT_FIELD_INVALID",
    ),
    workflowResourceId: stableId(
      projection?.workflowResourceId,
      "PRIVACY_SNAPSHOT_FIELD_INVALID",
    ),
    subjectModeBindingId: stableId(
      projection?.subjectModeBindingId,
      "PRIVACY_SNAPSHOT_FIELD_INVALID",
    ),
    inputName: stableId(projection?.inputName, "PRIVACY_SNAPSHOT_FIELD_INVALID"),
  })));
}

export function installGraphSerializationBarrier(
  app,
  getCoordinators,
  { onConflict = () => {} } = {},
) {
  if (!app || typeof getCoordinators !== "function") {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_BARRIER_INVALID");
  }
  const existing = APP_BARRIERS.get(app);
  if (existing) {
    existing.getCoordinators = getCoordinators;
    existing.onConflict = onConflict;
    existing.wrapGraphs();
    return existing.public;
  }

  const state = {
    getCoordinators,
    wrapGraphs: null,
    public: null,
    operationTail: Promise.resolve(),
    activeQueueGraphToPrompt: null,
    submissionService: null,
    queueInterceptor: null,
    onConflict,
  };
  const connectionState = APP_CONNECTION_GATES.get(app) || null;
  const connectionGate = connectionState?.controller || null;
  const submissionOwnership = connectionState?.submissionOwnership || null;
  let originalGraphToPrompt = connectionGate ? null : app.graphToPrompt;
  let originalQueuePrompt = connectionGate ? null : app.queuePrompt;
  const coordinators = () => {
    const values = state.getCoordinators();
    return Array.isArray(values) ? values : [...(values || [])];
  };
  const abortActiveSubmission = () => {
    state.submissionService?.invalidate();
  };
  const bindSubmissionInvalidators = (current = coordinators()) => {
    for (const coordinator of current) {
      coordinator.setSubmissionInvalidator?.(abortActiveSubmission);
    }
    return current;
  };
  bindSubmissionInvalidators();
  const settleAll = async (reason) => {
    return Promise.all(
      coordinators().map((coordinator) => coordinator.settle(reason)),
    );
  };
  const requireAll = (reason) => {
    for (const coordinator of coordinators()) coordinator.requireSettled(reason);
  };
  const projectAll = (serializedWorkflow, serializationOwner) => {
    let projectedWorkflow = serializedWorkflow;
    for (const coordinator of coordinators()) {
      if (typeof coordinator.projectSerializedWorkflow === "function") {
        projectedWorkflow = coordinator.projectSerializedWorkflow(
          projectedWorkflow,
          serializationOwner,
        );
      }
    }
    return projectedWorkflow;
  };
  const projectPromptWorkflow = (result) => {
    if (
      !result
      || typeof result !== "object"
      || !Object.hasOwn(result, "workflow")
    ) return result;
    const workflow = projectAll(result.workflow, app.rootGraph || app.graph);
    return workflow === result.workflow ? result : { ...result, workflow };
  };
  const injectExecutionReferences = async (promptData, current) => {
    let protectedPromptData = promptData;
    for (const coordinator of current) {
      if (typeof coordinator.injectExecutionReferences === "function") {
        protectedPromptData = await coordinator.injectExecutionReferences(
          protectedPromptData,
        );
      }
    }
    return protectedPromptData;
  };
  const prepareSubmissionData = async (promptData, onMint, current) => {
    if (
      !promptData
      || typeof promptData !== "object"
      || Array.isArray(promptData)
      || !promptData.output
      || typeof promptData.output !== "object"
      || Array.isArray(promptData.output)
      || !promptData.workflow
      || typeof promptData.workflow !== "object"
      || Array.isArray(promptData.workflow)
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
    let detached = cloneWorkflowSerialization(promptData);
    detached.workflow = projectAll(detached.workflow, app.rootGraph || app.graph);
    const references = [];
    for (const coordinator of current) {
      coordinator.requireActiveTransaction("queue");
      if (typeof coordinator.prepareSubmission !== "function") {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
      }
      const prepared = await coordinator.prepareSubmission(detached, (reference) => {
        onMint(Object.freeze({ coordinator, reference }));
      });
      coordinator.requireActiveTransaction("queue");
      if (
        !prepared
        || !prepared.promptData
        || !Array.isArray(prepared.references)
      ) {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
      }
      detached = prepared.promptData;
      references.push(...prepared.references);
    }
    validateSubmissionReferences(detached.output, references);
    for (const coordinator of current) coordinator.requireActiveTransaction("queue");
    return detached;
  };
  const revokeMintedReferences = async (minted) => {
    const grouped = new Map();
    for (const item of minted) {
      const values = grouped.get(item.coordinator) || [];
      values.push(item.reference);
      grouped.set(item.coordinator, values);
    }
    await Promise.allSettled([...grouped].map(([coordinator, references]) => (
      coordinator.revokePreparedReferences?.(references)
    )));
  };
  const invokeGraphToPrompt = async (graphToPrompt, receiver, args, current) => {
    if (typeof graphToPrompt !== "function") {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
    for (const coordinator of current) {
      coordinator.requireActiveTransaction("graph-to-prompt");
    }
    let promptData = projectPromptWorkflow(
      await graphToPrompt.apply(receiver, args),
    );
    for (const coordinator of current) {
      coordinator.requireActiveTransaction("graph-to-prompt");
      if (typeof coordinator.sanitizePromptExport !== "function") {
        if (connectionGate) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
        }
        continue;
      }
      promptData = coordinator.sanitizePromptExport(promptData);
    }
    if (connectionGate) validateSubmissionReferences(promptData?.output, []);
    return promptData;
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
          const graphToPrompt = connectionGate
            ? submissionOwnership?.core?.graphToPrompt
            : originalGraphToPrompt;
          return invokeGraphToPrompt(graphToPrompt, app, args, current);
        },
        snapshotRevisions: Object.freeze(Object.fromEntries(
          transactions.map((transaction) => [transaction.packId, transaction.revision]),
        )),
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
  const runSubmissionExclusive = (operation) => {
    const result = state.operationTail.then(async () => {
      const current = bindSubmissionInvalidators();
      const transactions = await Promise.all(
        current.map((coordinator) => coordinator.settle("queue")),
      );
      let activated = 0;
      try {
        for (; activated < current.length; activated += 1) {
          current[activated].activateTransaction(transactions[activated]);
        }
        return await operation(current);
      } finally {
        for (let index = activated - 1; index >= 0; index -= 1) {
          current[index].releaseTransaction(transactions[index]);
        }
      }
    });
    state.operationTail = result.catch(() => {});
    return result;
  };
  if (connectionGate) {
    state.submissionService = createPrivacyPromptSubmissionService({
      api: submissionOwnership.api,
      coreQueuePrompt: submissionOwnership.core.apiQueuePrompt,
      coreFetchApi: submissionOwnership.core.fetchApi,
      runSubmission: runSubmissionExclusive,
      prepareSubmission: prepareSubmissionData,
      validateSubmission: (current) => {
        for (const coordinator of current) {
          coordinator.requireActiveTransaction("queue");
        }
      },
      revokeMinted: revokeMintedReferences,
      createError: (code) => new PrivacySnapshotError(code),
    });
  }

  const submitProtectedPrompt = (number, promptData, options = undefined) => {
    if (!connectionGate || !state.submissionService) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
    const args = options === undefined
      ? [number, promptData]
      : [number, promptData, options];
    return state.submissionService.handlers.apiQueuePrompt(
      submissionOwnership.core.apiQueuePrompt,
      submissionOwnership.api,
      args,
    );
  };
  const installQueueInterceptor = (interceptor) => {
    if (
      !connectionGate
      || !interceptor
      || typeof interceptor !== "object"
      || Array.isArray(interceptor)
      || typeof interceptor.appQueuePrompt !== "function"
      || typeof interceptor.apiQueuePrompt !== "function"
      || state.queueInterceptor
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
    }
    const token = Object.freeze({});
    state.queueInterceptor = Object.freeze({ token, interceptor });
    return Object.freeze({
      submitPrompt(number, promptData, options = undefined) {
        if (state.queueInterceptor?.token !== token) {
          throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
        }
        return submitProtectedPrompt(number, promptData, options);
      },
      dispose() {
        if (state.queueInterceptor?.token === token) state.queueInterceptor = null;
      },
    });
  };

  if (connectionGate) {
    connectionGate.installBarrierHandlers({
      graphToPrompt: (graphToPrompt, receiver, args) => (
        state.activeQueueGraphToPrompt
          ? state.activeQueueGraphToPrompt(...args)
          : runExclusive(
            "graph-to-prompt",
            () => invokeGraphToPrompt(graphToPrompt, receiver, args, coordinators()),
          )
      ),
      appQueuePrompt: (captured, receiver, args) => {
        const active = state.queueInterceptor?.interceptor;
        return active
          ? active.appQueuePrompt(Object.freeze([...args]))
          : state.submissionService.handlers.appQueuePrompt(captured, receiver, args);
      },
      apiQueuePrompt: (captured, receiver, args) => {
        const active = state.queueInterceptor?.interceptor;
        return active
          ? active.apiQueuePrompt(Object.freeze([...args]))
          : state.submissionService.handlers.apiQueuePrompt(captured, receiver, args);
      },
      fetchApi: state.submissionService.handlers.fetchApi,
      requireSerialize: requireAll,
      projectSerialization: projectAll,
      onConflict: () => {
        abortActiveSubmission();
        state.onConflict();
        for (const coordinator of coordinators()) {
          try {
            coordinator.onSessionChange({ state: "locked" })?.catch?.(() => {});
          } catch {
            /* Gate unavailability remains authoritative. */
          }
        }
      },
    });
  } else if (typeof app.graphToPrompt === "function") {
    originalGraphToPrompt = app.graphToPrompt;
    app.graphToPrompt = async function heltoPrivacyGraphToPrompt(...args) {
      state.wrapGraphs();
      if (state.activeQueueGraphToPrompt) {
        return state.activeQueueGraphToPrompt(...args);
      }
      return runExclusive(
        "graph-to-prompt",
        async () => {
          const promptData = projectPromptWorkflow(
            await originalGraphToPrompt.apply(this, args),
          );
          return injectExecutionReferences(promptData, coordinators());
        },
      );
    };
  }
  if (!connectionGate && typeof originalQueuePrompt === "function") {
    app.queuePrompt = async function heltoPrivacyQueuePrompt(...args) {
      state.wrapGraphs();
      return runExclusive(
        "queue",
        async ({ graphToPrompt }) => {
          state.activeQueueGraphToPrompt = graphToPrompt;
          try {
            return projectPromptWorkflow(
              await originalQueuePrompt.apply(this, args),
            );
          } finally {
            state.activeQueueGraphToPrompt = null;
          }
        },
      );
    };
  }

  state.wrapGraphs = connectionGate
    ? () => connectionGate.refreshGraphs()
    : () => wrapGraphAndSubgraphs(
      app.rootGraph || app.graph,
      requireAll,
      projectAll,
    );
  state.public = Object.freeze({
    settle: settleAll,
    requireSettled: requireAll,
    refreshGraphs: () => state.wrapGraphs(),
    takeOwnership: (attempt) => attempt?.takeOwnership(),
    runWithSnapshot: (reason, operation) => {
      if (typeof operation !== "function") {
        throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_OPERATION_INVALID");
      }
      state.wrapGraphs();
      return runExclusive(reason, operation);
    },
    installQueueInterceptor,
  });
  APP_BARRIERS.set(app, state);
  state.wrapGraphs();
  return state.public;
}

function wrapGraphAndSubgraphs(graph, requireAll, projectAll) {
  if (!graph || typeof graph !== "object") return;
  if (typeof graph.serialize === "function" && !graph[GRAPH_SERIALIZE_WRAPPED]) {
    const original = graph.serialize;
    graph.serialize = function heltoPrivacySerialize(...args) {
      requireAll("serialize");
      const serialized = original.apply(this, args);
      return projectAll(serialized, this);
    };
    Object.defineProperty(graph, GRAPH_SERIALIZE_WRAPPED, { value: true });
  }
  const subgraphs = graph.subgraphs;
  const values = typeof subgraphs?.values === "function"
    ? subgraphs.values()
    : (Array.isArray(subgraphs) ? subgraphs : []);
  for (const subgraph of values) {
    wrapGraphAndSubgraphs(subgraph, requireAll, projectAll);
  }
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
    const legacyReaderIds = Object.freeze(
      (Array.isArray(field?.legacyReaderIds) ? field.legacyReaderIds : [])
        .map((value) => String(value || ""))
        .filter(Boolean),
    );
    if (!nodeTypes.length || seen.has(id)) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_FIELD_INVALID");
    }
    seen.add(id);
    return Object.freeze({
      id,
      workflowResourceId,
      scopeId,
      browserAdapter,
      nodeTypes,
      legacyReaderIds,
      execution: field?.execution === true,
    });
  }));
}

function validateAdapter(adapter, field) {
  if (
    typeof adapter?.normalize !== "function"
    || typeof adapter?.readProtected !== "function"
    || typeof adapter?.writeProtected !== "function"
    || (field.legacyReaderIds.length
      && typeof adapter?.writeWorkflowProjection !== "function")
  ) throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_ADAPTER_INVALID");
}

function clearLegacyStage(entry) {
  entry.stagedEnvelope = "";
  entry.migrationObligationId = null;
  entry.legacySourceEnvelope = "";
}

function cloneWorkflowSerialization(value) {
  try {
    if (typeof globalThis.structuredClone === "function") {
      return globalThis.structuredClone(value);
    }
    const serialized = JSON.stringify(value);
    if (typeof serialized !== "string") throw new Error("invalid serialization");
    return JSON.parse(serialized);
  } catch {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
  }
}

function collectSerializedGraphContainers(workflow) {
  const containers = [];
  const visited = new WeakSet();
  const visit = (value, root = false) => {
    if (!value || typeof value !== "object" || visited.has(value)) return;
    visited.add(value);
    if (!Array.isArray(value.nodes)) return;
    containers.push(Object.freeze({
      value,
      root,
      identity: root ? null : serializedGraphIdentity(value),
    }));
    const nested = [];
    if (Array.isArray(value.definitions?.subgraphs)) {
      nested.push(...value.definitions.subgraphs);
    }
    if (Array.isArray(value.subgraphs)) nested.push(...value.subgraphs);
    for (const subgraph of nested) visit(subgraph, false);
  };
  visit(workflow, true);
  return containers;
}

function serializedContainersForEntry(entry, serializationOwner, containers) {
  const ownerGraph = entry.owner?.graph;
  if (!serializationOwner || !ownerGraph) return containers;
  if (ownerGraph === serializationOwner) {
    return containers.filter((container) => container.root);
  }
  if (!graphContainsGraph(serializationOwner, ownerGraph)) return null;
  const identity = liveGraphIdentity(ownerGraph);
  if (!identity) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
  }
  const matches = containers.filter(
    (container) => !container.root && container.identity === identity,
  );
  if (matches.length !== 1) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED");
  }
  return matches;
}

function graphContainsGraph(root, target, visited = new WeakSet()) {
  if (root === target) return true;
  if (!root || typeof root !== "object" || visited.has(root)) return false;
  visited.add(root);
  for (const subgraph of subgraphCollectionValues(root.subgraphs)) {
    if (graphContainsGraph(subgraph, target, visited)) return true;
  }
  return false;
}

function liveGraphIdentity(graph) {
  for (const key of ["id", "_id", "uuid", "graphId"]) {
    const value = graph?.[key];
    if (typeof value === "string" && value) return value;
  }
  return "";
}

function serializedGraphIdentity(graph) {
  for (const key of ["id", "uuid", "graphId"]) {
    const value = graph?.[key];
    if (typeof value === "string" && value) return value;
  }
  return "";
}

function containsExactValue(value, expected, visited = new WeakSet()) {
  if (value === expected) return true;
  if (!value || typeof value !== "object" || visited.has(value)) return false;
  visited.add(value);
  if (Array.isArray(value)) {
    return value.some((item) => containsExactValue(item, expected, visited));
  }
  return Object.values(value).some(
    (item) => containsExactValue(item, expected, visited),
  );
}

function normalizeLive(entry) {
  try {
    return entry.adapter.normalize(entry.owner, adapterContext(entry));
  } catch {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_NORMALIZATION_FAILED");
  }
}

function readProtected(entry) {
  try {
    const value = entry.adapter.readProtected(entry.owner, adapterContext(entry));
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
    entry.adapter.writeProtected(entry.owner, envelope, adapterContext(entry));
    const written = readProtected(entry);
    if (written !== envelope) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_WRITE_FAILED");
    }
  } catch {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_WRITE_FAILED");
  }
}

function adapterContext(entry) {
  return Object.freeze({
    ...entry.context,
    effectiveMode: entry.private ? "private" : "public",
  });
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
    return canonicalJson(value);
  } catch {
    return "";
  }
}

function canonicalValue(value) {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  return canonicalJson(value);
}

const EPHEMERAL_REFERENCE_SCHEMAS = new Set([
  "helto.private-execution-reference",
  "helto.subject-mode-reference",
]);
const EPHEMERAL_REFERENCE_MARKERS = Object.freeze([
  "helto.private-execution-reference",
  "helto.subject-mode-reference",
]);
const EPHEMERAL_REFERENCE_SCAN_LIMIT = 1024 * 1024;

function validateSubmissionReferences(output, references) {
  const expected = new Map();
  for (const reference of references) {
    const path = `output.${reference.nodeId}.inputs.${reference.inputName}`;
    if (expected.has(path)) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    let parsed;
    try {
      parsed = JSON.parse(reference.serializedReference);
    } catch {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    if (!isCurrentEphemeralReference(parsed)) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    expected.set(path, canonicalReference(parsed));
  }
  const observed = [];
  scanEphemeralReferences(output, "output", observed, new WeakSet());
  if (observed.length !== expected.size) {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
  }
  const seen = new Set();
  for (const item of observed) {
    if (
      seen.has(item.path)
      || expected.get(item.path) !== item.canonical
    ) {
      throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
    }
    seen.add(item.path);
  }
}

function isCurrentEphemeralReference(reference) {
  if (!reference || typeof reference !== "object" || Array.isArray(reference)) {
    return false;
  }
  if (reference.schema === "helto.private-execution-reference") {
    return reference.version === 2 && /^[0-9a-f]{64}$/.test(reference.subject);
  }
  return reference.schema === "helto.subject-mode-reference"
    && reference.version === 2
    && /^[0-9a-f]{64}$/.test(reference.profileFingerprint)
    && /^[0-9a-f]{64}$/.test(reference.subject)
    && typeof reference.bindingId === "string"
    && !!reference.bindingId;
}

function scanEphemeralReferences(value, path, observed, visited, parsedValue = false) {
  if (typeof value === "string") {
    if (parsedValue && !isJsonContainerText(value)) return;
    if (value.length <= EPHEMERAL_REFERENCE_SCAN_LIMIT && isJsonContainerText(value)) {
      try {
        scanEphemeralReferences(
          JSON.parse(value),
          path,
          observed,
          new WeakSet(),
          true,
        );
        return;
      } catch (error) {
        if (error instanceof PrivacySnapshotError) throw error;
        if (!hasDecodedEphemeralReferenceMarker(value)) return;
      }
    } else if (!hasDecodedEphemeralReferenceMarker(value)) {
      return;
    }
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
  }
  if (!value || typeof value !== "object" || visited.has(value)) return;
  visited.add(value);
  if (EPHEMERAL_REFERENCE_SCHEMAS.has(value.schema)) {
    observed.push({ path, canonical: canonicalReference(value) });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => (
      scanEphemeralReferences(item, `${path}.${index}`, observed, visited, parsedValue)
    ));
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    scanEphemeralReferences(item, `${path}.${key}`, observed, visited, parsedValue);
  }
}

function isJsonContainerText(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) continue;
    return code === 0x7b || code === 0x5b;
  }
  return false;
}

function hasDecodedEphemeralReferenceMarker(value) {
  const progress = EPHEMERAL_REFERENCE_MARKERS.map(() => 0);
  const feed = (character) => {
    for (let index = 0; index < EPHEMERAL_REFERENCE_MARKERS.length; index += 1) {
      const marker = EPHEMERAL_REFERENCE_MARKERS[index];
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

function canonicalReference(value) {
  try {
    return canonicalJson(value);
  } catch {
    throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_EXECUTION_BLOCKED");
  }
}

function canonicalJson(value, ancestors = new WeakSet()) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-json number");
    return JSON.stringify(value);
  }
  if (!value || typeof value !== "object") {
    throw new TypeError("non-json value");
  }
  if (ancestors.has(value)) throw new TypeError("cyclic json value");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Reflect.ownKeys(value);
      if (ownKeys.some((key) => (
        key !== "length"
        && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key))
      ))) throw new TypeError("non-json array property");
      const encoded = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
          throw new TypeError("non-json array slot");
        }
        encoded.push(canonicalJson(descriptor.value, ancestors));
      }
      return `[${encoded.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("non-json object");
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      throw new TypeError("non-json symbol property");
    }
    const encoded = [];
    for (const key of keys.sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
        throw new TypeError("non-json object property");
      }
      encoded.push(`${JSON.stringify(key)}:${canonicalJson(descriptor.value, ancestors)}`);
    }
    return `{${encoded.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
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
