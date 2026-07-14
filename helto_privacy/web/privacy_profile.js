// Atomic browser compiler for Helto privacy profiles. This module owns only
// profile attestation, typed browser handles, and ComfyUI lifecycle binding.

import {
  connectAttestedPrivacyProfileClient,
  isPrivacySetupRequiredError,
  subscribePrivacySession,
} from "../privacy_client.js";
import {
  mountSharedPrivacySurface,
  showPrivateRecordMutationDialog,
  showPrivacyKeystoreDialog,
} from "../privacy.js";
import { normalizeArtifactLease } from "../privacy_artifacts.js";
import { normalizeRecordShell } from "../privacy_records.js";
import {
  createPrivacySnapshotCoordinator,
  installGraphSerializationBarrier,
  installPrivacyConnectionSerializationGate,
} from "../privacy_snapshot.js";

export const PRIVACY_CONTRACT_V3 = "helto.privacy.v3";
export const MODE_TRANSITION_PROTOCOL = "recoverable-v1";

const STATUS = Object.freeze({
  CONNECTING: "connecting",
  READY: "ready",
  CONFLICT: "conflict",
  SUITE_ACTIVE: "active",
});
const VERIFICATION_SUITE_STATUSES = new Set([
  "cutover-pending",
  "ready",
  "activation-required",
  STATUS.SUITE_ACTIVE,
]);
const RESOURCE_KIND = Object.freeze({
  MODE: "mode",
  WORKFLOW: "workflow",
  RECORD: "record",
  SINGLETON: "singleton",
  ARTIFACT: "artifact",
  EXECUTION: "execution",
  OPERATION: "operation",
});
const CONNECTED_PRIVACY_PACKS = new Map();
const CONNECTING_PRIVACY_PACKS = new WeakMap();
const PACK_ENTRIES = new WeakMap();
const HANDLE_ENTRIES = new WeakMap();
const ACTIVE_EXTERNAL_MODE_FENCES = new Set();
let PRIVACY_EXTENSION_APP = null;
let PRIVACY_EXTENSION_REGISTERED = false;

export class PrivacyPackConnectionError extends Error {
  constructor(code) {
    super("Privacy pack connection is incomplete or conflicting.");
    this.name = "PrivacyPackConnectionError";
    this.code = code;
  }
}

export class BrowserReadinessHandle {
  constructor(entry) {
    HANDLE_ENTRIES.set(this, entry);
    Object.freeze(this);
  }

  get state() {
    return HANDLE_ENTRIES.get(this).status;
  }

  requireReady() {
    if (this.state !== STATUS.READY) {
      throw new PrivacyPackConnectionError("browser_pack_blocked");
    }
  }
}

export class BrowserAuthorizationHandle {
  constructor(entry) {
    HANDLE_ENTRIES.set(this, entry);
    this.packId = entry.id;
    Object.freeze(this);
  }

  get readiness() {
    return new BrowserReadinessHandle(HANDLE_ENTRIES.get(this));
  }

  requireReady() {
    this.readiness.requireReady();
    if (HANDLE_ENTRIES.get(this).suiteStatus !== STATUS.SUITE_ACTIVE) {
      throw new PrivacyPackConnectionError("server_suite_not_active");
    }
  }

}

export class BrowserSessionHandle {
  constructor(entry) {
    HANDLE_ENTRIES.set(this, entry);
    Object.freeze(this);
  }

  get state() {
    return HANDLE_ENTRIES.get(this).sessionState;
  }

  subscribe(listener, options = {}) {
    return subscribePrivacySession(listener, options);
  }
}

class BrowserResourceHandle {
  constructor(entry, resource) {
    HANDLE_ENTRIES.set(this, entry);
    this.packId = entry.id;
    this.resourceId = resource.id;
    Object.freeze(this);
  }

  get readiness() {
    return new BrowserReadinessHandle(HANDLE_ENTRIES.get(this));
  }
}

class BrowserInvokableResourceHandle extends BrowserResourceHandle {
  invoke(operationId, body = undefined) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const operation = entry.protectedOperations.find(
      (item) => item.id === operationId && item.resourceId === this.resourceId,
    );
    if (!operation) throw new PrivacyPackConnectionError("unknown_browser_operation");
    return entry.transport.invoke(this.resourceId, operation.id, body);
  }
}

export class BrowserOperationHandle extends BrowserResourceHandle {
  invoke(operationId, input, references = {}) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const operation = entry.protectedOperations.find(
      (item) => item.id === operationId
        && item.resourceId === this.resourceId
        && item.typed === true
        && item.route !== null,
    );
    if (
      !operation
      || input === undefined
      || !references
      || typeof references !== "object"
      || Array.isArray(references)
    ) {
      throw new PrivacyPackConnectionError("unknown_browser_operation");
    }
    const expected = operation.referenceInputs.map((item) => item.name).sort();
    const supplied = Object.keys(references).sort();
    if (
      expected.join("\0") !== supplied.join("\0")
      || supplied.some((name) => (
        typeof references[name] !== "string"
        || !/^hp-ref-[A-Za-z0-9_-]{32}$/.test(references[name])
      ))
    ) {
      throw new PrivacyPackConnectionError("invalid_browser_operation_reference");
    }
    return Promise.resolve(entry.transport.invoke(
      this.resourceId,
      operation.id,
      { input, references: { ...references } },
    )).then((result) => validateTypedOperationResponse(result, operation));
  }

  invokeExternal(operationId, owner, input, references = {}) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const operation = entry.protectedOperations.find(
      (item) => item.id === operationId
        && item.resourceId === this.resourceId
        && item.externalOperationBinding !== null,
    );
    if (
      !operation
      || owner == null
      || input === undefined
      || !references
      || typeof references !== "object"
      || Array.isArray(references)
    ) {
      throw new PrivacyPackConnectionError("unknown_browser_operation");
    }
    const expected = operation.referenceInputs.map((item) => item.name).sort();
    const supplied = Object.keys(references).sort();
    if (
      expected.join("\0") !== supplied.join("\0")
      || supplied.some((name) => (
        typeof references[name] !== "string"
        || !/^hp-ref-[A-Za-z0-9_-]{32}$/.test(references[name])
      ))
    ) {
      throw new PrivacyPackConnectionError("invalid_browser_operation_reference");
    }
    return coordinateExternalOperation(
      entry,
      operation,
      owner,
      input,
      Object.freeze({ ...references }),
    );
  }

  revoke(references) {
    return HANDLE_ENTRIES.get(this).transport.revokeReferences(references);
  }

  claim(operationId, associationId) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const operation = entry.protectedOperations.find(
      (item) => item.id === operationId
        && item.resourceId === this.resourceId
        && item.deferredUi === true,
    );
    if (!operation || !/^hp-assoc-[A-Za-z0-9_-]{32}$/.test(String(associationId || ""))) {
      throw new PrivacyPackConnectionError("unknown_browser_operation");
    }
    return Promise.resolve(entry.transport.claimAssociation(associationId))
      .then((result) => validateTypedOperationResponse(result, operation));
  }
}

async function coordinateExternalOperation(entry, operation, suppliedOwner, input, references) {
  const binding = operation.externalOperationBinding;
  const field = entry.protectedFields.find((item) => item.id === binding.fieldId);
  const adapter = entry.adapters[binding.browserAdapter];
  if (!field || !adapter) {
    throw new PrivacyPackConnectionError("browser_external_operation_invalid");
  }
  const context = Object.freeze({ field, operation });
  let settlement = null;
  let storageKey = null;
  let session = null;
  let requestStarted = false;
  let primaryError = null;
  let clearAfterRelease = false;
  try {
    settlement = adapter.settleExternalOperation(suppliedOwner, context);
    if (
      !settlement
      || typeof settlement !== "object"
      || typeof settlement.release !== "function"
      || typeof settlement.settled?.then !== "function"
    ) {
      throw new PrivacyPackConnectionError("browser_external_operation_settle_invalid");
    }
    await settlement.settled;
    const identity = normalizeExternalOperationIdentity(
      await adapter.identifyExternalOperationOwner(suppliedOwner, context),
      field,
      binding.policy,
    );
    storageKey = await externalOperationStorageKey(entry, operation, identity);
    session = readExternalOperationSession(storageKey);
    let response;
    if (session?.transactionId) {
      response = await entry.transport.externalOperations.resume(
        operation.id,
        session.transactionId,
        session.resumeCapability,
      );
    } else {
      if (session === null) {
        session = writeExternalOperationSession(storageKey, {
          requestId: randomCapability("hp-operation-request-", 18),
          transactionId: null,
          resumeCapability: null,
        });
      }
      const original = boundedExternalExact(
        await adapter.readExternalOperationExact(suppliedOwner, context),
        binding.policy.maxOriginalBytes,
      );
      requestStarted = true;
      response = await entry.transport.externalOperations.prepare(
        operation.id,
        {
          requestId: session.requestId,
          ownerIdentity: identity,
          originalExact: bytesToBase64(original),
          input,
          references: { ...references },
        },
      );
      if (response.active) {
        session = writeExternalOperationSession(storageKey, {
          requestId: session.requestId,
          transactionId: response.transactionId,
          resumeCapability: response.resumeCapability,
        });
      }
    }
    let owner = await resolveExternalOperationOwner(
      adapter,
      response.ownerIdentity,
      context,
      field,
      binding.policy,
    );
    if (response.phase === "prepared") {
      await adapter.applyExternalOperation(
        owner,
        cloneExternalOperationValue(response.browserValue),
        context,
      );
      const current = boundedExternalExact(
        await adapter.readExternalOperationExact(owner, context),
        binding.policy.maxTargetBytes,
      );
      response = await entry.transport.externalOperations.apply(
        operation.id,
        session.transactionId,
        session.resumeCapability,
        bytesToBase64(current),
      );
    } else if (["captured", "rollback-required"].includes(response.phase)) {
      response = await rollbackExternalOperationBrowserState(
        entry,
        operation,
        adapter,
        owner,
        context,
        binding.policy,
        session,
        response,
      );
    }
    if (!["completed", "rolled-back"].includes(response.phase)) {
      throw new PrivacyPackConnectionError("browser_external_operation_indeterminate");
    }
    owner = await resolveExternalOperationOwner(
      adapter,
      response.ownerIdentity,
      context,
      field,
      binding.policy,
    );
    const result = await settleExternalOperationTerminal(
      adapter,
      owner,
      context,
      binding.policy,
      response,
      operation,
    );
    clearAfterRelease = true;
    if (response.phase === "rolled-back") {
      throw new PrivacyPackConnectionError("browser_external_operation_rolled_back");
    }
    return result;
  } catch (error) {
    primaryError = error;
    if (storageKey && session && !session.transactionId && !requestStarted) {
      clearExternalOperationSession(storageKey);
      session = null;
    }
    if (
      !clearAfterRelease
      && storageKey
      && session?.transactionId
      && session.resumeCapability
    ) {
      try {
        let recovery = await entry.transport.externalOperations.resume(
          operation.id,
          session.transactionId,
          session.resumeCapability,
        );
        const owner = await resolveExternalOperationOwner(
          adapter,
          recovery.ownerIdentity,
          context,
          field,
          binding.policy,
        );
        if (!["completed", "rolled-back"].includes(recovery.phase)) {
          recovery = await rollbackExternalOperationBrowserState(
            entry,
            operation,
            adapter,
            owner,
            context,
            binding.policy,
            session,
            recovery,
          );
        }
        if (["completed", "rolled-back"].includes(recovery.phase)) {
          const result = await settleExternalOperationTerminal(
            adapter,
            owner,
            context,
            binding.policy,
            recovery,
            operation,
          );
          clearAfterRelease = true;
          if (recovery.phase === "completed") {
            primaryError = null;
            return result;
          }
        }
      } catch {
        // The product-free session capability remains available for a retry.
      }
    }
    throw error;
  } finally {
    let releaseSucceeded = settlement === null;
    if (settlement !== null) {
      try {
        await settlement.release(context);
        releaseSucceeded = true;
      } catch (error) {
        if (primaryError === null) {
          throw new PrivacyPackConnectionError("browser_external_operation_release_failed");
        }
      }
    }
    if (clearAfterRelease && releaseSucceeded && storageKey !== null) {
      try {
        clearExternalOperationSession(storageKey);
        session = null;
      } catch (error) {
        if (primaryError === null) throw error;
      }
    }
  }
}

async function rollbackExternalOperationBrowserState(
  entry,
  operation,
  adapter,
  owner,
  context,
  policy,
  session,
  response,
) {
  if (typeof response.originalExact !== "string") {
    throw new PrivacyPackConnectionError("browser_external_operation_indeterminate");
  }
  const original = boundedExternalExact(
    base64ToBytes(response.originalExact),
    policy.maxOriginalBytes,
  );
  await adapter.restoreExternalOperationExact(owner, original, context);
  const readback = boundedExternalExact(
    await adapter.readExternalOperationExact(owner, context),
    policy.maxOriginalBytes,
  );
  if (!exactBytesEqual(original, readback)) {
    throw new PrivacyPackConnectionError("browser_external_operation_restore_failed");
  }
  return entry.transport.externalOperations.rollback(
    operation.id,
    session.transactionId,
    session.resumeCapability,
  );
}

async function settleExternalOperationTerminal(
  adapter,
  owner,
  context,
  policy,
  response,
  operation,
) {
  const maximum = response.phase === "completed"
    ? policy.maxTargetBytes : policy.maxOriginalBytes;
  const canonical = boundedExternalExact(base64ToBytes(response.exact), maximum);
  await adapter.restoreExternalOperationExact(owner, canonical, context);
  const readback = boundedExternalExact(
    await adapter.readExternalOperationExact(owner, context),
    maximum,
  );
  if (!exactBytesEqual(canonical, readback)) {
    throw new PrivacyPackConnectionError("browser_external_operation_restore_failed");
  }
  await adapter.reloadExternalOperationRuntime(owner, context);
  await adapter.reconcileExternalOperationRuntime(owner, context);
  return response.phase === "completed"
    ? validateTypedOperationResponse(response.result, operation)
    : null;
}

async function resolveExternalOperationOwner(adapter, identity, context, field, policy) {
  const normalized = normalizeExternalOperationIdentity(identity, field, policy);
  const owner = await adapter.resolveExternalOperationOwner(normalized, context);
  if (owner == null) {
    throw new PrivacyPackConnectionError("browser_external_operation_owner_missing");
  }
  const resolved = normalizeExternalOperationIdentity(
    await adapter.identifyExternalOperationOwner(owner, context),
    field,
    policy,
  );
  if (JSON.stringify(resolved) !== JSON.stringify(normalized)) {
    throw new PrivacyPackConnectionError("browser_external_operation_owner_drift");
  }
  return owner;
}

function normalizeExternalOperationIdentity(value, field, policy) {
  const keys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort().join("\0") : "";
  const identity = {
    fieldId: String(value?.fieldId || ""),
    graphId: String(value?.graphId || ""),
    nodeId: String(value?.nodeId || ""),
    rootGraphId: String(value?.rootGraphId || ""),
  };
  const encoded = new TextEncoder().encode(JSON.stringify(identity));
  if (
    keys !== "fieldId\0graphId\0nodeId\0rootGraphId"
    || identity.fieldId !== field.id
    || identity.rootGraphId !== "root"
    || Object.values(identity).some(
      (item) => !/^[A-Za-z0-9._~:-]{1,128}$/.test(item),
    )
    || encoded.byteLength > policy.maxIdentityBytes
  ) {
    throw new PrivacyPackConnectionError("browser_external_operation_owner_invalid");
  }
  return Object.freeze(identity);
}

function boundedExternalExact(value, maximum) {
  const exact = exactBytes(value);
  if (exact.byteLength > maximum) {
    throw new PrivacyPackConnectionError("browser_external_operation_exact_invalid");
  }
  return exact;
}

function cloneExternalOperationValue(value) {
  try {
    return typeof globalThis.structuredClone === "function"
      ? globalThis.structuredClone(value)
      : JSON.parse(JSON.stringify(value));
  } catch {
    throw new PrivacyPackConnectionError("browser_external_operation_value_invalid");
  }
}

async function externalOperationStorageKey(entry, operation, identity) {
  if (typeof globalThis.crypto?.subtle?.digest !== "function") {
    throw new PrivacyPackConnectionError("browser_external_crypto_unavailable");
  }
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(identity)),
  );
  return `helto_privacy_external_operation:${entry.id}:${operation.id}:`
    + bytesToBase64(new Uint8Array(digest));
}

function readExternalOperationSession(key) {
  try {
    const raw = requireExternalSessionStorage().getItem(key);
    if (!raw) return null;
    const value = JSON.parse(raw);
    if (
      !value
      || typeof value !== "object"
      || Array.isArray(value)
      || Object.keys(value).sort().join("\0")
        !== "requestId\0resumeCapability\0transactionId"
      || !/^hp-operation-request-[A-Za-z0-9_-]{24,64}$/.test(value.requestId)
      || ((value.transactionId === null) !== (value.resumeCapability === null))
      || (value.transactionId !== null
        && !/^hp-operation-[A-Za-z0-9_-]{32}$/.test(value.transactionId))
      || (value.resumeCapability !== null
        && !/^hp-operation-resume-[A-Za-z0-9_-]{43}$/.test(value.resumeCapability))
    ) {
      throw new Error("invalid operation session");
    }
    return Object.freeze(value);
  } catch {
    throw new PrivacyPackConnectionError("browser_external_session_invalid");
  }
}

function writeExternalOperationSession(key, value) {
  const safe = {
    requestId: String(value.requestId || ""),
    resumeCapability: value.resumeCapability === null
      ? null : String(value.resumeCapability || ""),
    transactionId: value.transactionId === null
      ? null : String(value.transactionId || ""),
  };
  try {
    const storage = requireExternalSessionStorage();
    const encoded = JSON.stringify(safe);
    storage.setItem(key, encoded);
    if (storage.getItem(key) !== encoded) throw new Error("session write failed");
    return readExternalOperationSession(key);
  } catch {
    throw new PrivacyPackConnectionError("browser_external_session_unavailable");
  }
}

function clearExternalOperationSession(key) {
  try {
    const storage = requireExternalSessionStorage();
    storage.removeItem(key);
    if (storage.getItem(key) !== null) throw new Error("session clear failed");
  } catch {
    throw new PrivacyPackConnectionError("browser_external_session_unavailable");
  }
}

export class BrowserModeHandle extends BrowserInvokableResourceHandle {
  resolve(scopeId, owner = null) {
    const entry = HANDLE_ENTRIES.get(this);
    const scope = entry.modeScopes.find(
      (item) => item.id === scopeId && item.modeResourceId === this.resourceId,
    );
    if (!scope) {
      throw new PrivacyPackConnectionError("unknown_browser_mode_scope");
    }
    const adapter = owner != null && scope.modeEditorAdapter
      ? entry.adapters[scope.modeEditorAdapter]
      : null;
    return entry.transport.mode.resolve(
      this.resourceId,
      scopeId,
      adapter?.readDeclaredMode?.(owner),
      adapter?.readModeFacts?.(owner),
    );
  }

  async transition(scopeId, target) {
    const entry = HANDLE_ENTRIES.get(this);
    if (!entry.modeScopes.some(
      (scope) => scope.id === scopeId && scope.modeResourceId === this.resourceId,
    )) {
      throw new PrivacyPackConnectionError("unknown_browser_mode_scope");
    }
    entry.pack.authorization.requireReady();
    const externalFields = entry.protectedFields.filter(
      (field) => field.scopeId === scopeId
        && field.stateAuthority === "external-browser-workflow",
    );
    let retryExemption = null;
    let result;
    try {
      if (externalFields.length) {
        retryExemption = activateExternalModeRetryExemption(entry, scopeId);
        result = await entry.serializationBarrier.runWithSnapshot(
          "mode-transition",
          (transaction) => runExternalBrowserModeTransition(
            entry,
            scopeId,
            target,
            externalFields,
            transaction,
          ),
        );
      } else {
        result = await entry.transport.mode.transition(scopeId, target);
      }
    } finally {
      deactivateExternalModeFence(retryExemption);
    }
    if (result !== null) await entry.snapshotCoordinator.refreshModes();
    return result;
  }
}

async function runExternalBrowserModeTransition(
  entry,
  scopeId,
  target,
  fields,
  transaction,
) {
  const stored = readExternalTransitionSession(entry.id, scopeId);
  const coordinatorId = stored?.coordinatorId || sessionCoordinatorId(entry.id);
  const resumeSecret = stored?.resumeSecret || randomCapability("hp-mode-resume-", 32);
  const status = await entry.transport.mode.readAll();
  const scopeStatus = status.scopes.find((scope) => scope.id === scopeId);
  if (!scopeStatus || !Number.isInteger(scopeStatus.modeEpoch)) {
    throw new PrivacyPackConnectionError("browser_mode_epoch_unavailable");
  }
  const serverBootEpoch = String(status.serverBootEpoch || "");
  if (!/^hp-boot-[A-Za-z0-9_-]{16,64}$/.test(serverBootEpoch)) {
    throw new PrivacyPackConnectionError("browser_mode_epoch_unavailable");
  }
  entry.serverBootEpoch = serverBootEpoch;
  if (stored === null) {
    recordExternalModeObservation(entry, scopeId, scopeStatus, serverBootEpoch);
  }
  const context = {
    packId: entry.id,
    profileFingerprint: entry.fingerprint,
    scopeId,
    target,
    coordinatorId,
    serverBootEpoch,
    snapshotRevision: transaction?.snapshotRevisions?.[entry.id],
  };
  let session = stored;
  let inventory = null;
  let owners = new Map();
  let recovery;
  let finalizeStarted = false;
  let terminal = false;
  let terminalCompletion = null;
  let primaryError = null;
  const settlements = [];
  const fence = claimExternalModeFence(
    entry, scopeId, coordinatorId, scopeStatus.modeEpoch, serverBootEpoch, fields,
  );
  try {
    await entry.transport.mode.heartbeat(scopeId, {
      coordinatorId,
      resumeSecret,
      serverBootEpoch,
    });
    inventory = await inventoryExternalOwners(entry, fields, context, settlements);
    if (session) {
      if (session.target !== target) {
        throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
      }
      if (
        scopeStatus.transitionStatus === "idle"
        && scopeStatus.modeEpoch === session.targetModeEpoch
        && scopeStatus.declared === session.target
      ) {
        for (const item of inventory.values) {
          await rebaseSettledExternalOwner(
            entry,
            item.owner,
            item.field,
            scopeStatus,
            serverBootEpoch,
            Object.freeze({ ...context, field: item.field }),
          );
        }
        const completed = Object.freeze({
          scopeId,
          declared: scopeStatus.declared,
          effective: scopeStatus.effective,
          transitionStatus: "idle",
          modeEpoch: scopeStatus.modeEpoch,
        });
        terminalCompletion = completed;
        terminal = true;
        return completed;
      }
      if (session.modeEpoch !== scopeStatus.modeEpoch) {
        throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
      }
      recovery = await entry.transport.mode.resume(
        scopeId,
        session.transitionId,
        {
          coordinatorId,
          resumeSecret,
          modeEpoch: session.modeEpoch,
          serverBootEpoch,
        },
      );
      session = updateExternalTransitionSession(entry.id, scopeId, {
        ...session,
        clientLease: recovery.clientLease,
        clientLeaseEpoch: recovery.clientLeaseEpoch,
        serverBootEpoch,
      });
    } else {
      const requestId = randomCapability("mode-request-", 18);
      const reservation = await reserveExternalTransitionWithRetry(
        entry, scopeId, target, {
          requestId,
          coordinatorId,
          resumeSecret,
          offlineRepresentationCount: inventory.offlineRepresentationCount,
          expectedModeEpoch: scopeStatus.modeEpoch,
          serverBootEpoch,
        },
      );
      if (reservation === null) {
        terminal = true;
        return null;
      }
      session = updateExternalTransitionSession(entry.id, scopeId, {
        transitionId: reservation.transitionId,
        requestId: reservation.requestId,
        coordinatorId,
        resumeSecret,
        scopeId,
        target,
        modeEpoch: reservation.modeEpoch,
        targetModeEpoch: reservation.targetModeEpoch,
        priorDeclared: reservation.priorDeclared,
        clientLease: reservation.clientLease,
        clientLeaseEpoch: reservation.clientLeaseEpoch,
        serverBootEpoch,
      });
    }
    owners = await bindOpaqueOwnerIds(entry, scopeId, inventory.values, session);
    if (!recovery) {
      recovery = await entry.transport.mode.prepare(
        scopeId,
        session.transitionId,
        {
          ...externalCapability(session),
          owners: inventory.values.map((item) => ({
            locator: item.locator,
            originalExact: bytesToBase64(item.originalExact),
          })),
        },
      );
    }
    if (["rollback-restoring", "rolling-back"].includes(recovery?.externalPhase)) {
      const completed = await rollbackExternalOwners(
        entry, scopeId, owners, session, context,
      );
      terminalCompletion = completed;
      terminal = true;
      return completed;
    }
    recovery = await applyPendingExternalOwners(
      entry, scopeId, owners, session, recovery, context,
    );
    const serialized = detachedWorkflowSerialization(entry.app);
    const detached = [];
    for (const pending of owners.values()) {
      const exact = exactBytes(await pending.adapter.extractDetachedModeTransitionOwnerExact(
        pending.owner,
        serialized,
        Object.freeze({ ...context, field: pending.field }),
      ));
      detached.push({ ownerId: pending.ownerId, exact: bytesToBase64(exact) });
    }
    recovery = await entry.transport.mode.verify(
      scopeId,
      session.transitionId,
      {
        ...externalCapability(session),
        acknowledgements: detached,
        snapshotId: randomCapability("mode-snapshot-", 18),
        snapshotGeneration: Number(transaction?.snapshotRevisions?.[entry.id] || 0),
      },
    );
    finalizeStarted = true;
    const completed = await finalizeExternalTransitionWithRetry(
      entry,
      scopeId,
      session.transitionId,
      session,
    );
    await reconcileExternalRuntime(owners, context);
    terminalCompletion = completed;
    terminal = true;
    return completed;
  } catch (error) {
    primaryError = error;
    if (session && !finalizeStarted) {
      try {
        const completed = await rollbackExternalOwners(
          entry, scopeId, owners, session, context,
        );
        terminalCompletion = completed;
        terminal = true;
      } catch {
        // The product-free recovery capability and cross-tab fence remain durable.
      }
    }
    throw error;
  } finally {
    let cleanupError = null;
    try {
      await releaseExternalSettlements(settlements, context);
    } catch (error) {
      cleanupError = error;
    }
    if ((terminal || !session) && cleanupError === null) {
      try {
        if (terminalCompletion !== null) {
          recordExternalModeCompletion(entry, scopeId, terminalCompletion);
          if (session !== null) clearExternalTransitionSession(entry.id, scopeId);
        }
        releaseExternalModeFence(fence);
      } catch (error) {
        cleanupError = error;
        deactivateExternalModeFence(fence);
      }
    } else {
      // Owning a durable fence is only an exemption while this coordinator call
      // is actively running.  A failed or unreleased call must fence its own
      // tab until an authenticated retry reclaims the fence.
      deactivateExternalModeFence(fence);
    }
    if (primaryError === null && cleanupError !== null) throw cleanupError;
  }
}

async function inventoryExternalOwners(entry, fields, context, settlements) {
  const values = [];
  let offlineRepresentationCount = 0;
  let totalBytes = 0;
  const totalBytesLimit = Math.min(
    ...fields.map((field) => field.externalTransitionPolicy.maxTotalBytes),
  );
  for (const field of fields) {
    const adapter = entry.adapters[field.browserAdapter];
    const settlement = adapter.settleModeTransition(
      Object.freeze({ ...context, field }),
    );
    if (
      !settlement
      || typeof settlement !== "object"
      || typeof settlement.release !== "function"
      || typeof settlement.settled?.then !== "function"
    ) {
      throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
    }
    settlements.push(Object.freeze({ field, release: settlement.release }));
    const settled = await settlement.settled;
    if (!Number.isInteger(settled?.offlineRepresentationCount)
      || settled.offlineRepresentationCount < 0) {
      throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
    }
    offlineRepresentationCount += settled.offlineRepresentationCount;
    const owners = await adapter.inventoryModeTransitionOwners(
      Object.freeze({ ...context, field }),
    );
    if (!Array.isArray(owners)) {
      throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
    }
    if (owners.length > field.externalTransitionPolicy.maxOwners) {
      throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
    }
    for (const item of owners) {
      const locator = normalizeExternalOwnerLocator(item, field.id);
      const originalExact = exactBytes(await adapter.readModeTransitionOwnerExact(
        item.owner,
        Object.freeze({ ...context, field }),
      ));
      totalBytes += originalExact.byteLength;
      if (
        originalExact.byteLength > field.externalTransitionPolicy.maxOriginalBytesPerOwner
        || totalBytes > totalBytesLimit
      ) {
        throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
      }
      values.push({ adapter, field, owner: item.owner, locator, originalExact });
    }
  }
  const identities = values.map((item) => JSON.stringify(item.locator));
  if (new Set(identities).size !== identities.length) {
    throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
  }
  return Object.freeze({ values, offlineRepresentationCount });
}

async function releaseExternalSettlements(settlements, context) {
  let failed = false;
  for (const settlement of [...settlements].reverse()) {
    try {
      await settlement.release(Object.freeze({
        ...context,
        field: settlement.field,
      }));
    } catch {
      failed = true;
    }
  }
  if (failed) {
    throw new PrivacyPackConnectionError("browser_external_release_failed");
  }
}

async function reserveExternalTransitionWithRetry(entry, scopeId, target, capability) {
  try {
    return await entry.transport.mode.reserve(scopeId, target, capability);
  } catch {
    return entry.transport.mode.reserve(scopeId, target, capability);
  }
}

async function finalizeExternalTransitionWithRetry(entry, scopeId, transitionId, session) {
  try {
    return await entry.transport.mode.finalize(
      scopeId, transitionId, externalCapability(session),
    );
  } catch {
    try {
      return await entry.transport.mode.finalize(
        scopeId, transitionId, externalCapability(session),
      );
    } catch {
      const canonical = await canonicalExternalCompletion(
        entry, scopeId, session.targetModeEpoch, session.target,
      );
      if (canonical) return canonical;
      throw new PrivacyPackConnectionError("browser_external_terminal_indeterminate");
    }
  }
}

async function canonicalExternalCompletion(entry, scopeId, modeEpoch, declared) {
  try {
    const status = await entry.transport.mode.readAll();
    const scope = status.scopes.find((item) => item.id === scopeId);
    if (
      scope
      && scope.transitionStatus === "idle"
      && scope.modeEpoch === modeEpoch
      && scope.declared === declared
    ) {
      return Object.freeze({
        scopeId,
        declared: scope.declared,
        effective: scope.effective,
        transitionStatus: "idle",
        modeEpoch: scope.modeEpoch,
      });
    }
  } catch {
    // The durable product-free session remains available for an exact retry.
  }
  return null;
}

async function bindOpaqueOwnerIds(entry, scopeId, inventory, session) {
  const owners = new Map();
  for (const item of inventory) {
    const ownerId = await opaqueExternalOwnerId(
      session.resumeSecret,
      entry.id,
      entry.fingerprint,
      scopeId,
      item.locator,
    );
    if (owners.has(ownerId)) {
      throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
    }
    owners.set(ownerId, { ...item, ownerId });
  }
  return owners;
}

async function applyPendingExternalOwners(
  entry, scopeId, owners, session, recovery, context,
) {
  for (const pending of recovery?.pendingOwners || []) {
    const local = owners.get(String(pending?.ownerId || ""));
    if (!local || local.field.id !== pending.fieldId) {
      throw new PrivacyPackConnectionError("browser_external_owner_drift");
    }
    const exact = base64ToBytes(pending.exact);
    if (exact.byteLength > local.field.externalTransitionPolicy.maxTargetBytesPerOwner) {
      throw new PrivacyPackConnectionError("browser_external_owner_drift");
    }
    await local.adapter.applyModeTransitionOwnerExact(
      local.owner,
      exact,
      Object.freeze({ ...context, field: local.field }),
    );
    const readback = exactBytes(await local.adapter.readModeTransitionOwnerExact(
      local.owner,
      Object.freeze({ ...context, field: local.field }),
    ));
    recovery = await entry.transport.mode.applyAck(
      scopeId,
      session.transitionId,
      {
        ...externalCapability(session),
        acknowledgements: [{
          ownerId: local.ownerId,
          exact: bytesToBase64(readback),
        }],
      },
    );
  }
  return recovery;
}

async function rollbackExternalOwners(entry, scopeId, owners, session, context) {
  let rollback = await rollbackExternalStepWithRetry(
    entry, scopeId, session,
    { ...externalCapability(session), acknowledgements: null },
  );
  for (const pending of rollback?.pendingOwners || []) {
    const local = owners.get(String(pending?.ownerId || ""));
    if (!local) throw new PrivacyPackConnectionError("browser_external_owner_drift");
    const original = base64ToBytes(pending.exact);
    if (original.byteLength > local.field.externalTransitionPolicy.maxOriginalBytesPerOwner) {
      throw new PrivacyPackConnectionError("browser_external_owner_drift");
    }
    await local.adapter.restoreModeTransitionOwnerExact(
      local.owner,
      original,
      Object.freeze({ ...context, field: local.field }),
    );
    const readback = exactBytes(await local.adapter.readModeTransitionOwnerExact(
      local.owner,
      Object.freeze({ ...context, field: local.field }),
    ));
    rollback = await rollbackExternalStepWithRetry(
      entry, scopeId, session,
      {
        ...externalCapability(session),
        acknowledgements: [{ ownerId: local.ownerId, exact: bytesToBase64(readback) }],
      },
    );
  }
  await reconcileExternalRuntime(owners, context);
  return rollback;
}

async function rollbackExternalStepWithRetry(entry, scopeId, session, body) {
  try {
    return await entry.transport.mode.rollback(
      scopeId, session.transitionId, body,
    );
  } catch {
    try {
      return await entry.transport.mode.rollback(
        scopeId, session.transitionId, body,
      );
    } catch {
      const canonical = await canonicalExternalCompletion(
        entry, scopeId, session.targetModeEpoch, session.priorDeclared,
      );
      if (canonical) return canonical;
      throw new PrivacyPackConnectionError("browser_external_terminal_indeterminate");
    }
  }
}

async function reconcileExternalRuntime(owners, context) {
  for (const item of owners.values()) {
    await item.adapter.reloadModeTransitionRuntime(
      item.owner,
      Object.freeze({ ...context, field: item.field }),
    );
    await item.adapter.reconcileModeTransitionRuntime(
      item.owner,
      Object.freeze({ ...context, field: item.field }),
    );
  }
}

function normalizeExternalOwnerLocator(value, fieldId) {
  const locator = {
    rootGraphId: String(value?.rootGraphId || ""),
    graphId: String(value?.graphId || ""),
    nodeId: String(value?.nodeId || ""),
    fieldId: String(fieldId || ""),
  };
  if (
    locator.rootGraphId !== "root"
    || Object.values(locator).some(
      (item) => !/^[A-Za-z0-9._~:-]{1,128}$/.test(item),
    )
  ) {
    throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
  }
  return Object.freeze(locator);
}

function detachedWorkflowSerialization(app) {
  const graph = app?.rootGraph || app?.graph;
  if (typeof graph?.serialize !== "function") {
    throw new PrivacyPackConnectionError("browser_external_serialization_unavailable");
  }
  try {
    const serialized = graph.serialize();
    return typeof globalThis.structuredClone === "function"
      ? globalThis.structuredClone(serialized)
      : JSON.parse(JSON.stringify(serialized));
  } catch {
    throw new PrivacyPackConnectionError("browser_external_serialization_unavailable");
  }
}

function exactBytes(value) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(
      value.byteOffset,
      value.byteOffset + value.byteLength,
    ));
  }
  throw new PrivacyPackConnectionError("browser_external_exact_bytes_invalid");
}

function bytesToBase64(value) {
  const bytes = exactBytes(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function base64ToBytes(value) {
  const encoded = String(value || "");
  if (!/^[A-Za-z0-9_-]*$/.test(encoded)) {
    throw new PrivacyPackConnectionError("browser_external_exact_bytes_invalid");
  }
  try {
    const binary = globalThis.atob(
      encoded.replaceAll("-", "+").replaceAll("_", "/")
        + "=".repeat((4 - encoded.length % 4) % 4),
    );
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (bytesToBase64(bytes) !== encoded) throw new Error("noncanonical");
    return bytes;
  } catch {
    throw new PrivacyPackConnectionError("browser_external_exact_bytes_invalid");
  }
}

function exactBytesEqual(left, right) {
  const leftBytes = exactBytes(left);
  const rightBytes = exactBytes(right);
  let difference = leftBytes.byteLength ^ rightBytes.byteLength;
  const length = Math.max(leftBytes.byteLength, rightBytes.byteLength);
  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] || 0) ^ (rightBytes[index] || 0);
  }
  return difference === 0;
}

function randomCapability(prefix, byteLength) {
  if (typeof globalThis.crypto?.getRandomValues !== "function") {
    throw new PrivacyPackConnectionError("browser_external_crypto_unavailable");
  }
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return `${prefix}${bytesToBase64(bytes)}`;
}

async function opaqueExternalOwnerId(
  resumeSecret,
  packId,
  profileFingerprint,
  scopeId,
  locator,
) {
  if (typeof globalThis.crypto?.subtle?.importKey !== "function") {
    throw new PrivacyPackConnectionError("browser_external_crypto_unavailable");
  }
  const encoder = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(resumeSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const message = [
    "graph-node-field-v1",
    packId,
    profileFingerprint,
    scopeId,
    locator.rootGraphId,
    locator.graphId,
    locator.nodeId,
    locator.fieldId,
  ].join("\0");
  const signature = await globalThis.crypto.subtle.sign(
    "HMAC", key, encoder.encode(message),
  );
  return `hp-owner-${bytesToBase64(new Uint8Array(signature))}`;
}

function externalCapability(session) {
  return {
    resumeSecret: session.resumeSecret,
    coordinatorId: session.coordinatorId,
    clientLease: session.clientLease,
    clientLeaseEpoch: session.clientLeaseEpoch,
    modeEpoch: session.modeEpoch,
    serverBootEpoch: session.serverBootEpoch,
  };
}

function externalTransitionStorageKey(packId, scopeId) {
  return `helto_privacy_mode_transition:${packId}:${scopeId}`;
}

function sessionCoordinatorId(packId) {
  const key = `helto_privacy_mode_coordinator:${packId}`;
  try {
    const storage = requireExternalSessionStorage();
    const stored = storage.getItem(key);
    if (/^mode-coordinator-[A-Za-z0-9_-]{24}$/.test(stored || "")) return stored;
    const created = randomCapability("mode-coordinator-", 18);
    storage.setItem(key, created);
    if (storage.getItem(key) !== created) throw new Error("session write failed");
    return created;
  } catch {
    throw new PrivacyPackConnectionError("browser_external_session_unavailable");
  }
}

function readExternalTransitionSession(packId, scopeId) {
  try {
    const raw = requireExternalSessionStorage().getItem(
      externalTransitionStorageKey(packId, scopeId),
    );
    if (!raw) return null;
    const value = JSON.parse(raw);
    const keys = Object.keys(value).sort().join("\0");
    if (
      keys !== [
        "clientLease", "clientLeaseEpoch", "coordinatorId", "modeEpoch",
        "priorDeclared", "requestId", "resumeSecret", "scopeId", "serverBootEpoch",
        "target", "targetModeEpoch", "transitionId",
      ].sort().join("\0")
      || value.scopeId !== scopeId
      || !["inherit", "private", "public"].includes(value.target)
      || !Number.isInteger(value.modeEpoch)
      || !Number.isInteger(value.targetModeEpoch)
      || value.targetModeEpoch !== value.modeEpoch + 1
      || !Number.isInteger(value.clientLeaseEpoch)
      || !["inherit", "private", "public"].includes(value.priorDeclared)
      || !/^[a-f0-9]{32}$/.test(value.transitionId)
      || !/^hp-mode-resume-[A-Za-z0-9_-]{43}$/.test(value.resumeSecret)
      || !/^hp-mode-client-[A-Za-z0-9_-]{43}$/.test(value.clientLease)
    ) {
      throw new Error("invalid transition session");
    }
    return Object.freeze(value);
  } catch {
    throw new PrivacyPackConnectionError("browser_external_session_invalid");
  }
}

function updateExternalTransitionSession(packId, scopeId, value) {
  const safe = {
    transitionId: String(value.transitionId),
    requestId: String(value.requestId),
    coordinatorId: String(value.coordinatorId),
    resumeSecret: String(value.resumeSecret),
    scopeId: String(value.scopeId),
    target: String(value.target),
    modeEpoch: Number(value.modeEpoch),
    targetModeEpoch: Number(value.targetModeEpoch),
    priorDeclared: String(value.priorDeclared),
    clientLease: String(value.clientLease),
    clientLeaseEpoch: Number(value.clientLeaseEpoch),
    serverBootEpoch: String(value.serverBootEpoch),
  };
  try {
    const storage = requireExternalSessionStorage();
    const key = externalTransitionStorageKey(packId, scopeId);
    const encoded = JSON.stringify(safe);
    storage.setItem(key, encoded);
    if (storage.getItem(key) !== encoded) throw new Error("session write failed");
  } catch {
    throw new PrivacyPackConnectionError("browser_external_session_unavailable");
  }
  return Object.freeze(safe);
}

function clearExternalTransitionSession(packId, scopeId) {
  try {
    const storage = requireExternalSessionStorage();
    const key = externalTransitionStorageKey(packId, scopeId);
    storage.removeItem(key);
    if (storage.getItem(key) !== null) throw new Error("session clear failed");
  } catch {
    throw new PrivacyPackConnectionError("browser_external_session_unavailable");
  }
}

function requireExternalSessionStorage() {
  const storage = globalThis.sessionStorage;
  if (
    !storage
    || typeof storage.getItem !== "function"
    || typeof storage.setItem !== "function"
    || typeof storage.removeItem !== "function"
  ) {
    throw new PrivacyPackConnectionError("browser_external_session_unavailable");
  }
  return storage;
}

function externalModeFenceKey(packId, scopeId) {
  return `helto_privacy_mode_fence:${packId}:${scopeId}`;
}

function externalModeEpochKey(packId, scopeId) {
  return `helto_privacy_mode_epoch:${packId}:${scopeId}`;
}

function requireExternalLocalStorage() {
  const storage = globalThis.localStorage;
  if (
    !storage
    || typeof storage.getItem !== "function"
    || typeof storage.setItem !== "function"
    || typeof storage.removeItem !== "function"
  ) {
    throw new PrivacyPackConnectionError("browser_external_cross_tab_unavailable");
  }
  return storage;
}

function claimExternalModeFence(
  entry, scopeId, coordinatorId, modeEpoch, serverBootEpoch, fields,
) {
  const storage = requireExternalLocalStorage();
  const key = externalModeFenceKey(entry.id, scopeId);
  const now = Date.now();
  try {
    const current = JSON.parse(storage.getItem(key) || "null");
    if (
      current
      && Number.isFinite(current.expiresAt)
      && current.expiresAt > now
      && current.coordinatorId !== coordinatorId
    ) {
      throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
    }
  } catch (error) {
    if (error instanceof PrivacyPackConnectionError) throw error;
    throw new PrivacyPackConnectionError("browser_external_cross_tab_unavailable");
  }
  const leaseSeconds = Math.min(
    ...fields.map((field) => field.externalTransitionPolicy.leaseSeconds),
  );
  const value = Object.freeze({
    coordinatorId,
    modeEpoch,
    serverBootEpoch,
    expiresAt: now + leaseSeconds * 1000,
  });
  const encoded = JSON.stringify(value);
  try {
    storage.setItem(key, encoded);
    if (storage.getItem(key) !== encoded) throw new Error("fence write failed");
  } catch {
    throw new PrivacyPackConnectionError("browser_external_cross_tab_unavailable");
  }
  ACTIVE_EXTERNAL_MODE_FENCES.add(key);
  return Object.freeze({ key, coordinatorId });
}

function releaseExternalModeFence(fence) {
  if (!fence) return;
  const storage = requireExternalLocalStorage();
  try {
    const current = JSON.parse(storage.getItem(fence.key) || "null");
    if (current?.coordinatorId === fence.coordinatorId) storage.removeItem(fence.key);
    ACTIVE_EXTERNAL_MODE_FENCES.delete(fence.key);
  } catch {
    throw new PrivacyPackConnectionError("browser_external_cross_tab_unavailable");
  }
}

function deactivateExternalModeFence(fence) {
  if (fence) ACTIVE_EXTERNAL_MODE_FENCES.delete(fence.key);
}

function activateExternalModeRetryExemption(entry, scopeId) {
  const session = readExternalTransitionSession(entry.id, scopeId);
  if (session === null) return null;
  const storage = requireExternalLocalStorage();
  const key = externalModeFenceKey(entry.id, scopeId);
  try {
    const fence = JSON.parse(storage.getItem(key) || "null");
    if (
      fence
      && Number.isFinite(fence.expiresAt)
      && fence.expiresAt > Date.now()
      && fence.coordinatorId !== session.coordinatorId
    ) {
      throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
    }
  } catch (error) {
    if (error instanceof PrivacyPackConnectionError) throw error;
    throw new PrivacyPackConnectionError("browser_external_cross_tab_unavailable");
  }
  ACTIVE_EXTERNAL_MODE_FENCES.add(key);
  return Object.freeze({ key, coordinatorId: session.coordinatorId });
}

function recordExternalModeObservation(entry, scopeId, scope, serverBootEpoch) {
  if (!Number.isInteger(scope?.modeEpoch)) return;
  const observed = Object.freeze({
    modeEpoch: scope.modeEpoch,
    serverBootEpoch,
  });
  const known = entry.modeEpochs.get(scopeId);
  if (
    known
    && (
      known.modeEpoch !== observed.modeEpoch
      || known.serverBootEpoch !== observed.serverBootEpoch
    )
  ) {
    throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
  }
  if (!known) entry.modeEpochs.set(scopeId, observed);
}

function recordExternalModeCompletion(entry, scopeId, completed) {
  if (!Number.isInteger(completed?.modeEpoch)) {
    throw new PrivacyPackConnectionError("browser_mode_epoch_unavailable");
  }
  const value = Object.freeze({
    modeEpoch: completed.modeEpoch,
    serverBootEpoch: entry.serverBootEpoch,
  });
  const encoded = JSON.stringify(value);
  const storage = requireExternalLocalStorage();
  storage.setItem(externalModeEpochKey(entry.id, scopeId), encoded);
  if (storage.getItem(externalModeEpochKey(entry.id, scopeId)) !== encoded) {
    throw new PrivacyPackConnectionError("browser_external_cross_tab_unavailable");
  }
  entry.modeEpochs.set(scopeId, value);
}

function requireEntryModeFence(entry) {
  if (!entry.protectedFields.some(
    (field) => field.stateAuthority === "external-browser-workflow",
  )) return true;
  const storage = requireExternalLocalStorage();
  for (const field of entry.protectedFields) {
    if (field.stateAuthority !== "external-browser-workflow") continue;
    const fenceKey = externalModeFenceKey(entry.id, field.scopeId);
    try {
      const fence = JSON.parse(storage.getItem(fenceKey) || "null");
      const activelyOwned = ACTIVE_EXTERNAL_MODE_FENCES.has(fenceKey);
      if (
        !activelyOwned
        && readExternalTransitionSession(entry.id, field.scopeId) !== null
      ) {
        throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
      }
      if (
        fence
        && fence.expiresAt > Date.now()
        && !activelyOwned
      ) {
        throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
      }
      const marker = JSON.parse(
        storage.getItem(externalModeEpochKey(entry.id, field.scopeId)) || "null",
      );
      const known = entry.modeEpochs.get(field.scopeId);
      if (
        marker
        && known
        && (
          marker.modeEpoch !== known.modeEpoch
          || marker.serverBootEpoch !== known.serverBootEpoch
        )
      ) {
        throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
      }
    } catch (error) {
      if (error instanceof PrivacyPackConnectionError) throw error;
      throw new PrivacyPackConnectionError("browser_external_cross_tab_unavailable");
    }
  }
  return true;
}

async function refreshEntryModeFences(entry) {
  const scopes = new Set(entry.protectedFields
    .filter((field) => field.stateAuthority === "external-browser-workflow")
    .map((field) => field.scopeId));
  if (!scopes.size) return true;
  const status = await entry.transport.mode.readAll();
  const serverBootEpoch = String(status.serverBootEpoch || "");
  if (!/^hp-boot-[A-Za-z0-9_-]{16,64}$/.test(serverBootEpoch)) {
    throw new PrivacyPackConnectionError("browser_mode_epoch_unavailable");
  }
  entry.serverBootEpoch = serverBootEpoch;
  for (const scopeId of scopes) {
    const scope = status.scopes.find((item) => item.id === scopeId);
    if (!scope || !Number.isInteger(scope.modeEpoch)) {
      throw new PrivacyPackConnectionError("browser_mode_epoch_unavailable");
    }
    const session = readExternalTransitionSession(entry.id, scopeId);
    const retrying = session !== null && ACTIVE_EXTERNAL_MODE_FENCES.has(
      externalModeFenceKey(entry.id, scopeId),
    );
    if (scope.transitionStatus !== "idle" && session === null) {
      throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
    }
    const known = entry.modeEpochs.get(scopeId);
    if (!retrying) {
      recordExternalModeObservation(entry, scopeId, scope, serverBootEpoch);
    }
    if (!retrying && !known && scope.transitionStatus === "idle") {
      const storage = requireExternalLocalStorage();
      const key = externalModeEpochKey(entry.id, scopeId);
      const marker = JSON.parse(storage.getItem(key) || "null");
      if (
        marker
        && (
          marker.modeEpoch !== scope.modeEpoch
          || marker.serverBootEpoch !== serverBootEpoch
        )
      ) {
        throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
      }
      recordExternalModeCompletion(entry, scopeId, scope);
    }
  }
  return requireEntryModeFence(entry);
}

async function reloadExternalOwnerAfterModeEpoch(entry, owner, field) {
  const status = await entry.transport.mode.readAll();
  const scope = status.scopes.find((item) => item.id === field.scopeId);
  const serverBootEpoch = String(status.serverBootEpoch || "");
  if (
    !scope
    || scope.transitionStatus !== "idle"
    || !Number.isInteger(scope.modeEpoch)
    || !/^hp-boot-[A-Za-z0-9_-]{16,64}$/.test(serverBootEpoch)
  ) {
    throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
  }
  const adapter = entry.adapters[field.browserAdapter];
  const context = Object.freeze({
    packId: entry.id,
    profileFingerprint: entry.fingerprint,
    scopeId: field.scopeId,
    target: scope.declared,
    serverBootEpoch,
    field,
  });
  const settlement = adapter.settleModeTransition(context);
  if (
    !settlement
    || typeof settlement !== "object"
    || typeof settlement.release !== "function"
    || typeof settlement.settled?.then !== "function"
  ) {
    throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
  }
  let primaryError = null;
  try {
    const settled = await settlement.settled;
    if (
      !Number.isInteger(settled?.offlineRepresentationCount)
      || settled.offlineRepresentationCount < 0
    ) {
      throw new PrivacyPackConnectionError("browser_external_inventory_invalid");
    }
    await rebaseSettledExternalOwner(
      entry, owner, field, scope, serverBootEpoch, context,
    );
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      await settlement.release(context);
    } catch {
      if (primaryError === null) {
        throw new PrivacyPackConnectionError("browser_external_release_failed");
      }
    }
  }
  entry.serverBootEpoch = serverBootEpoch;
  entry.modeEpochs.set(field.scopeId, Object.freeze({
    modeEpoch: scope.modeEpoch,
    serverBootEpoch,
  }));
  recordExternalModeCompletion(entry, field.scopeId, scope);
  return true;
}

async function rebaseSettledExternalOwner(
  entry,
  owner,
  field,
  scope,
  serverBootEpoch,
  context,
) {
  const adapter = entry.adapters[field.browserAdapter];
  const staleExact = exactBytes(await adapter.readModeTransitionOwnerExact(
    owner,
    context,
  ));
  const maximumInputBytes = Math.max(
    field.externalTransitionPolicy.maxOriginalBytesPerOwner,
    field.externalTransitionPolicy.maxTargetBytesPerOwner,
  );
  if (staleExact.byteLength > maximumInputBytes) {
    throw new PrivacyPackConnectionError("browser_external_owner_drift");
  }
  const rebased = await entry.transport.mode.rebase(field.scopeId, {
    fieldId: field.id,
    exact: bytesToBase64(staleExact),
    modeEpoch: scope.modeEpoch,
    serverBootEpoch,
  });
  if (
    rebased?.scopeId !== field.scopeId
    || rebased?.fieldId !== field.id
    || rebased?.modeEpoch !== scope.modeEpoch
    || rebased?.serverBootEpoch !== serverBootEpoch
  ) {
    throw new PrivacyPackConnectionError("browser_mode_transition_fenced");
  }
  const canonicalExact = base64ToBytes(rebased.exact);
  if (
    canonicalExact.byteLength
    > field.externalTransitionPolicy.maxTargetBytesPerOwner
  ) {
    throw new PrivacyPackConnectionError("browser_external_owner_drift");
  }
  await adapter.applyModeTransitionOwnerExact(owner, canonicalExact, context);
  const applied = exactBytes(await adapter.readModeTransitionOwnerExact(owner, context));
  if (!exactBytesEqual(applied, canonicalExact)) {
    throw new PrivacyPackConnectionError("browser_external_owner_drift");
  }
  await adapter.reloadModeTransitionRuntime(owner, context);
  await adapter.reconcileModeTransitionRuntime(owner, context);
  const reconciled = exactBytes(
    await adapter.readModeTransitionOwnerExact(owner, context),
  );
  if (!exactBytesEqual(reconciled, canonicalExact)) {
    throw new PrivacyPackConnectionError("browser_external_owner_drift");
  }
}
export class BrowserWorkflowHandle extends BrowserInvokableResourceHandle {
  markEdited(owner, fieldId) {
    const entry = HANDLE_ENTRIES.get(this);
    requireWorkflowField(entry, this.resourceId, fieldId);
    requireEntryModeFence(entry);
    return entry.snapshotCoordinator.markEdited(owner, fieldId);
  }

  notifyModeChange() {
    const entry = HANDLE_ENTRIES.get(this);
    requireEntryModeFence(entry);
    entry.snapshotCoordinator.notifyModeChange();
    return entry.serializationBarrier.settle("manual-save");
  }

  reload(owner, fieldId) {
    const entry = HANDLE_ENTRIES.get(this);
    const field = requireWorkflowField(entry, this.resourceId, fieldId);
    if (field.stateAuthority === "external-browser-workflow") {
      return reloadExternalOwnerAfterModeEpoch(entry, owner, field).then(
        () => entry.snapshotCoordinator.reload(owner, fieldId),
      );
    }
    return entry.snapshotCoordinator.reload(owner, fieldId);
  }

  settle(reason = "manual-save") {
    const entry = HANDLE_ENTRIES.get(this);
    return entry.serializationBarrier.settle(reason);
  }

  runWithSnapshot(reason, operation) {
    const entry = HANDLE_ENTRIES.get(this);
    return entry.serializationBarrier.runWithSnapshot(reason, operation);
  }

  installQueueInterceptor(interceptor) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    return entry.serializationBarrier.installQueueInterceptor(interceptor);
  }

  requireSettled(reason = "serialize") {
    const entry = HANDLE_ENTRIES.get(this);
    return entry.serializationBarrier.requireSettled(reason);
  }

  workflowProjection(owner, fieldId) {
    const entry = HANDLE_ENTRIES.get(this);
    requireWorkflowField(entry, this.resourceId, fieldId);
    return entry.snapshotCoordinator.workflowProjection(owner, fieldId);
  }

  executionProjection(owner, fieldId) {
    const entry = HANDLE_ENTRIES.get(this);
    requireWorkflowField(entry, this.resourceId, fieldId);
    return entry.snapshotCoordinator.executionProjection(owner, fieldId);
  }
}
export class BrowserRecordHandle extends BrowserResourceHandle {
  async list(recordKind) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const declaration = requireRecordDeclaration(entry, this.resourceId, recordKind);
    const result = await entry.transport.records.list(this.resourceId, declaration.id);
    if (!Array.isArray(result?.records)) {
      throw new PrivacyPackConnectionError("invalid_private_record_shell");
    }
    const shells = result.records.map(normalizeRecordShell);
    if (shells.some((shell) => !shell || shell.kind !== declaration.id)) {
      throw new PrivacyPackConnectionError("invalid_private_record_shell");
    }
    return Object.freeze(shells);
  }

  reveal(recordKind, recordId, operation) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const declaration = requireRecordDeclaration(entry, this.resourceId, recordKind);
    if (!declaration.revealOperations.includes(operation)) {
      throw new PrivacyPackConnectionError("unknown_browser_record_operation");
    }
    return entry.transport.records.reveal(
      this.resourceId,
      declaration.id,
      recordId,
      operation,
    );
  }

  create(recordKind, value) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const declaration = requireRecordDeclaration(entry, this.resourceId, recordKind);
    if (!declaration.mutationOperations.includes("create")) {
      throw new PrivacyPackConnectionError("unknown_browser_record_operation");
    }
    return entry.transport.records.mutate(
      this.resourceId,
      declaration.id,
      "create",
      value,
    );
  }

  mutate(recordKind, recordId, operation, value) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const declaration = requireRecordDeclaration(entry, this.resourceId, recordKind);
    if (operation === "create" || !declaration.mutationOperations.includes(operation)) {
      throw new PrivacyPackConnectionError("unknown_browser_record_operation");
    }
    return entry.transport.records.mutate(
      this.resourceId,
      declaration.id,
      operation,
      value,
      recordId,
    );
  }

  async delete(recordKind, recordId) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const declaration = requireRecordDeclaration(entry, this.resourceId, recordKind);
    if (!await showPrivateRecordMutationDialog("delete")) return null;
    return entry.transport.records.delete(
      this.resourceId,
      declaration.id,
      recordId,
      true,
    );
  }

  async replace(recordKind, recordId, protectedValue) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    const declaration = requireRecordDeclaration(entry, this.resourceId, recordKind);
    if (!await showPrivateRecordMutationDialog("replace")) return null;
    return entry.transport.records.replace(
      this.resourceId,
      declaration.id,
      recordId,
      protectedValue,
      true,
    );
  }

  migrateLegacyReference(recordKind, migrationId, reference) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    requireRecordReferenceMigration(entry, this.resourceId, recordKind, migrationId);
    return entry.transport.records.migrateLegacyReference(
      this.resourceId,
      recordKind,
      migrationId,
      reference,
    );
  }

  resolveLegacyReference(recordKind, migrationId, reference) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    requireRecordReferenceMigration(entry, this.resourceId, recordKind, migrationId);
    return entry.transport.records.resolveLegacyReference(
      this.resourceId,
      recordKind,
      migrationId,
      reference,
    );
  }
}
export class BrowserArtifactHandle extends BrowserResourceHandle {
  lease(artifactKind, reference, operation) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    requireArtifactDeclaration(entry, this.resourceId, artifactKind);
    return entry.transport.artifacts.lease(
      this.resourceId,
      artifactKind,
      reference,
      operation,
    );
  }
}
export class BrowserExecutionHandle extends BrowserInvokableResourceHandle {
  prepare(owner, projectionId = null) {
    const entry = HANDLE_ENTRIES.get(this);
    entry.pack.authorization.requireReady();
    entry.snapshotCoordinator.requireActiveExecutionTransaction();
    const candidates = entry.executionProjections.filter(
      (projection) => projection.executionResourceId === this.resourceId,
    );
    const projection = projectionId === null
      ? (candidates.length === 1 ? candidates[0] : null)
      : candidates.find((item) => item.id === projectionId);
    if (!projection) {
      throw new PrivacyPackConnectionError("unknown_execution_projection");
    }
    const fields = entry.protectedFields.filter((field) => (
      field.execution
      && field.workflowResourceId === projection.workflowResourceId
    ));
    if (!fields.length) {
      throw new PrivacyPackConnectionError("execution_fields_unavailable");
    }
    const prepared = entry.transport.execution.prepare(
      this.resourceId,
      projection.id,
      owner?.id,
      fields.map((field) => ({
        fieldId: field.id,
        protectedValue: entry.snapshotCoordinator.executionProjection(
          owner,
          field.id,
        ),
      })),
    );
    return Promise.resolve(prepared).then((result) => {
      entry.snapshotCoordinator.requireActiveExecutionTransaction();
      return result;
    });
  }
}

class BrowserPrivacyPack {
  constructor(entry) {
    PACK_ENTRIES.set(this, entry);
    this.packId = entry.id;
    this.contract = entry.contract;
    this.fingerprint = entry.fingerprint;
    this.suiteManifestDigest = entry.suiteManifestDigest;
    this.readiness = new BrowserReadinessHandle(entry);
    this.authorization = new BrowserAuthorizationHandle(entry);
    this.session = new BrowserSessionHandle(entry);
    Object.freeze(this);
  }

  mode(resourceId) {
    return browserResource(this, resourceId, RESOURCE_KIND.MODE, BrowserModeHandle);
  }

  workflow(resourceId) {
    return browserResource(this, resourceId, RESOURCE_KIND.WORKFLOW, BrowserWorkflowHandle);
  }

  records(resourceId) {
    return browserResource(this, resourceId, RESOURCE_KIND.RECORD, BrowserRecordHandle);
  }

  artifacts(resourceId) {
    return browserResource(this, resourceId, RESOURCE_KIND.ARTIFACT, BrowserArtifactHandle);
  }

  execution(resourceId) {
    return browserResource(this, resourceId, RESOURCE_KIND.EXECUTION, BrowserExecutionHandle);
  }

  operations(resourceId) {
    return browserResource(this, resourceId, RESOURCE_KIND.OPERATION, BrowserOperationHandle);
  }
}

/** Attest and bind a complete browser profile as one immutable pack. */
export async function connectPrivacyPack(options = {}) {
  let connectionGate;
  try {
    connectionGate = installPrivacyConnectionSerializationGate(options?.app);
  } catch {
    return Promise.reject(
      new PrivacyPackConnectionError("browser_serialization_gate_failed"),
    );
  }
  const identity = connectionIdentity(options);
  markAppEntriesConnecting(identity.app);
  const connections = connectingPrivacyPacks(identity.app);
  const pending = connections.get(identity.id);
  if (pending) {
    if (sameConnectionIdentity(pending.identity, identity)) {
      connectionGate.coalesce();
      return pending.promise;
    }
    markAppEntriesConflict(identity.app);
    pending.connectionGate.markUnavailable();
    connectionGate.markUnavailable();
    return Promise.reject(new PrivacyPackConnectionError("browser_profile_conflict"));
  }
  const pendingEntry = { identity, connectionGate, entry: null, promise: null };
  const promise = connectPrivacyPackAfterGate(
    options,
    connectionGate,
    pendingEntry,
  ).then((pack) => {
    markAppEntriesReady(identity.app);
    return pack;
  }).catch((error) => {
    markAppEntriesConflict(identity.app);
    connectionGate.markUnavailable();
    throw error;
  }).finally(() => {
    if (connections.get(identity.id)?.promise === promise) {
      connections.delete(identity.id);
    }
  });
  pendingEntry.promise = promise;
  connections.set(identity.id, pendingEntry);
  return promise;
}

async function connectPrivacyPackAfterGate({
  app,
  packId,
  contract = PRIVACY_CONTRACT_V3,
  profileFingerprint,
  suiteManifestDigest,
  adapters = {},
  adapterFactories = {},
}, connectionGate, pendingConnection) {
  const id = String(packId || "").trim();
  const fingerprint = String(profileFingerprint || "").trim();
  const suiteDigest = String(suiteManifestDigest || "").trim();
  if (
    !app
    || !id
    || !/^[0-9a-f]{64}$/.test(fingerprint)
    || !/^[0-9a-f]{64}$/.test(suiteDigest)
    || contract !== PRIVACY_CONTRACT_V3
    || !adapters
    || typeof adapters !== "object"
    || Array.isArray(adapters)
    || !adapterFactories
    || typeof adapterFactories !== "object"
    || Array.isArray(adapterFactories)
  ) {
    throw new PrivacyPackConnectionError("invalid_browser_declaration");
  }

  const existing = CONNECTED_PRIVACY_PACKS.get(id);
  if (existing) {
    if (existing.status === STATUS.CONFLICT) {
      throw new PrivacyPackConnectionError("browser_pack_blocked");
    }
    if (
      existing.fingerprint !== fingerprint
      || existing.contract !== contract
      || existing.suiteManifestDigest !== suiteDigest
      || existing.app !== app
    ) {
      existing.status = STATUS.CONFLICT;
      throw new PrivacyPackConnectionError("browser_profile_conflict");
    }
    await resolveBrowserAdapterBindings(existing, adapters, adapterFactories);
    await existing.serializationBarrier.takeOwnership(connectionGate);
    existing.status = STATUS.READY;
    return existing.pack;
  }

  let transport;
  try {
    transport = await connectAttestedPrivacyProfileClient({
      packId: id,
      profileFingerprint: fingerprint,
      suiteManifestDigest: suiteDigest,
      promptUnlock: ({ error }) => showPrivacyKeystoreDialog(
        isPrivacySetupRequiredError(error) ? "setup" : "unlock",
      ),
    });
  } catch (error) {
    if (error?.code === "PRIVACY_BROWSER_ATTESTATION_DRIFT") {
      throw new PrivacyPackConnectionError("browser_server_attestation_drift");
    }
    throw new PrivacyPackConnectionError("server_attestation_unavailable");
  }
  const { attestation } = transport;
  validateServerAttestation({
    id,
    contract,
    fingerprint,
    suiteDigest,
    attestation,
  });
  if (PRIVACY_EXTENSION_APP && PRIVACY_EXTENSION_APP !== app) {
    throw new PrivacyPackConnectionError("comfyui_app_conflict");
  }

  const entry = {
    app,
    id,
    contract,
    fingerprint,
    suiteManifestDigest: suiteDigest,
    serverBootEpoch: String(attestation.serverBootEpoch),
    suiteStatus: attestation.suiteStatus,
    adapters: Object.freeze({}),
    requirements: attestation.requiredBrowserAdapters.map((item) => Object.freeze({
      id: String(item.id),
      nodeTypes: Object.freeze([...item.nodeTypes]),
      methods: Object.freeze([...item.methods]),
    })),
    resources: attestation.resources.map((item) => Object.freeze({
      id: String(item.id),
      kind: String(item.kind),
    })),
    modeScopes: attestation.modeScopes.map((item) => Object.freeze({
      id: String(item.id),
      modeResourceId: String(item.modeResourceId),
      modeEditorAdapter: item.modeEditorAdapter == null
        ? null
        : String(item.modeEditorAdapter),
    })),
    protectedFields: attestation.protectedFields.map((item) => Object.freeze({
      id: String(item.id),
      workflowResourceId: String(item.workflowResourceId),
      scopeId: String(item.scopeId),
      browserAdapter: String(item.browserAdapter),
      nodeTypes: Object.freeze([...item.nodeTypes]),
      legacyReaderIds: Object.freeze([...item.legacyReaderIds]),
      execution: item.execution === true,
      stateAuthority: String(item.stateAuthority),
      externalTransitionPolicy: item.externalTransitionPolicy === null
        ? null
        : Object.freeze({ ...item.externalTransitionPolicy }),
    })),
    executionProjections: attestation.executionProjections.map((item) => Object.freeze({
      id: String(item.id),
      executionResourceId: String(item.executionResourceId),
      workflowResourceId: String(item.workflowResourceId),
      subjectModeBindingId: String(item.subjectModeBindingId),
      inputName: String(item.inputName),
    })),
    subjectModeBindings: attestation.subjectModeBindings.map((item) => Object.freeze({
      id: String(item.id),
      scopeId: String(item.scopeId),
      inputName: String(item.inputName),
      nodeTypes: Object.freeze([...item.nodeTypes]),
    })),
    recordDeclarations: attestation.records.map((item) => Object.freeze({
      id: String(item.id),
      resourceId: String(item.resourceId),
      scopeId: String(item.scopeId),
      revealOperations: Object.freeze([...item.revealOperations]),
      mutationOperations: Object.freeze([...item.mutationOperations]),
      safeProjection: Object.freeze([...item.safeProjection]),
      fixedPrivateLabel: String(item.fixedPrivateLabel),
    })),
    singletonDeclarations: attestation.singletons.map((item) => Object.freeze({
      id: String(item.id),
      resourceId: String(item.resourceId),
      scopeId: String(item.scopeId),
      currentSchema: String(item.currentSchema),
      purpose: String(item.purpose),
      storeAdapter: String(item.storeAdapter),
      payloadKind: String(item.payloadKind),
      legacyReaderIds: Object.freeze([...item.legacyReaderIds]),
    })),
    recordReferenceMigrations: (attestation.recordReferenceMigrations ?? []).map(
      (item) => Object.freeze({
        id: String(item.id),
        resourceId: String(item.resourceId),
        recordKind: String(item.recordKind),
        legacyBindingId: String(item.legacyBindingId),
      }),
    ),
    artifactDeclarations: attestation.artifacts.map((item) => Object.freeze({
      id: String(item.id),
      resourceId: String(item.resourceId),
      scopeId: String(item.scopeId),
      retention: String(item.retention),
      operations: Object.freeze([...item.operations]),
      mediaType: String(item.mediaType),
      payloadMode: String(item.payloadMode),
      streamContract: item.streamContract === null
        ? null
        : Object.freeze({ ...item.streamContract }),
    })),
    safePayloadProjections: (attestation.safePayloadProjections ?? []).map(
      (item) => Object.freeze({
        id: String(item.id),
        operationId: String(item.operationId),
        schema: String(item.schema),
        purpose: String(item.purpose),
        safeLeaves: Object.freeze(item.safeLeaves.map((leaf) => Object.freeze({
          path: String(leaf.path),
          kind: String(leaf.kind),
        }))),
      }),
    ),
    protectedOperations: attestation.protectedOperations.map((item) => Object.freeze({
      id: String(item.id),
      resourceId: String(item.resourceId),
      route: item.route == null ? null : String(item.route),
      method: String(item.method),
      scopeId: item.scopeId == null ? null : String(item.scopeId),
      sensitiveFields: Object.freeze(item.sensitiveFields.map((field) => Object.freeze({
        path: String(field.path),
        class: String(field.class),
      }))),
      safeProjection: Object.freeze(item.safeProjection.map((field) => Object.freeze({
        path: String(field.path),
        kind: String(field.kind),
      }))),
      referenceInputs: Object.freeze((item.referenceInputs ?? []).map((input) => Object.freeze({
        name: String(input.name),
        referenceKindId: String(input.referenceKindId),
        revokeOnSuccess: input.revokeOnSuccess === true,
      }))),
      referenceOutputs: Object.freeze((item.referenceOutputs ?? []).map((output) => Object.freeze({
        referenceKindId: String(typeof output === "string" ? output : output.referenceKindId),
        minimum: Number(typeof output === "string" ? 1 : output.minimum),
        maximum: Number(typeof output === "string" ? 1 : output.maximum),
      }))),
      legacyOperationWire: (item.referenceOutputs ?? []).some(
        (output) => typeof output === "string",
      ),
      returnsLease: item.returnsLease === true,
      safePayloadProjectionId: item.safePayloadProjectionId == null
        ? null : String(item.safePayloadProjectionId),
      safePayloadLeaves: Object.freeze([
        ...((attestation.safePayloadProjections ?? []).find(
          (projection) => projection.id === item.safePayloadProjectionId,
        )?.safeLeaves ?? []),
      ]),
      deferredUi: item.deferredUi === true,
      recordDependencies: Object.freeze((item.recordDependencies ?? []).map(
        (dependency) => Object.freeze({
          resourceId: String(dependency.resourceId),
          recordKind: String(dependency.recordKind),
          operation: String(dependency.operation),
        }),
      )),
      singletonDependencies: Object.freeze((item.singletonDependencies ?? []).map(
        (dependency) => Object.freeze({
          singletonId: String(dependency.singletonId),
          verbs: Object.freeze([...dependency.verbs]),
        }),
      )),
      artifactDependencies: Object.freeze((item.artifactDependencies ?? []).map(
        (dependency) => Object.freeze({
          artifactKind: String(dependency.artifactKind),
          verbs: Object.freeze([...dependency.verbs]),
        }),
      )),
      externalOperationBinding: item.externalOperationBinding == null
        ? null
        : Object.freeze({
          fieldId: String(item.externalOperationBinding.fieldId),
          browserAdapter: String(item.externalOperationBinding.browserAdapter),
          policy: Object.freeze({ ...item.externalOperationBinding.policy }),
        }),
      typed: Array.isArray(item.referenceInputs)
        || Array.isArray(item.referenceOutputs)
        || item.returnsLease === true
        || item.externalOperationBinding != null,
    })),
    handles: new Map(),
    modeEpochs: new Map(),
    transport,
    snapshotCoordinator: null,
    serializationBarrier: null,
    sessionState: Object.freeze({ state: "unknown", revision: 0 }),
    sessionUnsubscribe: null,
    surface: null,
    status: STATUS.CONNECTING,
    pack: null,
  };
  pendingConnection.entry = entry;
  entry.pack = new BrowserPrivacyPack(entry);
  try {
    entry.adapters = await resolveBrowserAdapterBindings(
      entry,
      adapters,
      adapterFactories,
    );
  } catch {
    entry.status = STATUS.CONFLICT;
    throw new PrivacyPackConnectionError("browser_adapter_mismatch");
  }
  entry.snapshotCoordinator = createPrivacySnapshotCoordinator({
    packId: entry.id,
    fields: entry.protectedFields,
    executionProjections: entry.executionProjections,
    adapters: entry.adapters,
    transport: entry.transport.snapshot,
    prepareExecution: (projection, owner, fields) => entry.transport.execution.prepare(
      projection.executionResourceId,
      projection.id,
      owner?.id,
      fields.map((field) => ({
        fieldId: field.field.id,
        protectedValue: entry.snapshotCoordinator.executionProjection(
          field.owner,
          field.field.id,
        ),
      })),
    ),
    subjectModeBindings: entry.subjectModeBindings,
    prepareSubjectMode: (binding, owner) => {
      const scope = entry.modeScopes.find((item) => item.id === binding.scopeId);
      const adapter = scope?.modeEditorAdapter
        ? entry.adapters[scope.modeEditorAdapter]
        : null;
      return entry.transport.subjectMode.prepare(
        binding.id,
        owner?.id,
        adapter?.readDeclaredMode?.(owner),
        adapter?.readModeFacts?.(owner),
      );
    },
    revokeSubmissionReferences: (references) => (
      entry.transport.submissionGrants.revoke(references)
    ),
    refreshModeFence: () => refreshEntryModeFences(entry),
    requireModeFence: () => requireEntryModeFence(entry),
    resolvePrivate: async (field, owner) => {
      const scope = entry.modeScopes.find((item) => item.id === field.scopeId);
      if (!scope) return true;
      const modeAdapter = scope.modeEditorAdapter
        ? entry.adapters[scope.modeEditorAdapter]
        : null;
      const declaration = modeAdapter?.readDeclaredMode?.(owner);
      const facts = modeAdapter?.readModeFacts?.(owner);
      const resolution = await entry.transport.mode.resolve(
        scope.modeResourceId,
        scope.id,
        declaration,
        facts,
      );
      return resolution.effective !== "public";
    },
    blocked: entry.suiteStatus !== STATUS.SUITE_ACTIVE,
  });
  entry.sessionUnsubscribe = subscribePrivacySession((session) => {
    entry.sessionState = session;
    entry.snapshotCoordinator.onSessionChange(session).catch(() => {
      entry.status = STATUS.CONFLICT;
    });
    for (const adapter of Object.values(entry.adapters)) {
      try {
        adapter.onPrivacySessionChange(session);
      } catch {
        entry.status = STATUS.CONFLICT;
      }
    }
  }, { emitCurrent: true });
  if (entry.status === STATUS.CONFLICT) {
    entry.sessionUnsubscribe();
    throw new PrivacyPackConnectionError("browser_session_binding_failed");
  }

  CONNECTED_PRIVACY_PACKS.set(id, entry);
  try {
    registerPrivacyLifecycleExtension(app);
    entry.serializationBarrier = installGraphSerializationBarrier(
      app,
      () => [...CONNECTED_PRIVACY_PACKS.values()].map(
        (connected) => connected.snapshotCoordinator,
      ),
      { onConflict: () => markAppEntriesConflict(app) },
    );
    await reconcileExistingNodeDefinitions(app, entry);
    await reconcileExistingPrivacyNodes(app, entry);
    await entry.serializationBarrier.takeOwnership(connectionGate);
    entry.status = STATUS.READY;
  } catch {
    entry.sessionUnsubscribe?.();
    entry.status = STATUS.CONFLICT;
    throw new PrivacyPackConnectionError("browser_lifecycle_registration_failed");
  }
  entry.surface = mountSharedPrivacySurface({
    packId: entry.id,
    readiness: entry.status,
    modeScopes: entry.modeScopes,
    modeClient: entry.transport.mode,
  });
  entry.surface?.refresh().catch(() => {});
  return entry.pack;
}

function connectionIdentity(options) {
  return Object.freeze({
    app: options?.app,
    id: String(options?.packId || "").trim(),
    contract: options?.contract ?? PRIVACY_CONTRACT_V3,
    fingerprint: String(options?.profileFingerprint || "").trim(),
    suiteDigest: String(options?.suiteManifestDigest || "").trim(),
    adapterBindings: adapterBindingIdentity(options),
  });
}

function connectingPrivacyPacks(app) {
  let connections = CONNECTING_PRIVACY_PACKS.get(app);
  if (!connections) {
    connections = new Map();
    CONNECTING_PRIVACY_PACKS.set(app, connections);
  }
  return connections;
}

function sameConnectionIdentity(left, right) {
  return left.app === right.app
    && left.id === right.id
    && left.contract === right.contract
    && left.fingerprint === right.fingerprint
    && left.suiteDigest === right.suiteDigest
    && left.adapterBindings.length === right.adapterBindings.length
    && left.adapterBindings.every((binding, index) => (
      binding.id === right.adapterBindings[index].id
      && binding.kind === right.adapterBindings[index].kind
      && binding.value === right.adapterBindings[index].value
    ));
}

function adapterBindingIdentity(options) {
  const declarations = [];
  const add = (values, kind) => {
    if (!values || typeof values !== "object" || Array.isArray(values)) return;
    for (const [id, value] of Object.entries(values)) {
      declarations.push(Object.freeze({ id, kind, value }));
    }
  };
  add(options?.adapters, "adapter");
  add(options?.adapterFactories, "factory");
  return Object.freeze(declarations.sort(
    (left, right) => `${left.id}:${left.kind}`.localeCompare(`${right.id}:${right.kind}`),
  ));
}

function markAppEntriesConnecting(app) {
  for (const entry of CONNECTED_PRIVACY_PACKS.values()) {
    if (entry.app === app && entry.status !== STATUS.CONFLICT) {
      entry.status = STATUS.CONNECTING;
    }
  }
}

function markAppEntriesConflict(app) {
  for (const entry of CONNECTED_PRIVACY_PACKS.values()) {
    if (entry.app === app) entry.status = STATUS.CONFLICT;
  }
}

function markAppEntriesReady(app) {
  for (const entry of CONNECTED_PRIVACY_PACKS.values()) {
    if (entry.app === app && entry.status !== STATUS.CONFLICT) {
      entry.status = STATUS.READY;
    }
  }
}

function validArtifactStreamAttestation(artifact) {
  if (
    !artifact
    || typeof artifact !== "object"
    || Array.isArray(artifact)
    || Object.keys(artifact).sort().join("\0") !== [
      "id", "mediaType", "operations", "payloadMode", "resourceId", "retention",
      "scopeId", "streamContract",
    ].join("\0")
  ) return false;
  if (!["bounded-bytes-v1", "stream-v1"].includes(artifact?.payloadMode)) return false;
  if (artifact.payloadMode === "bounded-bytes-v1") return artifact.streamContract === null;
  if (artifact.retention === "durable-adjunct") return false;
  const stream = artifact.streamContract;
  const safeInteger = (value) => Number.isSafeInteger(value) && value > 0;
  return !!stream
    && typeof stream === "object"
    && !Array.isArray(stream)
    && Object.keys(stream).sort().join("\0") === [
      "codecSchema", "codecVersion", "decodedOutput", "maxMaterializedOutputBytes",
      "maxOwnerPlaintextBytes", "maxPlaintextBytes",
    ].join("\0")
    && /^[a-z0-9][a-z0-9._-]*$/.test(String(stream.codecSchema || ""))
    && safeInteger(stream.codecVersion)
    && safeInteger(stream.maxPlaintextBytes)
    && ["materialized", "stream"].includes(stream.decodedOutput)
    && (stream.maxOwnerPlaintextBytes === null
      || (safeInteger(stream.maxOwnerPlaintextBytes)
        && stream.maxOwnerPlaintextBytes >= stream.maxPlaintextBytes))
    && (stream.decodedOutput === "materialized"
      ? safeInteger(stream.maxMaterializedOutputBytes)
      : stream.maxMaterializedOutputBytes === null);
}

function validateServerAttestation({
  id,
  contract,
  fingerprint,
  suiteDigest,
  attestation,
}) {
  if (
    !attestation
    || attestation.id !== id
    || attestation.contract !== contract
    || attestation.modeTransitionProtocol !== MODE_TRANSITION_PROTOCOL
    || !/^hp-boot-[A-Za-z0-9_-]{16,64}$/.test(attestation.serverBootEpoch)
    || attestation.fingerprint !== fingerprint
    || attestation.suiteManifestDigest !== suiteDigest
  ) {
    throw new PrivacyPackConnectionError("browser_server_attestation_drift");
  }
  if (attestation.status !== STATUS.READY) {
    throw new PrivacyPackConnectionError("server_profile_not_ready");
  }
  if (!VERIFICATION_SUITE_STATUSES.has(attestation.suiteStatus)) {
    throw new PrivacyPackConnectionError("server_suite_blocked");
  }
  if (!Array.isArray(attestation.resources)) {
    throw new PrivacyPackConnectionError("invalid_server_resource_declaration");
  }
  validateBrowserAdapterRequirements(attestation.requiredBrowserAdapters);
  const resourceIds = new Set();
  for (const resource of attestation.resources) {
    if (
      !resource?.id
      || !Object.values(RESOURCE_KIND).includes(resource.kind)
      || resourceIds.has(resource.id)
    ) {
      throw new PrivacyPackConnectionError("invalid_server_resource_declaration");
    }
    resourceIds.add(resource.id);
  }
  if (!Array.isArray(attestation.modeScopes)) {
    throw new PrivacyPackConnectionError("invalid_server_mode_scope_declaration");
  }
  const modeScopeIds = new Set();
  for (const scope of attestation.modeScopes) {
    if (
      !scope?.id
      || !scope?.modeResourceId
      || (
        scope.modeEditorAdapter != null
        && !attestation.requiredBrowserAdapters.some(
          (adapter) => adapter.id === scope.modeEditorAdapter,
        )
      )
      || modeScopeIds.has(scope.id)
      || !attestation.resources.some(
        (resource) => resource.id === scope.modeResourceId && resource.kind === RESOURCE_KIND.MODE,
      )
    ) {
      throw new PrivacyPackConnectionError("invalid_server_mode_scope_declaration");
    }
    modeScopeIds.add(scope.id);
  }
  if (!Array.isArray(attestation.protectedFields)) {
    throw new PrivacyPackConnectionError("invalid_server_field_declaration");
  }
  const fieldIds = new Set();
  for (const field of attestation.protectedFields) {
    if (
      !field?.id
      || !field?.workflowResourceId
      || !field?.scopeId
      || !field?.browserAdapter
      || !Array.isArray(field.nodeTypes)
      || !field.nodeTypes.length
      || !Array.isArray(field.legacyReaderIds)
      || field.legacyReaderIds.some(
        (readerId, index) => (
          typeof readerId !== "string"
          || !readerId
          || field.legacyReaderIds.indexOf(readerId) !== index
        ),
      )
      || typeof field.execution !== "boolean"
      || fieldIds.has(field.id)
      || !attestation.resources.some(
        (resource) => resource.id === field.workflowResourceId
          && resource.kind === RESOURCE_KIND.WORKFLOW,
      )
      || !attestation.requiredBrowserAdapters.some(
        (adapter) => (
          adapter.id === field.browserAdapter
          && (!field.legacyReaderIds.length
            || adapter.methods.includes("writeWorkflowProjection"))
        ),
      )
      || !attestation.modeScopes.some((scope) => scope.id === field.scopeId)
    ) {
      throw new PrivacyPackConnectionError("invalid_server_field_declaration");
    }
    fieldIds.add(field.id);
  }
  if (!Array.isArray(attestation.executionProjections)) {
    throw new PrivacyPackConnectionError("invalid_execution_projection_declaration");
  }
  if (!Array.isArray(attestation.subjectModeBindings)) {
    throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
  }
  const subjectBindingIds = new Set();
  const injectedInputBindings = new Set();
  for (const binding of attestation.subjectModeBindings) {
    const scope = attestation.modeScopes.find((item) => item.id === binding?.scopeId);
    const modeAdapter = attestation.requiredBrowserAdapters.find(
      (item) => item.id === scope?.modeEditorAdapter,
    );
    if (
      !binding?.id
      || !binding?.scopeId
      || !binding?.inputName
      || !Array.isArray(binding.nodeTypes)
      || !binding.nodeTypes.length
      || subjectBindingIds.has(binding.id)
      || !attestation.modeScopes.some(
        (item) => item.id === binding.scopeId && item.modeEditorAdapter,
      )
      || binding.nodeTypes.some((nodeType) => !modeAdapter?.nodeTypes.includes(nodeType))
    ) {
      throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
    }
    for (const nodeType of binding.nodeTypes) {
      const key = `${nodeType}:${binding.inputName}`;
      if (injectedInputBindings.has(key)) {
        throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
      }
      injectedInputBindings.add(key);
    }
    subjectBindingIds.add(binding.id);
  }
  for (const projection of attestation.executionProjections) {
    const binding = attestation.subjectModeBindings.find(
      (item) => item.id === projection.subjectModeBindingId,
    );
    const executionFields = attestation.protectedFields.filter((field) => (
      field.execution === true
      && field.workflowResourceId === projection.workflowResourceId
    ));
    const nodeTypes = new Set(executionFields.flatMap((field) => field.nodeTypes));
    const scopes = new Set(executionFields.map((field) => field.scopeId));
    if (
      !binding
      || !executionFields.length
      || scopes.size !== 1
      || !scopes.has(binding.scopeId)
      || nodeTypes.size !== binding.nodeTypes.length
      || binding.nodeTypes.some((nodeType) => !nodeTypes.has(nodeType))
    ) {
      throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
    }
    for (const nodeType of binding.nodeTypes) {
      const key = `${nodeType}:${projection.inputName}`;
      if (injectedInputBindings.has(key)) {
        throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
      }
      injectedInputBindings.add(key);
    }
  }
  const executionProjectionIds = new Set();
  for (const projection of attestation.executionProjections) {
    if (
      !projection?.id
      || !projection?.executionResourceId
      || !projection?.workflowResourceId
      || !projection?.subjectModeBindingId
      || !projection?.inputName
      || executionProjectionIds.has(projection.id)
      || !attestation.resources.some(
        (resource) => resource.id === projection.executionResourceId
          && resource.kind === RESOURCE_KIND.EXECUTION,
      )
      || !subjectBindingIds.has(projection.subjectModeBindingId)
      || !attestation.resources.some(
        (resource) => resource.id === projection.workflowResourceId
          && resource.kind === RESOURCE_KIND.WORKFLOW,
      )
    ) {
      throw new PrivacyPackConnectionError("invalid_execution_projection_declaration");
    }
    executionProjectionIds.add(projection.id);
  }
  if (!Array.isArray(attestation.protectedOperations)) {
    throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
  }
  const opaqueReferenceKinds = attestation.opaqueReferenceKinds ?? [];
  if (!Array.isArray(opaqueReferenceKinds)) {
    throw new PrivacyPackConnectionError("invalid_opaque_reference_kind");
  }
  const opaqueReferenceKindIds = new Set();
  for (const kind of opaqueReferenceKinds) {
    if (
      !kind?.id
      || !kind?.resourceId
      || !kind?.scopeId
      || opaqueReferenceKindIds.has(kind.id)
      || !attestation.resources.some(
        (resource) => resource.id === kind.resourceId
          && resource.kind === RESOURCE_KIND.OPERATION,
      )
      || !attestation.modeScopes.some((scope) => scope.id === kind.scopeId)
    ) {
      throw new PrivacyPackConnectionError("invalid_opaque_reference_kind");
    }
    opaqueReferenceKindIds.add(kind.id);
  }
  const safePayloadProjections = attestation.safePayloadProjections ?? [];
  if (!Array.isArray(safePayloadProjections)) {
    throw new PrivacyPackConnectionError("invalid_safe_payload_projection");
  }
  const safePayloadProjectionIds = new Set();
  for (const projection of safePayloadProjections) {
    if (
      !projection?.id
      || !projection?.operationId
      || !projection?.schema
      || !projection?.purpose
      || !Array.isArray(projection.safeLeaves)
      || !projection.safeLeaves.length
      || projection.safeLeaves.some((leaf) => (
        !leaf
        || typeof leaf !== "object"
        || Array.isArray(leaf)
        || Object.keys(leaf).sort().join("\0") !== "kind\0path"
        || String(leaf.path).includes("*")
        || !isProjectionPath(leaf.path)
        || !["boolean", "count", "number", "safe-text"].includes(leaf.kind)
      ))
      || new Set(projection.safeLeaves.map((leaf) => leaf.path)).size
        !== projection.safeLeaves.length
      || safePayloadProjectionIds.has(projection.id)
    ) {
      throw new PrivacyPackConnectionError("invalid_safe_payload_projection");
    }
    safePayloadProjectionIds.add(projection.id);
  }
  const usedSubjectBindings = new Set(
    attestation.executionProjections.map((item) => item.subjectModeBindingId),
  );
  for (const operation of attestation.protectedOperations) {
    if (operation?.subjectModeBindingId == null) continue;
    const binding = attestation.subjectModeBindings.find(
      (item) => item.id === operation.subjectModeBindingId,
    );
    if (!binding || operation.scopeId !== binding.scopeId) {
      throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
    }
    usedSubjectBindings.add(binding.id);
  }
  if (attestation.subjectModeBindings.some(
    (binding) => !usedSubjectBindings.has(binding.id),
  )) {
    throw new PrivacyPackConnectionError("invalid_subject_mode_binding");
  }
  if (!Array.isArray(attestation.records)) {
    throw new PrivacyPackConnectionError("invalid_record_declaration");
  }
  const recordIds = new Set();
  for (const record of attestation.records) {
    if (
      !record?.id
      || !record?.resourceId
      || !record?.scopeId
      || !Array.isArray(record.revealOperations)
      || record.revealOperations.some(
        (operation) => !["use", "preview", "details"].includes(operation),
      )
      || record.revealOperations.length !== new Set(record.revealOperations).size
      || !Array.isArray(record.mutationOperations)
      || record.mutationOperations.some(
        (operation) => !["create", "replace", "patch", "duplicate"].includes(operation),
      )
      || record.mutationOperations.length !== new Set(record.mutationOperations).size
      || !Array.isArray(record.safeProjection)
      || record.safeProjection.length !== 0
      || record.fixedPrivateLabel !== "Private record"
      || recordIds.has(record.id)
      || !attestation.resources.some(
        (resource) => resource.id === record.resourceId
          && resource.kind === RESOURCE_KIND.RECORD,
      )
      || !attestation.modeScopes.some((scope) => scope.id === record.scopeId)
    ) {
      throw new PrivacyPackConnectionError("invalid_record_declaration");
    }
    recordIds.add(record.id);
  }
  if (!Array.isArray(attestation.singletons)) {
    throw new PrivacyPackConnectionError("invalid_singleton_declaration");
  }
  const singletonIds = new Set();
  const exactSingletonKeys = [
    "currentSchema",
    "id",
    "legacyReaderIds",
    "payloadKind",
    "purpose",
    "resourceId",
    "scopeId",
    "storeAdapter",
  ].join("\0");
  for (const singleton of attestation.singletons) {
    const readers = singleton?.legacyReaderIds;
    if (
      !singleton
      || typeof singleton !== "object"
      || Array.isArray(singleton)
      || Object.keys(singleton).sort().join("\0") !== exactSingletonKeys
      || !isStableDeclarationId(singleton.id)
      || !isStableDeclarationId(singleton.resourceId)
      || !isStableDeclarationId(singleton.scopeId)
      || !isStableDeclarationId(singleton.currentSchema)
      || !isStableDeclarationId(singleton.purpose)
      || !isStableDeclarationId(singleton.storeAdapter)
      || !["field", "blob"].includes(singleton.payloadKind)
      || !Array.isArray(readers)
      || readers.some((readerId) => !isStableDeclarationId(readerId))
      || readers.length !== new Set(readers).size
      || [...readers].sort().join("\0") !== readers.join("\0")
      || singletonIds.has(singleton.id)
      || !attestation.resources.some(
        (resource) => resource.id === singleton.resourceId
          && resource.kind === RESOURCE_KIND.SINGLETON,
      )
      || !attestation.modeScopes.some((scope) => scope.id === singleton.scopeId)
    ) {
      throw new PrivacyPackConnectionError("invalid_singleton_declaration");
    }
    singletonIds.add(singleton.id);
  }
  if (!Array.isArray(attestation.recordReferenceMigrations ?? [])) {
    throw new PrivacyPackConnectionError("invalid_record_reference_migration");
  }
  const recordReferenceMigrationIds = new Set();
  for (const migration of (attestation.recordReferenceMigrations ?? [])) {
    if (
      !migration?.id
      || !migration?.resourceId
      || !migration?.recordKind
      || !migration?.legacyBindingId
      || recordReferenceMigrationIds.has(migration.id)
      || !attestation.records.some(
        (record) => record.id === migration.recordKind
          && record.resourceId === migration.resourceId,
      )
      || !attestation.legacyBindings?.some(
        (binding) => binding.id === migration.legacyBindingId
          && binding.resourceId === migration.resourceId
          && binding.locationId === migration.recordKind
          && binding.locationKind === "record",
      )
    ) {
      throw new PrivacyPackConnectionError("invalid_record_reference_migration");
    }
    recordReferenceMigrationIds.add(migration.id);
  }
  if (!Array.isArray(attestation.artifacts)) {
    throw new PrivacyPackConnectionError("invalid_artifact_declaration");
  }
  const artifactIds = new Set();
  for (const artifact of attestation.artifacts) {
    const key = `${artifact?.resourceId}:${artifact?.id}`;
    if (
      !artifact?.id
      || !artifact?.resourceId
      || !artifact?.scopeId
      || ![
        "durable-adjunct",
        "regenerable-cache",
        "run-scoped-spill",
        "served-transient",
      ].includes(artifact.retention)
      || !Array.isArray(artifact.operations)
      || (!artifact.operations.length && artifact.retention !== "run-scoped-spill")
      || artifact.operations.some(
        (operation) => !/^[a-z0-9][a-z0-9._-]*$/.test(operation),
      )
      || artifact.operations.length !== new Set(artifact.operations).size
      || !/^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/i.test(
        String(artifact.mediaType || ""),
      )
      || artifactIds.has(key)
      || !attestation.resources.some(
        (resource) => resource.id === artifact.resourceId
          && resource.kind === RESOURCE_KIND.ARTIFACT,
      )
      || !attestation.modeScopes.some((scope) => scope.id === artifact.scopeId)
      || !validArtifactStreamAttestation(artifact)
    ) {
      throw new PrivacyPackConnectionError("invalid_artifact_declaration");
    }
    artifactIds.add(key);
  }
  const projectionIds = new Set();
  for (const projection of attestation.executionProjections) {
    if (
      !projection?.id
      || !projection?.executionResourceId
      || !projection?.workflowResourceId
      || projectionIds.has(projection.id)
      || !attestation.resources.some(
        (resource) => resource.id === projection.executionResourceId
          && resource.kind === RESOURCE_KIND.EXECUTION,
      )
      || !attestation.resources.some(
        (resource) => resource.id === projection.workflowResourceId
          && resource.kind === RESOURCE_KIND.WORKFLOW,
      )
      || !attestation.protectedFields.some(
        (field) => field.execution === true
          && field.workflowResourceId === projection.workflowResourceId,
      )
    ) {
      throw new PrivacyPackConnectionError("invalid_execution_projection_declaration");
    }
    projectionIds.add(projection.id);
  }
  if (!Array.isArray(attestation.protectedOperations)) {
    throw new PrivacyPackConnectionError("invalid_server_operation_declaration");
  }
  const operationIds = new Set();
  for (const operation of attestation.protectedOperations) {
    const operationResource = attestation.resources.find(
      (resource) => resource.id === operation?.resourceId,
    );
    const referenceInputs = operation?.referenceInputs ?? [];
    const referenceOutputs = operation?.referenceOutputs ?? [];
    const typed = Array.isArray(operation?.referenceInputs)
      || Array.isArray(operation?.referenceOutputs)
      || operation?.returnsLease === true;
    const recordDependencies = operation?.recordDependencies ?? [];
    const singletonDependencies = operation?.singletonDependencies ?? [];
    const artifactDependencies = operation?.artifactDependencies ?? [];
    const externalOperationBinding = operation?.externalOperationBinding ?? null;
    if (
      !operation?.id
      || !operation?.resourceId
      || (operation.route != null && !isSafeBrowserOperationRoute(operation.route))
      || !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(operation.method)
      || !Array.isArray(operation.sensitiveFields)
      || !Array.isArray(operation.safeProjection)
      || (operation.scopeId != null && !/^[a-z0-9][a-z0-9._-]*$/.test(operation.scopeId))
      || operation.sensitiveFields.some((field) => (
        (field?.path !== "*" && !isProjectionPath(field?.path))
        || !["user-authored", "path-or-name", "debug", "consumer-derived"]
          .includes(field?.class)
      ))
      || operation.safeProjection.some((field) => (
        !isProjectionPath(field?.path) || !["boolean", "count"].includes(field?.kind)
      ))
      || new Set(operation.sensitiveFields.map((field) => field?.path)).size
        !== operation.sensitiveFields.length
      || new Set(operation.safeProjection.map((field) => field?.path)).size
        !== operation.safeProjection.length
      || ((operation.sensitiveFields.length || operation.safeProjection.length)
        && operation.scopeId == null)
      || ((operation.sensitiveFields.length || operation.safeProjection.length)
        && !operation.sensitiveFields.some(
          (field) => field?.path === "*" && field?.class === "consumer-derived",
        ))
      || operationIds.has(operation.id)
      || !operationResource
      || [RESOURCE_KIND.RECORD, RESOURCE_KIND.ARTIFACT, RESOURCE_KIND.SINGLETON]
        .includes(operationResource.kind)
      || !Array.isArray(referenceInputs)
      || !Array.isArray(referenceOutputs)
      || referenceInputs.some((input) => (
        !input?.name
        || !opaqueReferenceKindIds.has(input?.referenceKindId)
        || typeof input?.revokeOnSuccess !== "boolean"
      ))
      || new Set(referenceInputs.map((input) => input?.name)).size
        !== referenceInputs.length
      || referenceOutputs.some((output) => (
        !opaqueReferenceKindIds.has(typeof output === "string" ? output : output?.referenceKindId)
        || (typeof output !== "string" && (
          !Number.isInteger(output?.minimum)
          || !Number.isInteger(output?.maximum)
          || output.minimum < 0
          || output.maximum < output.minimum
          || output.maximum > 256
        ))
      ))
      || new Set(referenceOutputs.map(
        (output) => (typeof output === "string" ? output : output?.referenceKindId),
      )).size
        !== referenceOutputs.length
      || (operation.safePayloadProjectionId != null
        && !safePayloadProjectionIds.has(operation.safePayloadProjectionId))
      || (operation.safePayloadProjectionId != null
        && safePayloadProjections.find(
          (projection) => projection.id === operation.safePayloadProjectionId,
        )?.operationId !== operation.id)
      || (operation.deferredUi === true && (
        operation.route !== null
        || operation.subjectModeBindingId == null
        || (operation.safePayloadProjectionId == null && !referenceOutputs.length)
      ))
      || (typed && operationResource.kind !== RESOURCE_KIND.OPERATION)
      || (operation.scopeId != null && !attestation.modeScopes.some(
        (scope) => scope?.id === operation.scopeId,
      ))
      || !validRecordOperationDependencies(
        recordDependencies,
        operation.scopeId,
        attestation.records,
      )
      || !validSingletonOperationDependencies(
        singletonDependencies,
        operation.scopeId,
        attestation.singletons,
      )
      || !validArtifactOperationDependencies(
        artifactDependencies,
        operation.scopeId,
        attestation.artifacts,
      )
      || !validExternalOperationBinding(
        externalOperationBinding,
        operation,
        attestation.protectedFields,
      )
    ) {
      throw new PrivacyPackConnectionError("invalid_server_operation_declaration");
    }
    for (const referenceKindId of [
      ...referenceInputs.map((input) => input.referenceKindId),
      ...referenceOutputs.map(
        (output) => (typeof output === "string" ? output : output.referenceKindId),
      ),
    ]) {
      const kind = opaqueReferenceKinds.find((item) => item.id === referenceKindId);
      if (
        kind.resourceId !== operation.resourceId
        || kind.scopeId !== operation.scopeId
      ) {
        throw new PrivacyPackConnectionError("invalid_server_operation_declaration");
      }
    }
    operationIds.add(operation.id);
  }

}

function validExternalOperationBinding(value, operation, fields) {
  if (value == null) return true;
  const policy = value?.policy;
  const field = fields.find((item) => item.id === value?.fieldId);
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).sort().join("\0") === "browserAdapter\0fieldId\0policy"
    && policy
    && typeof policy === "object"
    && !Array.isArray(policy)
    && Object.keys(policy).sort().join("\0") === [
      "leaseSeconds",
      "maxIdentityBytes",
      "maxOriginalBytes",
      "maxTargetBytes",
      "ownerIdentity",
    ].join("\0")
    && isStableDeclarationId(value.fieldId)
    && isStableDeclarationId(value.browserAdapter)
    && policy.ownerIdentity === "graph-node-v1"
    && Number.isInteger(policy.maxIdentityBytes)
    && policy.maxIdentityBytes >= 256
    && policy.maxIdentityBytes <= 64 * 1024
    && Number.isInteger(policy.maxOriginalBytes)
    && policy.maxOriginalBytes >= 1024
    && policy.maxOriginalBytes <= 16 * 1024 * 1024
    && Number.isInteger(policy.maxTargetBytes)
    && policy.maxTargetBytes >= 1024
    && policy.maxTargetBytes <= 16 * 1024 * 1024
    && Number.isInteger(policy.leaseSeconds)
    && policy.leaseSeconds >= 30
    && policy.leaseSeconds <= 900
    && operation.route === null
    && operation.method === "POST"
    && operation.scopeId != null
    && operation.subjectModeBindingId == null
    && operation.deferredUi !== true
    && operation.returnsLease !== true
    && Array.isArray(operation.referenceOutputs)
    && operation.referenceOutputs.length === 0
    && field
    && field.scopeId === operation.scopeId
    && field.browserAdapter === value.browserAdapter
    && field.stateAuthority === "external-browser-workflow"
  );
}

function validRecordOperationDependencies(values, scopeId, declarations) {
  if (!Array.isArray(values)) return false;
  const seen = new Set();
  return values.every((value) => {
    if (
      !value
      || typeof value !== "object"
      || Array.isArray(value)
      || Object.keys(value).sort().join("\0") !== "operation\0recordKind\0resourceId"
      || !isStableDeclarationId(value.resourceId)
      || !isStableDeclarationId(value.recordKind)
      || !isStableDeclarationId(value.operation)
    ) return false;
    const key = `${value.resourceId}\0${value.recordKind}\0${value.operation}`;
    const declaration = declarations.find(
      (item) => item.id === value.recordKind && item.resourceId === value.resourceId,
    );
    if (
      seen.has(key)
      || !declaration
      || declaration.scopeId !== scopeId
      || !declaration.revealOperations.includes(value.operation)
    ) return false;
    seen.add(key);
    return true;
  });
}

function validSingletonOperationDependencies(values, scopeId, declarations) {
  if (!Array.isArray(values)) return false;
  const allowed = new Set(["status", "reveal", "replace", "delete"]);
  const seen = new Set();
  return values.every((value) => {
    const verbs = value?.verbs;
    const declaration = declarations.find((item) => item.id === value?.singletonId);
    if (
      !value
      || typeof value !== "object"
      || Array.isArray(value)
      || Object.keys(value).sort().join("\0") !== "singletonId\0verbs"
      || !isStableDeclarationId(value.singletonId)
      || !Array.isArray(verbs)
      || !verbs.length
      || verbs.some((verb) => !allowed.has(verb))
      || new Set(verbs).size !== verbs.length
      || [...verbs].sort().join("\0") !== verbs.join("\0")
      || seen.has(value.singletonId)
      || !declaration
      || declaration.scopeId !== scopeId
    ) return false;
    seen.add(value.singletonId);
    return true;
  });
}

function validArtifactOperationDependencies(values, scopeId, declarations) {
  if (!Array.isArray(values)) return false;
  const allowed = new Set([
    "write", "read", "retire", "release-owner", "reconcile-owner",
  ]);
  const seen = new Set();
  return values.every((value) => {
    const verbs = value?.verbs;
    const declaration = declarations.find((item) => item.id === value?.artifactKind);
    if (
      !value
      || typeof value !== "object"
      || Array.isArray(value)
      || Object.keys(value).sort().join("\0") !== "artifactKind\0verbs"
      || !isStableDeclarationId(value.artifactKind)
      || !Array.isArray(verbs)
      || !verbs.length
      || verbs.some((verb) => (
        !allowed.has(verb)
        && !(verb.startsWith("lease.")
          && declaration?.operations.includes(verb.slice(6)))
      ))
      || new Set(verbs).size !== verbs.length
      || [...verbs].sort().join("\0") !== verbs.join("\0")
      || seen.has(value.artifactKind)
      || !declaration
      || declaration.scopeId !== scopeId
      || (verbs.includes("reconcile-owner") && declaration.retention !== "durable-adjunct")
      || (verbs.includes("write") && declaration.retention === "run-scoped-spill")
    ) return false;
    seen.add(value.artifactKind);
    return true;
  });
}

function isSafeBrowserOperationRoute(route) {
  const value = String(route || "");
  return value.startsWith("/")
    && !value.startsWith("//")
    && !value.includes("?")
    && !value.includes("#")
    && !value.includes("\\")
    && !value.includes("{")
    && !value.includes("}");
}

function isStableDeclarationId(value) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9._-]*$/.test(value);
}

function isProjectionPath(value) {
  return String(value || "").split(".").every(
    (segment) => /^[a-z0-9][a-z0-9._-]*$/.test(segment),
  );
}

function validateBrowserAdapterRequirements(requirements) {
  if (!Array.isArray(requirements)) {
    throw new PrivacyPackConnectionError("invalid_server_adapter_declaration");
  }
  const expectedIds = requirements.map((item) => String(item?.id || "")).sort();
  if (
    expectedIds.some((item) => !item)
    || new Set(expectedIds).size !== expectedIds.length
    || requirements.some((requirement) => (
      !Array.isArray(requirement?.nodeTypes)
      || !Array.isArray(requirement?.methods)
    ))
  ) {
    throw new PrivacyPackConnectionError("invalid_server_adapter_declaration");
  }
}

function validateBrowserAdapterBindings(requirements, adapters) {
  validateBrowserAdapterRequirements(requirements);
  const expectedIds = requirements.map((item) => String(item.id)).sort();
  const suppliedIds = Object.keys(adapters).sort();
  if (
    expectedIds.length !== suppliedIds.length
    || expectedIds.some((idValue, index) => idValue !== suppliedIds[index])
  ) {
    throw new PrivacyPackConnectionError("browser_adapter_mismatch");
  }
  for (const requirement of requirements) {
    if (
      !Array.isArray(requirement.nodeTypes)
      || !Array.isArray(requirement.methods)
      || !adapters[requirement.id]
      || requirement.methods.some(
        (method) => typeof adapters[requirement.id]?.[method] !== "function",
      )
    ) {
      throw new PrivacyPackConnectionError("browser_adapter_mismatch");
    }
  }
}

async function resolveBrowserAdapterBindings(entry, adapters, adapterFactories) {
  validateBrowserAdapterRequirements(entry.requirements);
  const concreteIds = Object.keys(adapters);
  const factoryIds = Object.keys(adapterFactories);
  if (concreteIds.some((id) => factoryIds.includes(id))) {
    throw new PrivacyPackConnectionError("browser_adapter_mismatch");
  }
  const suppliedIds = [...concreteIds, ...factoryIds].sort();
  const expectedIds = entry.requirements.map((item) => item.id).sort();
  if (
    suppliedIds.length !== expectedIds.length
    || expectedIds.some((id, index) => id !== suppliedIds[index])
  ) {
    throw new PrivacyPackConnectionError("browser_adapter_mismatch");
  }

  const resolved = {};
  for (const requirement of entry.requirements) {
    if (Object.hasOwn(adapterFactories, requirement.id)) {
      const factory = adapterFactories[requirement.id];
      if (typeof factory !== "function") {
        throw new PrivacyPackConnectionError("browser_adapter_mismatch");
      }
      const handle = adapterFactoryHandle(entry, requirement);
      const context = Object.freeze({
        requirement,
        handle,
      });
      try {
        resolved[requirement.id] = await factory(context);
      } catch {
        throw new PrivacyPackConnectionError("browser_adapter_mismatch");
      }
    } else {
      resolved[requirement.id] = adapters[requirement.id];
    }
  }
  validateBrowserAdapterBindings(entry.requirements, resolved);
  return Object.freeze(resolved);
}

function adapterFactoryHandle(entry, requirement) {
  const candidates = new Map();
  for (const scope of entry.modeScopes) {
    if (scope.modeEditorAdapter !== requirement.id) continue;
    const resource = entry.resources.find(
      (item) => item.id === scope.modeResourceId && item.kind === RESOURCE_KIND.MODE,
    );
    if (resource) candidates.set(
      `${resource.kind}:${resource.id}`,
      [resource, BrowserModeHandle],
    );
  }
  for (const field of entry.protectedFields) {
    if (field.browserAdapter !== requirement.id) continue;
    const resource = entry.resources.find(
      (item) => item.id === field.workflowResourceId && item.kind === RESOURCE_KIND.WORKFLOW,
    );
    if (resource) candidates.set(
      `${resource.kind}:${resource.id}`,
      [resource, BrowserWorkflowHandle],
    );
  }
  if (candidates.size !== 1) {
    throw new PrivacyPackConnectionError("browser_adapter_mismatch");
  }
  const [[resource, HandleType]] = candidates.values();
  return browserResourceUnchecked(entry.pack, resource, HandleType);
}

function browserResource(pack, resourceId, expectedKind, HandleType) {
  const entry = PACK_ENTRIES.get(pack);
  entry.pack.readiness.requireReady();
  const resource = entry.resources.find(
    (item) => item.id === resourceId && item.kind === expectedKind,
  );
  if (!resource) throw new PrivacyPackConnectionError("unknown_browser_resource");
  return browserResourceUnchecked(pack, resource, HandleType);
}

function browserResourceUnchecked(pack, resource, HandleType) {
  const entry = PACK_ENTRIES.get(pack);
  const cacheKey = `${resource.kind}:${resource.id}`;
  if (!entry.handles.has(cacheKey)) {
    entry.handles.set(cacheKey, new HandleType(entry, resource));
  }
  return entry.handles.get(cacheKey);
}

function requireWorkflowField(entry, workflowResourceId, fieldId) {
  const id = String(fieldId || "");
  const field = entry.protectedFields.find(
    (field) => field.id === id && field.workflowResourceId === workflowResourceId,
  );
  if (!field) {
    throw new PrivacyPackConnectionError("unknown_browser_field");
  }
  return field;
}

function requireRecordDeclaration(entry, resourceId, recordKind) {
  const declaration = entry.recordDeclarations.find(
    (item) => item.resourceId === resourceId && item.id === recordKind,
  );
  if (!declaration) {
    throw new PrivacyPackConnectionError("unknown_browser_record_declaration");
  }
  return declaration;
}

function requireRecordReferenceMigration(entry, resourceId, recordKind, migrationId) {
  const migration = entry.recordReferenceMigrations.find(
    (item) => item.id === migrationId
      && item.resourceId === resourceId
      && item.recordKind === recordKind,
  );
  if (!migration) {
    throw new PrivacyPackConnectionError("unknown_browser_record_reference_migration");
  }
  return migration;
}

function validateTypedOperationResponse(result, operation) {
  if (operation.legacyOperationWire === true) {
    const exactLegacy = ["correlationId", "ok", "payload", "private", "references"];
    if (
      !result
      || typeof result !== "object"
      || Array.isArray(result)
      || Object.keys(result).sort().join("\0") !== exactLegacy.join("\0")
      || result.ok !== true
      || typeof result.private !== "boolean"
      || !/^hp-operation-[A-Za-z0-9_-]{16,64}$/.test(String(result.correlationId || ""))
      || !result.payload
      || typeof result.payload !== "object"
      || Array.isArray(result.payload)
      || !Array.isArray(result.references)
      || result.references.length !== operation.referenceOutputs.length
    ) {
      throw new PrivacyPackConnectionError("invalid_browser_operation_response");
    }
    const references = result.references.map((shell, index) => {
      if (
        !shell
        || typeof shell !== "object"
        || Array.isArray(shell)
        || Object.keys(shell).sort().join("\0") !== "id\0kind"
        || !/^hp-ref-[A-Za-z0-9_-]{32}$/.test(String(shell.id || ""))
        || shell.kind !== operation.referenceOutputs[index].referenceKindId
      ) {
        throw new PrivacyPackConnectionError("invalid_browser_operation_response");
      }
      return Object.freeze({ id: String(shell.id), kind: String(shell.kind) });
    });
    return Object.freeze({
      ok: true,
      payload: Object.freeze({ ...result.payload }),
      references: Object.freeze(references),
      private: result.private,
      correlationId: String(result.correlationId),
    });
  }
  const exactTopLevel = [
    "association", "correlationId", "data", "lease", "ok", "private", "references", "safePayload",
  ].sort();
  const lease = operation.returnsLease === true
    ? normalizeTypedOperationLease(result?.lease)
    : null;
  if (
    !result
    || typeof result !== "object"
    || Array.isArray(result)
    || Object.keys(result).sort().join("\0") !== exactTopLevel.join("\0")
    || result.ok !== true
    || typeof result.private !== "boolean"
    || !/^hp-operation-[A-Za-z0-9_-]{16,64}$/.test(String(result.correlationId || ""))
    || !result.data
    || typeof result.data !== "object"
    || Array.isArray(result.data)
    || (result.safePayload !== null && (
      typeof result.safePayload !== "object" || Array.isArray(result.safePayload)
    ))
    || !validateSafePayload(result.safePayload, operation.safePayloadLeaves)
    || (operation.returnsLease === true ? lease === null : result.lease !== null)
    || result.association !== null
    || !Array.isArray(result.references)
  ) {
    throw new PrivacyPackConnectionError("invalid_browser_operation_response");
  }
  let offset = 0;
  const references = [];
  for (const output of operation.referenceOutputs) {
    let count = 0;
    while (
      offset + count < result.references.length
      && result.references[offset + count]?.kind === output.referenceKindId
    ) count += 1;
    if (count < output.minimum || count > output.maximum) {
      throw new PrivacyPackConnectionError("invalid_browser_operation_response");
    }
    for (let index = offset; index < offset + count; index += 1) {
      const shell = result.references[index];
    if (
      !shell
      || typeof shell !== "object"
      || Array.isArray(shell)
      || Object.keys(shell).sort().join("\0") !== "id\0kind"
      || !/^hp-ref-[A-Za-z0-9_-]{32}$/.test(String(shell.id || ""))
      || shell.kind !== output.referenceKindId
    ) {
      throw new PrivacyPackConnectionError("invalid_browser_operation_response");
    }
      references.push(Object.freeze({ id: String(shell.id), kind: String(shell.kind) }));
    }
    offset += count;
  }
  if (offset !== result.references.length) {
    throw new PrivacyPackConnectionError("invalid_browser_operation_response");
  }
  return Object.freeze({
    ok: true,
    data: Object.freeze({ ...result.data }),
    safePayload: result.safePayload === null ? null : Object.freeze({ ...result.safePayload }),
    references: Object.freeze(references),
    lease,
    association: null,
    private: result.private,
    correlationId: String(result.correlationId),
  });
}

function normalizeTypedOperationLease(value) {
  try {
    return normalizeArtifactLease(value);
  } catch {
    return null;
  }
}

function validateSafePayload(value, expectedLeaves) {
  if (!Array.isArray(expectedLeaves)) return false;
  if (!expectedLeaves.length) return value === null;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const leaves = new Map();
  const visit = (current, prefix, depth) => {
    if (depth > 8) return false;
    if (current && typeof current === "object" && !Array.isArray(current)) {
      const entries = Object.entries(current);
      if (!entries.length) return false;
      return entries.every(([key, item]) => (
        /^[a-z0-9][a-z0-9_-]*$/.test(key)
        && visit(item, prefix ? `${prefix}.${key}` : key, depth + 1)
      ));
    }
    if (
      Array.isArray(current)
      || (typeof current === "number" && !Number.isFinite(current))
      || !["string", "number", "boolean"].includes(typeof current) && current !== null
      || leaves.has(prefix)
    ) return false;
    leaves.set(prefix, current);
    return true;
  };
  if (!visit(value, "", 0)) return false;
  const actual = [...leaves.keys()].sort();
  const expected = expectedLeaves.map((leaf) => leaf.path).sort();
  if (actual.join("\0") !== expected.join("\0")) return false;
  for (const leaf of expectedLeaves) {
    const item = leaves.get(leaf.path);
    if (leaf.kind === "boolean" && typeof item !== "boolean") return false;
    if (leaf.kind === "count" && (
      !Number.isInteger(item) || item < 0 || item > 2_147_483_647
    )) return false;
    if (leaf.kind === "number" && (
      typeof item !== "number" || !Number.isFinite(item) || Math.abs(item) > 1e15
    )) return false;
    if (leaf.kind === "safe-text" && !isSafePayloadText(item)) return false;
  }
  try {
    return new TextEncoder().encode(JSON.stringify(value)).length <= 64 * 1024;
  } catch {
    return false;
  }
}

function isSafePayloadText(value) {
  if (
    typeof value !== "string"
    || !value
    || value !== value.trim()
    || value.length > 256
    || new TextEncoder().encode(value).length > 512
    || [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  ) return false;
  const lowered = value.toLowerCase();
  return !value.includes("/")
    && !value.includes("\\")
    && !value.includes("..")
    && !value.includes("://")
    && !/^[A-Za-z][A-Za-z0-9+.-]*:/.test(value)
    && !/^[A-Za-z]:/.test(value)
    && !lowered.startsWith("~")
    && !lowered.includes("%2f")
    && !lowered.includes("%5c");
}

function requireArtifactDeclaration(entry, resourceId, artifactKind) {
  const declaration = entry.artifactDeclarations.find(
    (item) => item.resourceId === resourceId && item.id === artifactKind,
  );
  if (!declaration) {
    throw new PrivacyPackConnectionError("unknown_browser_artifact_declaration");
  }
  return declaration;
}

function registerPrivacyLifecycleExtension(app) {
  if (PRIVACY_EXTENSION_REGISTERED) return;
  if (typeof app.registerExtension !== "function") {
    throw new PrivacyPackConnectionError("comfyui_extension_api_missing");
  }
  app.registerExtension({
    name: "helto.privacy.profile-runtime",
    async beforeRegisterNodeDef(nodeType, nodeData) {
      await reconcilePrivacyNodeDefinition(nodeType, nodeData, "definition");
    },
    async nodeCreated(node) {
      await reconcilePrivacyNode(node, "created");
    },
    async loadedGraphNode(node) {
      await reconcilePrivacyNode(node, "loaded");
    },
  });
  PRIVACY_EXTENSION_APP = app;
  PRIVACY_EXTENSION_REGISTERED = true;
}

async function reconcileExistingNodeDefinitions(app, entry) {
  const definitions = app?.registeredNodeTypes
    || globalThis.LiteGraph?.registered_node_types
    || {};
  for (const [typeName, nodeType] of Object.entries(definitions)) {
    const nodeData = nodeType?.nodeData || { name: typeName };
    await reconcileEntryNodeDefinition(entry, nodeType, nodeData, "definition-existing");
  }
}

async function reconcileExistingPrivacyNodes(app, entry) {
  for (const node of collectGraphNodes(app?.rootGraph || app?.graph)) {
    await reconcileEntryNode(entry, node, "existing");
  }
}

function collectGraphNodes(rootGraph) {
  const nodes = [];
  const visited = new Set();
  const visit = (graph) => {
    if (!graph || typeof graph !== "object" || visited.has(graph)) return;
    visited.add(graph);
    const graphNodes = graph._nodes || graph.nodes || [];
    if (Array.isArray(graphNodes)) nodes.push(...graphNodes);
    const subgraphs = graph.subgraphs;
    const values = typeof subgraphs?.values === "function"
      ? subgraphs.values()
      : (Array.isArray(subgraphs) ? subgraphs : []);
    for (const subgraph of values) visit(subgraph);
  };
  visit(rootGraph);
  return nodes;
}

async function reconcilePrivacyNode(node, phase) {
  for (const entry of CONNECTED_PRIVACY_PACKS.values()) {
    if (entry.status === STATUS.READY) await reconcileEntryNode(entry, node, phase);
  }
}

async function reconcileEntryNode(entry, node, phase) {
  entry.snapshotCoordinator.reserveNode(node);
  const nodeType = String(node?.comfyClass || node?.type || "");
  for (const requirement of entry.requirements) {
    if (!requirement.nodeTypes.includes(nodeType)) continue;
    const reconcile = entry.adapters[requirement.id]?.reconcileNode;
    if (typeof reconcile === "function") {
      await reconcile(node, Object.freeze({ packId: entry.id, adapterId: requirement.id, phase }));
    }
  }
  await entry.snapshotCoordinator.registerNode(node);
  entry.serializationBarrier?.refreshGraphs();
}

async function reconcilePrivacyNodeDefinition(nodeType, nodeData, phase) {
  for (const entry of CONNECTED_PRIVACY_PACKS.values()) {
    if (entry.status === STATUS.READY) {
      await reconcileEntryNodeDefinition(entry, nodeType, nodeData, phase);
    }
  }
}

async function reconcileEntryNodeDefinition(entry, nodeType, nodeData, phase) {
  const typeName = String(nodeData?.name || nodeData?.type || nodeType?.comfyClass || "");
  for (const requirement of entry.requirements) {
    if (!requirement.nodeTypes.includes(typeName)) continue;
    const reconcile = entry.adapters[requirement.id]?.reconcileNodeDefinition;
    if (typeof reconcile === "function") {
      await reconcile(nodeType, nodeData, Object.freeze({
        packId: entry.id,
        adapterId: requirement.id,
        phase,
      }));
    }
  }
}
