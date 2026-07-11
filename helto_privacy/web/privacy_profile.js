// Atomic browser compiler for Helto privacy profiles. This module owns only
// profile attestation, typed browser handles, and ComfyUI lifecycle binding.

import {
  connectAttestedPrivacyProfileClient,
  isPrivacySetupRequiredError,
  subscribePrivacySession,
} from "../privacy_client.js";
import {
  mountSharedPrivacySurface,
  showPrivacyKeystoreDialog,
} from "../privacy.js";
import {
  createPrivacySnapshotCoordinator,
  installGraphSerializationBarrier,
} from "../privacy_snapshot.js";

export const PRIVACY_CONTRACT_V2 = "helto.privacy.v2";

const STATUS = Object.freeze({
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
  ARTIFACT: "artifact",
  EXECUTION: "execution",
});
const CONNECTED_PRIVACY_PACKS = new Map();
const PACK_ENTRIES = new WeakMap();
const HANDLE_ENTRIES = new WeakMap();
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

export class BrowserModeHandle extends BrowserResourceHandle {
  resolve(scopeId) {
    const entry = HANDLE_ENTRIES.get(this);
    return entry.transport.mode.resolve(this.resourceId, scopeId);
  }

  async transition(scopeId, target) {
    const entry = HANDLE_ENTRIES.get(this);
    if (!entry.modeScopes.some(
      (scope) => scope.id === scopeId && scope.modeResourceId === this.resourceId,
    )) {
      throw new PrivacyPackConnectionError("unknown_browser_mode_scope");
    }
    entry.pack.authorization.requireReady();
    const result = await entry.transport.mode.transition(scopeId, target);
    if (result !== null) await entry.snapshotCoordinator.refreshModes();
    return result;
  }
}
export class BrowserWorkflowHandle extends BrowserResourceHandle {
  markEdited(owner, fieldId) {
    const entry = HANDLE_ENTRIES.get(this);
    requireWorkflowField(entry, this.resourceId, fieldId);
    return entry.snapshotCoordinator.markEdited(owner, fieldId);
  }

  settle(reason = "manual-save") {
    const entry = HANDLE_ENTRIES.get(this);
    return entry.serializationBarrier.settle(reason);
  }

  runWithSnapshot(reason, operation) {
    const entry = HANDLE_ENTRIES.get(this);
    return entry.serializationBarrier.runWithSnapshot(reason, operation);
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
export class BrowserRecordHandle extends BrowserResourceHandle {}
export class BrowserArtifactHandle extends BrowserResourceHandle {}
export class BrowserExecutionHandle extends BrowserResourceHandle {}

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
}

/** Attest and bind a complete browser profile as one immutable pack. */
export async function connectPrivacyPack({
  app,
  packId,
  contract = PRIVACY_CONTRACT_V2,
  profileFingerprint,
  suiteManifestDigest,
  adapters = {},
}) {
  const id = String(packId || "").trim();
  const fingerprint = String(profileFingerprint || "").trim();
  const suiteDigest = String(suiteManifestDigest || "").trim();
  if (
    !app
    || !id
    || !/^[0-9a-f]{64}$/.test(fingerprint)
    || !/^[0-9a-f]{64}$/.test(suiteDigest)
    || contract !== PRIVACY_CONTRACT_V2
    || !adapters
    || typeof adapters !== "object"
    || Array.isArray(adapters)
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
    validateBrowserAdapterBindings(existing.requirements, adapters);
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
    adapters,
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
    suiteStatus: attestation.suiteStatus,
    adapters: Object.freeze({ ...adapters }),
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
    })),
    protectedFields: attestation.protectedFields.map((item) => Object.freeze({
      id: String(item.id),
      workflowResourceId: String(item.workflowResourceId),
      scopeId: String(item.scopeId),
      browserAdapter: String(item.browserAdapter),
      nodeTypes: Object.freeze([...item.nodeTypes]),
    })),
    protectedOperations: attestation.protectedOperations.map((item) => Object.freeze({
      id: String(item.id),
      resourceId: String(item.resourceId),
      route: String(item.route),
      method: String(item.method),
    })),
    handles: new Map(),
    transport,
    snapshotCoordinator: null,
    serializationBarrier: null,
    sessionState: Object.freeze({ state: "unknown", revision: 0 }),
    sessionUnsubscribe: null,
    surface: null,
    status: STATUS.READY,
    pack: null,
  };
  entry.snapshotCoordinator = createPrivacySnapshotCoordinator({
    packId: entry.id,
    fields: entry.protectedFields,
    adapters: entry.adapters,
    transport: entry.transport.snapshot,
    resolvePrivate: async (field) => {
      const scope = entry.modeScopes.find((item) => item.id === field.scopeId);
      if (!scope) return true;
      const resolution = await entry.transport.mode.resolve(
        scope.modeResourceId,
        scope.id,
      );
      return resolution.effective !== "public";
    },
    blocked: entry.suiteStatus !== STATUS.SUITE_ACTIVE,
  });
  entry.pack = new BrowserPrivacyPack(entry);
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
    );
    await reconcileExistingNodeDefinitions(app, entry);
    await reconcileExistingPrivacyNodes(app, entry);
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

function validateServerAttestation({
  id,
  contract,
  fingerprint,
  suiteDigest,
  adapters,
  attestation,
}) {
  if (
    !attestation
    || attestation.id !== id
    || attestation.contract !== contract
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
      || fieldIds.has(field.id)
      || !attestation.resources.some(
        (resource) => resource.id === field.workflowResourceId
          && resource.kind === RESOURCE_KIND.WORKFLOW,
      )
      || !attestation.requiredBrowserAdapters.some(
        (adapter) => adapter.id === field.browserAdapter,
      )
      || !attestation.modeScopes.some((scope) => scope.id === field.scopeId)
    ) {
      throw new PrivacyPackConnectionError("invalid_server_field_declaration");
    }
    fieldIds.add(field.id);
  }
  if (!Array.isArray(attestation.protectedOperations)) {
    throw new PrivacyPackConnectionError("invalid_server_operation_declaration");
  }
  const operationIds = new Set();
  for (const operation of attestation.protectedOperations) {
    if (
      !operation?.id
      || !operation?.resourceId
      || !isSafeBrowserOperationRoute(operation.route)
      || !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(operation.method)
      || operationIds.has(operation.id)
      || !attestation.resources.some((resource) => resource.id === operation.resourceId)
    ) {
      throw new PrivacyPackConnectionError("invalid_server_operation_declaration");
    }
    operationIds.add(operation.id);
  }

  const requirements = Array.isArray(attestation.requiredBrowserAdapters)
    ? attestation.requiredBrowserAdapters
    : [];
  validateBrowserAdapterBindings(requirements, adapters);
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

function validateBrowserAdapterBindings(requirements, adapters) {
  const expectedIds = requirements.map((item) => String(item?.id || "")).sort();
  const suppliedIds = Object.keys(adapters).sort();
  if (expectedIds.some((item) => !item) || new Set(expectedIds).size !== expectedIds.length) {
    throw new PrivacyPackConnectionError("invalid_server_adapter_declaration");
  }
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

function browserResource(pack, resourceId, expectedKind, HandleType) {
  const entry = PACK_ENTRIES.get(pack);
  entry.pack.readiness.requireReady();
  const resource = entry.resources.find(
    (item) => item.id === resourceId && item.kind === expectedKind,
  );
  if (!resource) throw new PrivacyPackConnectionError("unknown_browser_resource");
  const cacheKey = `${expectedKind}:${resourceId}`;
  if (!entry.handles.has(cacheKey)) {
    entry.handles.set(cacheKey, new HandleType(entry, resource));
  }
  return entry.handles.get(cacheKey);
}

function requireWorkflowField(entry, workflowResourceId, fieldId) {
  const id = String(fieldId || "");
  if (!entry.protectedFields.some(
    (field) => field.id === id && field.workflowResourceId === workflowResourceId,
  )) {
    throw new PrivacyPackConnectionError("unknown_browser_field");
  }
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
