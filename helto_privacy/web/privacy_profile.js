// Atomic browser compiler for Helto privacy profiles. This module owns only
// profile attestation, typed browser handles, and ComfyUI lifecycle binding.

const ROUTE_PREFIX = "/helto_privacy";
export const PRIVACY_CONTRACT_V2 = "helto.privacy.v2";

const STATUS = Object.freeze({
  READY: "ready",
  CONFLICT: "conflict",
});
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

export class BrowserModeHandle extends BrowserResourceHandle {}
export class BrowserWorkflowHandle extends BrowserResourceHandle {}
export class BrowserRecordHandle extends BrowserResourceHandle {}
export class BrowserArtifactHandle extends BrowserResourceHandle {}
export class BrowserExecutionHandle extends BrowserResourceHandle {}

class BrowserPrivacyPack {
  constructor(entry) {
    PACK_ENTRIES.set(this, entry);
    this.packId = entry.id;
    this.contract = entry.contract;
    this.fingerprint = entry.fingerprint;
    this.readiness = new BrowserReadinessHandle(entry);
    this.authorization = new BrowserAuthorizationHandle(entry);
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
  adapters = {},
  fetchProfile = fetchPrivacyProfile,
}) {
  const id = String(packId || "").trim();
  const fingerprint = String(profileFingerprint || "").trim();
  if (
    !app
    || !id
    || !fingerprint
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
      || existing.app !== app
    ) {
      existing.status = STATUS.CONFLICT;
      throw new PrivacyPackConnectionError("browser_profile_conflict");
    }
    return existing.pack;
  }

  let attestation;
  try {
    attestation = await fetchProfile(id);
  } catch {
    throw new PrivacyPackConnectionError("server_attestation_unavailable");
  }
  validateServerAttestation({ id, contract, fingerprint, adapters, attestation });

  if (PRIVACY_EXTENSION_APP && PRIVACY_EXTENSION_APP !== app) {
    throw new PrivacyPackConnectionError("comfyui_app_conflict");
  }

  const entry = {
    app,
    id,
    contract,
    fingerprint,
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
    handles: new Map(),
    status: STATUS.READY,
    pack: null,
  };
  entry.pack = new BrowserPrivacyPack(entry);

  CONNECTED_PRIVACY_PACKS.set(id, entry);
  try {
    registerPrivacyLifecycleExtension(app);
    await reconcileExistingNodeDefinitions(app, entry);
    await reconcileExistingPrivacyNodes(app, entry);
  } catch {
    entry.status = STATUS.CONFLICT;
    throw new PrivacyPackConnectionError("browser_lifecycle_registration_failed");
  }
  return entry.pack;
}

async function fetchPrivacyProfile(packId) {
  const response = await fetch(`${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}`, {
    headers: { Accept: "application/json" },
  });
  const payload = await response.json();
  if (!response.ok || payload?.ok === false) throw new Error("Profile attestation failed.");
  return payload;
}

function validateServerAttestation({ id, contract, fingerprint, adapters, attestation }) {
  if (
    !attestation
    || attestation.id !== id
    || attestation.contract !== contract
    || attestation.fingerprint !== fingerprint
  ) {
    throw new PrivacyPackConnectionError("browser_server_attestation_drift");
  }
  if (attestation.status !== STATUS.READY) {
    throw new PrivacyPackConnectionError("server_profile_not_ready");
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

  const requirements = Array.isArray(attestation.requiredBrowserAdapters)
    ? attestation.requiredBrowserAdapters
    : [];
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
  const nodes = app?.graph?._nodes || app?.graph?.nodes || [];
  for (const node of nodes) await reconcileEntryNode(entry, node, "existing");
}

async function reconcilePrivacyNode(node, phase) {
  for (const entry of CONNECTED_PRIVACY_PACKS.values()) {
    if (entry.status === STATUS.READY) await reconcileEntryNode(entry, node, phase);
  }
}

async function reconcileEntryNode(entry, node, phase) {
  const nodeType = String(node?.comfyClass || node?.type || "");
  for (const requirement of entry.requirements) {
    if (!requirement.nodeTypes.includes(nodeType)) continue;
    const reconcile = entry.adapters[requirement.id]?.reconcileNode;
    if (typeof reconcile === "function") {
      await reconcile(node, Object.freeze({ packId: entry.id, adapterId: requirement.id, phase }));
    }
  }
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
