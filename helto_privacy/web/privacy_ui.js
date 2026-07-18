// Shared Helto privacy UI, served by the helto-privacy Python package at
// /helto_privacy/ui/privacy.js. Node packs import it dynamically:
//
//   const privacy = await import("/helto_privacy/ui/privacy.js");
//   await privacy.showPrivacyKeystoreDialog("unlock");
//
// Token storage (localStorage + cookie) is shared per ComfyUI origin, so an
// unlock performed through any pack covers every Helto pack's frontend and
// media elements. Talks to the canonical /helto_privacy/* endpoints
// registered by helto_privacy.comfy_ui.register_helto_privacy_ui().

const ROUTE_PREFIX = "/helto_privacy";
const PRIVACY_TOKEN_HEADER = "X-Helto-Privacy-Token";
const PRIVACY_TOKEN_STORAGE_KEY = "helto_privacy_token";
const PRIVACY_LOCKED_CODES = ["PRIVACY_LOCKED", "PRIVACY_TOKEN_REQUIRED"];
const PRIVACY_SETUP_CODES = ["PRIVACY_KEYSTORE_UNINITIALIZED"];
const PRIVACY_UNREADABLE_VALUE_CODES = [
  "PRIVACY_KEYSTORE_UNINITIALIZED",
  "PRIVACY_KEYSTORE_INVALID",
  "PRIVACY_KEY_MISSING",
  "PRIVACY_KEY_INVALID",
  "PRIVACY_KEY_MISMATCH",
  "PRIVACY_DECRYPT_FAILED",
  "PRIVACY_PAYLOAD_INVALID",
];
const PRIVACY_UNREADABLE_VALUE_MESSAGES = [
  "different local privacy key",
  "privacy key file is missing",
  "could not read privacy key file",
  "could not decrypt state payload",
  "could not decrypt timeline director data",
  "unsupported legacy privacy schema",
  "unsupported encrypted privacy schema",
  "unsupported legacy aio privacy payload",
  "unsupported aio privacy payload schema",
];
const PRIVACY_ENVELOPE_ALGORITHM = "AES-256-GCM";
const LEGACY_ENCRYPTED_PREFIX = "__HELTO_ENC__:";
const DIALOG_CLASS = "helto-privacy-keystore-dialog";
const RECOVERY_DIALOG_CLASS = "helto-privacy-recovery-dialog";
const UNREADABLE_DIALOG_CLASS = "helto-privacy-unreadable-dialog";
const STYLE_ID = "helto-privacy-keystore-ui-style";
const RECOVERY_ISSUE_TYPES = Object.freeze({
  LEGACY_VALUE: "legacy_encrypted_value",
  INVALID_ENVELOPE: "invalid_encrypted_value",
  PLAINTEXT: "plaintext_sensitive_value",
  MISSING_PRIVACY: "missing_privacy_setting",
  ENCRYPTION_UNAVAILABLE: "encryption_unavailable",
});
export const PRIVACY_RECOVERY_ISSUE_TYPES = RECOVERY_ISSUE_TYPES;

const RECOVERY_DESCRIPTORS = new Map();
const OWNER_MEMOS = new WeakMap();
const FALLBACK_OWNER = {};
let unreadableResetDialogPromise = null;

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

export function getStoredPrivacyToken() {
  try {
    return globalThis.localStorage?.getItem(PRIVACY_TOKEN_STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

export function storePrivacyToken(token) {
  try {
    if (token) globalThis.localStorage?.setItem(PRIVACY_TOKEN_STORAGE_KEY, String(token));
    else globalThis.localStorage?.removeItem(PRIVACY_TOKEN_STORAGE_KEY);
  } catch {
    /* localStorage unavailable — token stays per-request. */
  }
  writePrivacyTokenCookie(token);
}

export function ensureStoredPrivacyTokenCookie(documentRef = globalThis.document) {
  const token = getStoredPrivacyToken();
  if (!token) return false;
  writePrivacyTokenCookie(token, documentRef);
  return true;
}

function writePrivacyTokenCookie(token, documentRef = globalThis.document) {
  // Image/media elements cannot send custom headers, so privacy-mode
  // thumbnails and waveforms authenticate with this cookie instead.
  try {
    if (!documentRef) return;
    documentRef.cookie = token
      ? `${PRIVACY_TOKEN_STORAGE_KEY}=${encodeURIComponent(String(token))}; path=/; SameSite=Lax`
      : `${PRIVACY_TOKEN_STORAGE_KEY}=; path=/; SameSite=Lax; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  } catch {
    /* cookies unavailable — header-based callers still work. */
  }
}

export function isPrivacyLockedError(error) {
  const message = String(error?.message ?? error ?? "");
  return PRIVACY_LOCKED_CODES.some((code) => message.includes(code));
}

export function isPrivacySetupRequiredError(error) {
  const message = String(error?.message ?? error ?? "");
  return PRIVACY_SETUP_CODES.some((code) => message.includes(code));
}

export function isPrivacyUnlockRequiredError(error) {
  return isPrivacyLockedError(error) || isPrivacySetupRequiredError(error);
}

export function isUnreadablePrivacyValueError(error) {
  if (isPrivacyLockedError(error)) return false;
  const message = String(error?.message ?? error ?? "").toLowerCase();
  return PRIVACY_UNREADABLE_VALUE_CODES.some((code) => message.includes(code.toLowerCase()))
    || PRIVACY_UNREADABLE_VALUE_MESSAGES.some((fragment) => message.includes(fragment));
}

export function isPrivacyKeyUnavailableError(error) {
  if (isPrivacyLockedError(error)) return false;
  const message = String(error?.message ?? error ?? "").toLowerCase();
  return [
    "PRIVACY_KEYSTORE_UNINITIALIZED",
    "PRIVACY_KEYSTORE_INVALID",
    "PRIVACY_KEY_MISSING",
    "PRIVACY_KEY_INVALID",
  ].some((code) => message.includes(code.toLowerCase()))
    || message.includes("privacy key file is missing")
    || message.includes("could not read privacy key file")
    || (message.includes("privacy key file") && message.includes("malformed"));
}

// ---------------------------------------------------------------------------
// Canonical keystore API
// ---------------------------------------------------------------------------

async function fetchPrivacyJson(endpoint, payload = null) {
  const headers = { "Content-Type": "application/json" };
  const token = getStoredPrivacyToken();
  if (token) headers[PRIVACY_TOKEN_HEADER] = token;
  const options = payload
    ? { method: "POST", headers, body: JSON.stringify(payload) }
    : undefined;
  const response = await fetch(`${ROUTE_PREFIX}/${endpoint}`, options);
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(text || response.statusText || `HTTP ${response.status}`);
  }
  if (!response.ok || data.ok === false || data.error) throw new Error(data.error || response.statusText);
  return data;
}

export async function fetchPrivacyStatus() {
  return fetchPrivacyJson("status");
}

export async function initializePrivacyKeystore(password) {
  const result = await fetchPrivacyJson("keystore/init", { password });
  storePrivacyToken(result.token || "");
  return result;
}

export async function unlockPrivacyKeystore(password) {
  const result = await fetchPrivacyJson("unlock", { password });
  storePrivacyToken(result.token || "");
  return result;
}

export async function lockPrivacyKeystore() {
  const result = await fetchPrivacyJson("lock", {});
  storePrivacyToken("");
  return result;
}

export async function changePrivacyKeystorePassword(currentPassword, newPassword) {
  const result = await fetchPrivacyJson("keystore/change_password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
  storePrivacyToken(result.token || "");
  return result;
}

// ---------------------------------------------------------------------------
// Privacy recovery registry, scanning, and fail-closed encryption
// ---------------------------------------------------------------------------

export class PrivacyRecoveryError extends Error {
  constructor(message, code = "PRIVACY_RECOVERY_ERROR") {
    super(`${code}: ${message}`);
    this.name = "PrivacyRecoveryError";
    this.code = code;
  }
}

export function registerPrivacyRecoveryDescriptors(sourceId, descriptors) {
  const id = String(sourceId || "").trim();
  if (!id) throw new PrivacyRecoveryError("Descriptor source id is required.", "PRIVACY_RECOVERY_DESCRIPTOR_INVALID");
  const list = Array.isArray(descriptors) ? descriptors : [descriptors];
  const normalized = list
    .map((descriptor, index) => normalizeDescriptor(id, descriptor, index))
    .filter(Boolean);
  const unique = new Map();
  for (const descriptor of normalized) unique.set(descriptor.id, descriptor);
  RECOVERY_DESCRIPTORS.set(id, [...unique.values()]);
  return {
    sourceId: id,
    descriptorCount: unique.size,
    totalDescriptors: allRecoveryDescriptors().length,
  };
}

export function registeredPrivacyRecoveryDescriptors() {
  return allRecoveryDescriptors().map((descriptor) => ({
    id: descriptor.id,
    sourceId: descriptor.sourceId,
    label: descriptor.label,
    nodeTypes: [...descriptor.nodeTypes],
    fieldCount: descriptor.fields.length,
  }));
}

export function scanPrivacyRecoveryIssues(graph = defaultRecoveryGraph()) {
  const descriptors = allRecoveryDescriptors();
  const nodes = collectGraphNodes(graph);
  const issues = [];
  let nextIssue = 1;

  for (const node of nodes) {
    for (const descriptor of descriptors) {
      if (!matchesRecoveryDescriptor(node, descriptor)) continue;
      const privacy = readPrivacyState(node, descriptor);
      if (privacy.missing) {
        issues.push(createRecoveryIssue({
          id: `privacy-recovery-${nextIssue++}`,
          type: RECOVERY_ISSUE_TYPES.MISSING_PRIVACY,
          node,
          descriptor,
          field: null,
          target: privacy.target,
          message: "Privacy setting is missing.",
        }));
      }

      for (const field of descriptor.fields) {
        if (field.sensitive === false) continue;
        const target = getRecoveryTarget(node, field);
        if (!target.exists) continue;
        const value = target.get();
        if (isUnsetOrDefaultValue(value, field, node)) continue;

        if (isLegacyPrivacyValue(value)) {
          issues.push(createRecoveryIssue({
            id: `privacy-recovery-${nextIssue++}`,
            type: RECOVERY_ISSUE_TYPES.LEGACY_VALUE,
            node,
            descriptor,
            field,
            target,
            message: "Legacy encrypted value needs reset.",
          }));
          continue;
        }

        if (looksLikeEncryptedJson(value)) {
          if (!isPrivacyEnvelopeAccepted(value, field, descriptor)) {
            issues.push(createRecoveryIssue({
              id: `privacy-recovery-${nextIssue++}`,
              type: RECOVERY_ISSUE_TYPES.INVALID_ENVELOPE,
              node,
              descriptor,
              field,
              target,
              message: "Encrypted-looking value does not match the registered schema.",
            }));
          }
          continue;
        }

        if (privacy.enabled) {
          issues.push(createRecoveryIssue({
            id: `privacy-recovery-${nextIssue++}`,
            type: RECOVERY_ISSUE_TYPES.PLAINTEXT,
            node,
            descriptor,
            field,
            target,
            message: "Plaintext sensitive value is present while privacy is enabled.",
          }));
        }
      }
    }
  }

  return issues;
}

export function buildPrivacyRecoveryDialogModel(issues = scanPrivacyRecoveryIssues()) {
  const counts = {};
  const nodes = new Map();
  for (const issue of issues || []) {
    counts[issue.type] = (counts[issue.type] || 0) + 1;
    const nodeKey = String(issue.nodeId ?? issue.nodeTitle ?? "node");
    if (!nodes.has(nodeKey)) {
      nodes.set(nodeKey, {
        nodeId: issue.nodeId,
        nodeTitle: issue.nodeTitle,
        nodeType: issue.nodeType,
        label: issue.nodeLabel,
        issues: [],
      });
    }
    nodes.get(nodeKey).issues.push({
      id: issue.id,
      type: issue.type,
      fieldKind: issue.fieldKind,
      fieldName: issue.fieldName,
      fieldLabel: issue.fieldLabel,
      message: issue.message,
      canReset: issue.canReset,
      canReencrypt: issue.canReencrypt,
      canEnablePrivacy: issue.canEnablePrivacy,
    });
  }
  return {
    totalIssues: (issues || []).length,
    counts,
    nodes: [...nodes.values()],
  };
}

export async function recoverPrivacyIssues(options = {}) {
  const action = String(options.action || "all_safe_defaults");
  const graph = options.graph ?? defaultRecoveryGraph();
  const issues = Array.isArray(options.issues) ? options.issues : scanPrivacyRecoveryIssues(graph);
  const applied = [];
  const skipped = [];
  const failed = [];
  const changedNodes = new Set();

  for (const issue of issues) {
    try {
      if (shouldEnablePrivacy(action, issue)) {
        const changed = applyPrivacyDefault(issue);
        if (changed) {
          applied.push(summarizeRecoveryAction(issue, "enable_privacy"));
          changedNodes.add(issue._node);
        } else {
          skipped.push(summarizeRecoveryAction(issue, "enable_privacy"));
        }
        continue;
      }

      if (shouldResetField(action, issue)) {
        const changed = applyFieldReset(issue);
        if (changed) {
          applied.push(summarizeRecoveryAction(issue, "reset"));
          changedNodes.add(issue._node);
        } else {
          skipped.push(summarizeRecoveryAction(issue, "reset"));
        }
        continue;
      }

      if (shouldReencryptField(action, issue)) {
        const changed = await applyFieldReencrypt(issue, options);
        if (changed) {
          applied.push(summarizeRecoveryAction(issue, "reencrypt"));
          changedNodes.add(issue._node);
        } else {
          skipped.push(summarizeRecoveryAction(issue, "reencrypt"));
        }
        continue;
      }

      skipped.push(summarizeRecoveryAction(issue, action));
    } catch (error) {
      const failedAction = summarizeRecoveryAction(issue, action);
      if (isPrivacyEncryptionUnavailable(error)) {
        failedAction.type = RECOVERY_ISSUE_TYPES.ENCRYPTION_UNAVAILABLE;
      }
      failed.push({
        ...failedAction,
        error: sanitizeErrorMessage(error),
      });
    }
  }

  for (const node of changedNodes) {
    markRecoveryGraphDirty(node, graph);
  }

  return {
    ok: failed.length === 0,
    action,
    appliedCount: applied.length,
    skippedCount: skipped.length,
    failedCount: failed.length,
    applied,
    skipped,
    failed,
  };
}

export function parsePrivacyEnvelope(value) {
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }
  return value && typeof value === "object" ? value : null;
}

export function serializePrivacyEnvelope(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return "";
  return stablePrivacyJsonStringify(value) || "";
}

export function isLegacyPrivacyValue(value) {
  return typeof value === "string" && value.startsWith(LEGACY_ENCRYPTED_PREFIX);
}

export function isPrivacyEnvelopeAccepted(value, field = {}, descriptor = {}) {
  const payload = parsePrivacyEnvelope(value);
  if (!payload || typeof payload !== "object") return false;
  const customAccepts = field.acceptsEnvelope ?? descriptor.acceptsEnvelope;
  if (typeof customAccepts === "function") {
    try {
      return customAccepts(payload, { field, descriptor }) === true;
    } catch {
      return false;
    }
  }
  if (payload.encrypted !== true || payload.algorithm !== PRIVACY_ENVELOPE_ALGORITHM) return false;
  const schemas = acceptedSchemas(field, descriptor);
  return schemas.length === 0 || schemas.includes(String(payload.schema || ""));
}

export function rememberPrivacyEnvelope(owner, fieldName, plaintext, envelope, options = {}) {
  const encrypted = serializePrivacyEnvelope(envelope);
  if (!isPrivacyEnvelopeAccepted(encrypted, options, options.descriptor || {})) return "";
  const memo = memoForOwner(owner, true);
  memo.set(fieldKey(fieldName), {
    canonical: canonicalPrivacyValue(plaintext),
    envelope: encrypted,
    field: options,
  });
  return encrypted;
}

export function rememberedPrivacyEnvelope(owner, fieldName, plaintext, options = {}) {
  const memo = memoForOwner(owner, false);
  const entry = memo?.get(fieldKey(fieldName));
  if (!entry) return "";
  if (entry.canonical !== canonicalPrivacyValue(plaintext)) return "";
  return isPrivacyEnvelopeAccepted(entry.envelope, options, options.descriptor || {}) ? entry.envelope : "";
}

export function forgetPrivacyEnvelope(owner, fieldName) {
  memoForOwner(owner, false)?.delete(fieldKey(fieldName));
}

export async function ensureEncryptedPrivacyValue(options = {}) {
  const {
    owner = null,
    fieldName = "value",
    value = "",
    canonicalValue = value,
    privacyMode = true,
    encrypt = null,
    defaultValue = "",
    encryptEmpty = true,
    promptUnlock = true,
    retryUnlock = true,
  } = options;
  const field = options.field || options;
  const descriptor = options.descriptor || {};
  const serialized = canonicalPrivacyValue(value);

  if (isPrivacyEnvelopeAccepted(serialized, field, descriptor)) {
    return serializePrivacyEnvelope(serialized);
  }
  if (!privacyMode) {
    forgetPrivacyEnvelope(owner, fieldName);
    return serialized;
  }
  if (!encryptEmpty && !serialized) {
    forgetPrivacyEnvelope(owner, fieldName);
    return String(defaultValue ?? "");
  }

  const remembered = rememberedPrivacyEnvelope(owner, fieldName, canonicalValue, { ...field, descriptor });
  if (remembered) return remembered;

  if (typeof encrypt !== "function") {
    throw new PrivacyRecoveryError(
      "No encryption handler is registered for this privacy field.",
      "PRIVACY_ENCRYPTION_UNAVAILABLE",
    );
  }

  const encrypted = await runFailClosedEncrypt(encrypt, serialized, {
    promptUnlock,
    retryUnlock,
    context: options.context || {},
  });
  if (!isPrivacyEnvelopeAccepted(encrypted, field, descriptor)) {
    throw new PrivacyRecoveryError(
      "Encryption did not return a valid privacy envelope for the registered schema.",
      "PRIVACY_ENCRYPTION_FAILED",
    );
  }
  rememberPrivacyEnvelope(owner, fieldName, canonicalValue, encrypted, { ...field, descriptor });
  return serializePrivacyEnvelope(encrypted);
}

function normalizeDescriptor(sourceId, descriptor, index) {
  if (!descriptor || typeof descriptor !== "object") return null;
  const nodeTypes = uniqueStrings([
    descriptor.nodeType,
    ...(Array.isArray(descriptor.nodeTypes) ? descriptor.nodeTypes : []),
  ]);
  const label = String(descriptor.label || descriptor.nodeType || descriptor.id || "Privacy-capable node");
  const id = String(descriptor.id || `${sourceId}:${nodeTypes.join("|") || index}:${label}`);
  return {
    ...descriptor,
    id,
    sourceId,
    label,
    nodeTypes,
    fields: (Array.isArray(descriptor.fields) ? descriptor.fields : [])
      .map((field) => normalizeField(field))
      .filter(Boolean),
    privacy: normalizePrivacyDescriptor(descriptor.privacy),
  };
}

function normalizeField(field) {
  if (!field || typeof field !== "object" || !field.name) return null;
  return {
    kind: String(field.kind || "widget"),
    label: String(field.label || field.name),
    sensitive: field.sensitive !== false,
    ...field,
    name: String(field.name),
  };
}

function normalizePrivacyDescriptor(privacy) {
  if (!privacy || typeof privacy !== "object") return null;
  const name = privacy.property || privacy.widget || privacy.name;
  if (!name) return null;
  return {
    kind: privacy.widget ? "widget" : "property",
    default: true,
    ...privacy,
    name: String(name),
  };
}

function allRecoveryDescriptors() {
  return [...RECOVERY_DESCRIPTORS.values()].flat();
}

function defaultRecoveryGraph() {
  return globalThis.app?.graph || globalThis.graph || null;
}

function collectGraphNodes(graph) {
  const found = [];
  const seen = new Set();

  const visitNode = (node) => {
    if (!node || typeof node !== "object" || seen.has(node)) return;
    seen.add(node);
    found.push(node);

    const innerNodes = typeof node.getInnerNodes === "function" ? safeCall(() => node.getInnerNodes(new Map()), []) : [];
    for (const innerNode of iterableValues(innerNodes)) visitNode(innerNode);
    for (const subgraphNode of iterableValues(node.subgraph?._nodes ?? node.subgraph?.nodes ?? [])) visitNode(subgraphNode);
  };

  const graphNodes = graphNodesFor(graph);
  for (const node of iterableValues(graphNodes)) visitNode(node);
  return found;
}

function graphNodesFor(graph) {
  if (!graph) return [];
  if (typeof graph.computeExecutionOrder === "function") {
    const ordered = safeCall(() => graph.computeExecutionOrder(false), null);
    if (ordered) return ordered;
  }
  if (typeof graph.serialize === "function") {
    const serialized = safeCall(() => graph.serialize(), null);
    if (Array.isArray(serialized?.nodes)) return serialized.nodes;
  }
  return graph._nodes ?? graph.nodes ?? [];
}

function matchesRecoveryDescriptor(node, descriptor) {
  if (typeof descriptor.match === "function") {
    try {
      if (descriptor.match(node, descriptor) === true) return true;
    } catch {
      return false;
    }
  }
  if (!descriptor.nodeTypes.length) return false;
  const candidates = nodeTypeCandidates(node);
  return descriptor.nodeTypes.some((nodeType) => candidates.includes(nodeType));
}

function nodeTypeCandidates(node) {
  return uniqueStrings([
    node?.comfyClass,
    node?.type,
    node?.class_type,
    node?.className,
    node?.constructor?.type,
    node?.constructor?.name,
  ]);
}

function readPrivacyState(node, descriptor) {
  const privacy = descriptor.privacy;
  if (!privacy) return { enabled: false, missing: false, target: null };
  const target = getRecoveryTarget(node, privacy);
  const missing = !target.exists || target.get() === undefined || target.get() === null || target.get() === "";
  return {
    enabled: missing ? privacyValueEnabled(privacy.default) : privacyValueEnabled(target.get()),
    missing,
    target,
  };
}

function getRecoveryTarget(node, field) {
  return field.kind === "property"
    ? getPropertyTarget(node, field)
    : getWidgetTarget(node, field);
}

function getPropertyTarget(node, field) {
  const name = String(field.name);
  const exists = Object.prototype.hasOwnProperty.call(node?.properties || {}, name);
  return {
    exists,
    kind: "property",
    name,
    label: String(field.label || name),
    get: () => node?.properties?.[name],
    set: (value) => {
      if (!node || typeof node !== "object") return false;
      node.properties ??= {};
      const previous = node.properties[name];
      node.properties[name] = value;
      return previous !== value;
    },
  };
}

function getWidgetTarget(node, field) {
  const name = String(field.name);
  const widgets = Array.isArray(node?.widgets) ? node.widgets : [];
  const widget = widgets.find((item) => item?.name === name);
  const requestedIndex = Number.isInteger(field.index) ? field.index : field.widgetIndex;
  const index = Number.isInteger(requestedIndex) ? requestedIndex : (widget ? widgets.indexOf(widget) : -1);
  const hasSerializedIndex = Number.isInteger(index) && Array.isArray(node?.widgets_values) && index >= 0 && index < node.widgets_values.length;
  return {
    exists: Boolean(widget) || hasSerializedIndex,
    kind: "widget",
    name,
    label: String(field.label || name),
    get: () => (widget ? widget.value : node?.widgets_values?.[index]),
    set: (value) => {
      let changed = false;
      if (widget && widget.value !== value) {
        widget.value = value;
        changed = true;
      }
      if (hasSerializedIndex && node.widgets_values[index] !== value) {
        node.widgets_values[index] = value;
        changed = true;
      }
      return changed;
    },
  };
}

function createRecoveryIssue({ id, type, node, descriptor, field, target, message }) {
  const issue = {
    id,
    type,
    sourceId: descriptor.sourceId,
    descriptorId: descriptor.id,
    nodeId: node?.id ?? node?.node_id ?? null,
    nodeType: nodeTypeCandidates(node)[0] || "",
    nodeTitle: safeNodeTitle(node, descriptor),
    nodeLabel: descriptor.label,
    fieldKind: field?.kind || target?.kind || "",
    fieldName: field?.name || target?.name || "",
    fieldLabel: field?.label || target?.label || "",
    message,
    canReset: canResetFieldIssue(type, field),
    canReencrypt: Boolean(field && type === RECOVERY_ISSUE_TYPES.PLAINTEXT),
    canEnablePrivacy: type === RECOVERY_ISSUE_TYPES.MISSING_PRIVACY,
  };
  Object.defineProperties(issue, {
    _node: { value: node, enumerable: false },
    _descriptor: { value: descriptor, enumerable: false },
    _field: { value: field, enumerable: false },
    _target: { value: target, enumerable: false },
  });
  return issue;
}

function safeNodeTitle(node, descriptor) {
  return String(node?.title || node?.label || nodeTypeCandidates(node)[0] || descriptor.label || "Node");
}

function looksLikeEncryptedJson(value) {
  const payload = parsePrivacyEnvelope(value);
  return Boolean(
    payload
    && typeof payload === "object"
    && (
      payload.encrypted === true
      || payload.algorithm === PRIVACY_ENVELOPE_ALGORITHM
      || ("ciphertext" in payload && "nonce" in payload)
      || "keyId" in payload
    )
  );
}

function acceptedSchemas(field = {}, descriptor = {}) {
  return uniqueStrings([
    field.schema,
    ...(Array.isArray(field.schemas) ? field.schemas : []),
    descriptor.schema,
    descriptor.envelope?.schema,
    ...(Array.isArray(descriptor.schemas) ? descriptor.schemas : []),
    ...(Array.isArray(descriptor.envelope?.schemas) ? descriptor.envelope.schemas : []),
  ]);
}

function isUnsetOrDefaultValue(value, field, node) {
  if (value === undefined || value === null || value === "") return true;
  if (field.defaultValue !== undefined) {
    return canonicalPrivacyValue(value) === canonicalPrivacyValue(defaultFieldValue(field, node));
  }
  return false;
}

function defaultFieldValue(field, node) {
  if (typeof field.defaultValue === "function") {
    return safeCall(() => field.defaultValue(node, field), "");
  }
  return field.defaultValue;
}

function shouldEnablePrivacy(action, issue) {
  return issue.type === RECOVERY_ISSUE_TYPES.MISSING_PRIVACY
    && (action === "enable_privacy" || action === "all_safe_defaults" || action === "all");
}

function canResetFieldIssue(type, field) {
  if (!field || field.defaultValue === undefined) return false;
  if (field.resetOnlyForLegacy !== true) return true;
  return type === RECOVERY_ISSUE_TYPES.LEGACY_VALUE || type === RECOVERY_ISSUE_TYPES.INVALID_ENVELOPE;
}

function shouldResetField(action, issue) {
  if (!issue._field) return false;
  if (action === "reset" || action === "all_safe_defaults") return issue.canReset;
  if (action === "all") {
    return issue.type === RECOVERY_ISSUE_TYPES.LEGACY_VALUE || issue.type === RECOVERY_ISSUE_TYPES.INVALID_ENVELOPE;
  }
  return false;
}

function shouldReencryptField(action, issue) {
  return issue.type === RECOVERY_ISSUE_TYPES.PLAINTEXT && (action === "reencrypt" || action === "all");
}

function applyPrivacyDefault(issue) {
  const descriptor = issue._descriptor;
  const privacy = descriptor?.privacy;
  const target = issue._target;
  if (!privacy || !target) return false;
  const changed = target.set(privacy.default);
  clearDescriptorRuntimeState(issue._node, null, issue);
  return changed;
}

function applyFieldReset(issue) {
  const field = issue._field;
  const target = issue._target;
  const node = issue._node;
  if (!field || !target || field.defaultValue === undefined) return false;
  const changed = target.set(defaultFieldValue(field, node));
  forgetPrivacyEnvelope(node, field.name);
  clearRuntimeFieldState(node, field, issue);
  clearDescriptorRuntimeState(node, field, issue);
  return changed;
}

async function applyFieldReencrypt(issue, options) {
  const field = issue._field;
  const target = issue._target;
  const node = issue._node;
  const descriptor = issue._descriptor;
  if (!field || !target || !node) return false;
  const encrypt = encryptionHandlerFor(issue, options);
  const encrypted = await ensureEncryptedPrivacyValue({
    owner: node,
    fieldName: field.name,
    value: target.get(),
    canonicalValue: target.get(),
    privacyMode: true,
    encrypt,
    field,
    descriptor,
    context: { node, field, descriptor, issue },
  });
  const changed = target.set(encrypted);
  clearRuntimeFieldState(node, field, issue);
  clearDescriptorRuntimeState(node, field, issue);
  return changed;
}

function encryptionHandlerFor(issue, options) {
  const field = issue._field || {};
  const descriptor = issue._descriptor || {};
  const handler = field.reencrypt || field.encrypt || descriptor.reencrypt || descriptor.encrypt || options.reencrypt || options.encrypt;
  if (typeof handler !== "function") return null;
  return (plaintext) => handler(plaintext, {
    node: issue._node,
    field,
    descriptor,
    issue,
    token: getStoredPrivacyToken(),
  });
}

async function runFailClosedEncrypt(encrypt, plaintext, { promptUnlock = true, retryUnlock = true, context = {} } = {}) {
  try {
    return encryptedFromResponse(await encrypt(plaintext, context));
  } catch (error) {
    if (!promptUnlock || !retryUnlock || !isPrivacyUnlockRequiredError(error)) throw error;
    const unlocked = await showPrivacyKeystoreDialog("auto");
    if (!unlocked) {
      throw new PrivacyRecoveryError(
        "Privacy keystore was not unlocked, so encryption was blocked.",
        "PRIVACY_ENCRYPTION_UNAVAILABLE",
      );
    }
    return encryptedFromResponse(await encrypt(plaintext, context));
  }
}

function encryptedFromResponse(response) {
  if (typeof response === "string") return response;
  if (looksLikeEncryptedJson(response)) return response;
  return response?.encrypted ?? response?.data?.encrypted ?? response?.payload ?? response;
}

function clearRuntimeFieldState(node, field, issue) {
  const keys = uniqueStrings([
    field.runtimeProperty,
    ...(Array.isArray(field.runtimeProperties) ? field.runtimeProperties : []),
  ]);
  for (const key of keys) {
    try {
      delete node[key];
    } catch {
      /* Runtime cleanup is best-effort. */
    }
  }
  if (typeof field.clearRuntimeState === "function") {
    safeCall(() => field.clearRuntimeState(node, { field, issue }));
  }
}

function clearDescriptorRuntimeState(node, field, issue) {
  const descriptor = issue?._descriptor ?? field?._descriptor;
  if (typeof descriptor?.clearRuntimeState === "function") {
    safeCall(() => descriptor.clearRuntimeState(node, { field, issue }));
  }
}

function markRecoveryGraphDirty(node, graph) {
  node?.setDirtyCanvas?.(true, true);
  node?.graph?.setDirtyCanvas?.(true, true);
  graph?.setDirtyCanvas?.(true, true);
  globalThis.app?.graph?.setDirtyCanvas?.(true, true);
  globalThis.app?.canvas?.setDirty?.(true, true);
}

function summarizeRecoveryAction(issue, action) {
  return {
    id: issue.id,
    action,
    type: issue.type,
    nodeId: issue.nodeId,
    nodeTitle: issue.nodeTitle,
    nodeType: issue.nodeType,
    fieldKind: issue.fieldKind,
    fieldName: issue.fieldName,
    fieldLabel: issue.fieldLabel,
  };
}

function sanitizeErrorMessage(error) {
  const message = String(error?.message ?? error ?? "Privacy recovery failed.");
  const knownCode = [
    "PRIVACY_ENCRYPTION_UNAVAILABLE",
    "PRIVACY_ENCRYPTION_FAILED",
    "PRIVACY_LOCKED",
    "PRIVACY_TOKEN_REQUIRED",
    "PRIVACY_KEYSTORE_UNINITIALIZED",
    "PRIVACY_PASSWORD_INVALID",
  ].find((code) => message.includes(code));
  return knownCode ? message : "Privacy recovery failed for this field.";
}

function isPrivacyEncryptionUnavailable(error) {
  const message = String(error?.message ?? error ?? "");
  return (
    message.includes("PRIVACY_ENCRYPTION_UNAVAILABLE")
    || message.includes("PRIVACY_LOCKED")
    || message.includes("PRIVACY_TOKEN_REQUIRED")
    || message.includes("PRIVACY_KEYSTORE_UNINITIALIZED")
  );
}

function ownerKey(owner) {
  return owner && (typeof owner === "object" || typeof owner === "function") ? owner : FALLBACK_OWNER;
}

function fieldKey(fieldName) {
  return String(fieldName || "value");
}

function memoForOwner(owner, create = false) {
  const key = ownerKey(owner);
  let memo = OWNER_MEMOS.get(key);
  if (!memo && create) {
    memo = new Map();
    OWNER_MEMOS.set(key, memo);
  }
  return memo || null;
}

function stableJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => {
      const next = stableJsonValue(item);
      return next === undefined ? null : next;
    });
  }
  if (value && typeof value === "object") {
    const result = {};
    for (const key of Object.keys(value).sort()) {
      const next = stableJsonValue(value[key]);
      if (next !== undefined) result[key] = next;
    }
    return result;
  }
  if (typeof value === "function" || typeof value === "symbol" || value === undefined) return undefined;
  return value;
}

function stablePrivacyJsonStringify(value) {
  return JSON.stringify(stableJsonValue(value));
}

function canonicalPrivacyValue(value) {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  if (typeof value === "object") {
    const serialized = stablePrivacyJsonStringify(value);
    return serialized === undefined ? "" : serialized;
  }
  return String(value);
}

function privacyValueEnabled(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  const text = String(value ?? "").trim().toLowerCase();
  if (!text) return false;
  return !["0", "false", "off", "no", "none", "disabled"].includes(text);
}

function iterableValues(value) {
  if (!value) return [];
  if (value instanceof Map) return value.values();
  if (Array.isArray(value)) return value;
  if (typeof value[Symbol.iterator] === "function") return value;
  if (typeof value === "object") return Object.values(value);
  return [];
}

function uniqueStrings(values) {
  const result = [];
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const text = String(value);
    if (!result.includes(text)) result.push(text);
  }
  return result;
}

function safeCall(run, fallback = undefined) {
  try {
    return run();
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// Dialog
// ---------------------------------------------------------------------------

const MODES = {
  unlock: {
    title: "Unlock Privacy Keystore",
    hint: "Enter your privacy password. It stays unlocked until this computer restarts or you lock it.",
    fields: [{ name: "password", label: "Privacy password" }],
    action: "Unlock",
    run: (values) => unlockPrivacyKeystore(values.password),
  },
  setup: {
    title: "Set Privacy Password",
    hint: "Creates a password-protected keystore shared by all Helto node packs. Existing pack keys are imported so saved work stays readable.",
    fields: [
      { name: "password", label: "New privacy password" },
      { name: "confirm", label: "Repeat password" },
    ],
    action: "Create keystore",
    run: (values) => {
      if (values.password !== values.confirm) throw new Error("Passwords do not match.");
      return initializePrivacyKeystore(values.password);
    },
  },
  change: {
    title: "Change Privacy Password",
    hint: "Re-wraps the keystore with a new password. Encrypted data is unaffected.",
    fields: [
      { name: "current", label: "Current password" },
      { name: "password", label: "New privacy password" },
      { name: "confirm", label: "Repeat new password" },
    ],
    action: "Change password",
    run: (values) => {
      if (values.password !== values.confirm) throw new Error("Passwords do not match.");
      return changePrivacyKeystorePassword(values.current, values.password);
    },
  },
};

export function closePrivacyKeystoreDialog(documentRef = globalThis.document) {
  for (const dialog of documentRef?.querySelectorAll?.(`.${DIALOG_CLASS}`) ?? []) dialog.remove();
}

export function isPrivacyKeystoreDialogOpen(documentRef = globalThis.document) {
  return Boolean(documentRef?.querySelector?.(`.${DIALOG_CLASS}`));
}

export function closePrivacyRecoveryDialog(documentRef = globalThis.document) {
  for (const dialog of documentRef?.querySelectorAll?.(`.${RECOVERY_DIALOG_CLASS}`) ?? []) dialog.remove();
}

export function isPrivacyRecoveryDialogOpen(documentRef = globalThis.document) {
  return Boolean(documentRef?.querySelector?.(`.${RECOVERY_DIALOG_CLASS}`));
}

export function isUnreadablePrivacyResetDialogOpen(documentRef = globalThis.document) {
  return Boolean(documentRef?.querySelector?.(`.${UNREADABLE_DIALOG_CLASS}`));
}

export async function confirmUnreadablePrivacyReset({ documentRef = globalThis.document } = {}) {
  if (unreadableResetDialogPromise) return unreadableResetDialogPromise;
  if (!documentRef?.createElement || !documentRef.body) return false;
  installStyles(documentRef);

  const pending = new Promise((resolve) => {
    const overlay = documentRef.createElement("div");
    overlay.className = UNREADABLE_DIALOG_CLASS;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Unreadable encrypted values");
    overlay.tabIndex = -1;
    const previousFocus = documentRef.activeElement;
    const finish = (reset) => {
      overlay.remove();
      previousFocus?.focus?.();
      resolve(Boolean(reset));
    };

    const panel = documentRef.createElement("div");
    panel.className = "helto-privacy-keystore-panel helto-privacy-unreadable-panel";
    const title = documentRef.createElement("h3");
    title.textContent = "Encrypted values cannot be read";
    const hint = documentRef.createElement("p");
    hint.className = "helto-privacy-keystore-hint";
    hint.textContent = "The original encrypted values are still preserved. Resetting replaces the affected values with safe defaults and cannot be undone.";
    const actions = documentRef.createElement("div");
    actions.className = "helto-privacy-keystore-actions";
    const keepButton = documentRef.createElement("button");
    keepButton.type = "button";
    keepButton.textContent = "Keep encrypted values";
    const resetButton = documentRef.createElement("button");
    resetButton.type = "button";
    resetButton.className = "danger";
    resetButton.textContent = "Reset affected values";
    actions.append(keepButton, resetButton);
    panel.append(title, hint, actions);
    overlay.append(panel);

    keepButton.addEventListener("click", () => finish(false));
    resetButton.addEventListener("click", () => finish(true));
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) finish(false);
    });
    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        finish(false);
        return;
      }
      if (event.key === "Tab") trapFocus(event, overlay, documentRef);
      event.stopPropagation();
    });

    documentRef.body.append(overlay);
    keepButton.focus?.();
  });
  unreadableResetDialogPromise = pending;
  try {
    return await pending;
  } finally {
    if (unreadableResetDialogPromise === pending) unreadableResetDialogPromise = null;
  }
}

// Shows the dialog for `mode` ("unlock" | "setup" | "change"). Resolves with
// the endpoint result on success, or null when cancelled. `mode: "auto"`
// picks setup/unlock from keystore status and resolves immediately with the
// status when the keystore is already unlocked.
export async function showPrivacyKeystoreDialog(mode = "unlock", { documentRef = globalThis.document } = {}) {
  if (mode === "auto") {
    const status = await fetchPrivacyStatus();
    if (!status.keystoreInitialized) mode = "setup";
    else if (status.keystoreLocked) mode = "unlock";
    else return status;
  }
  const spec = MODES[mode] ?? MODES.unlock;
  if (!documentRef?.createElement || !documentRef.body) return null;
  installStyles(documentRef);
  closePrivacyKeystoreDialog(documentRef);

  return new Promise((resolve) => {
    const overlay = documentRef.createElement("div");
    overlay.className = DIALOG_CLASS;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", spec.title);
    overlay.tabIndex = -1;
    const previousFocus = documentRef.activeElement;
    const finish = (result) => {
      overlay.remove();
      previousFocus?.focus?.();
      resolve(result);
    };

    const panel = documentRef.createElement("div");
    panel.className = "helto-privacy-keystore-panel";

    const title = documentRef.createElement("h3");
    title.textContent = spec.title;
    const hint = documentRef.createElement("p");
    hint.className = "helto-privacy-keystore-hint";
    hint.textContent = spec.hint;
    panel.append(title, hint);

    const inputs = new Map();
    for (const field of spec.fields) {
      const label = documentRef.createElement("label");
      label.className = "helto-privacy-keystore-field";
      const caption = documentRef.createElement("span");
      caption.textContent = field.label;
      const input = documentRef.createElement("input");
      input.type = "password";
      input.autocomplete = "off";
      input.spellcheck = false;
      label.append(caption, input);
      panel.append(label);
      inputs.set(field.name, input);
    }

    const status = documentRef.createElement("div");
    status.className = "helto-privacy-keystore-status";
    const actions = documentRef.createElement("div");
    actions.className = "helto-privacy-keystore-actions";
    const cancelButton = documentRef.createElement("button");
    cancelButton.type = "button";
    cancelButton.textContent = "Cancel";
    const submitButton = documentRef.createElement("button");
    submitButton.type = "button";
    submitButton.className = "primary";
    submitButton.textContent = spec.action;
    actions.append(cancelButton, submitButton);
    panel.append(status, actions);
    overlay.append(panel);

    const submit = async () => {
      const values = {};
      for (const [name, input] of inputs) values[name] = input.value || "";
      submitButton.disabled = true;
      status.textContent = "Working...";
      try {
        const result = await spec.run(values);
        finish(result);
      } catch (error) {
        status.textContent = error.message || String(error);
        submitButton.disabled = false;
      }
    };

    submitButton.addEventListener("click", submit);
    cancelButton.addEventListener("click", () => finish(null));
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) finish(null);
    });
    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        finish(null);
        return;
      }
      if (event.key === "Enter" && event.target?.tagName === "INPUT") {
        event.preventDefault();
        submit();
      }
      if (event.key === "Tab") trapFocus(event, overlay, documentRef);
      event.stopPropagation();
    });

    documentRef.body.append(overlay);
    (inputs.values().next().value ?? overlay).focus?.();
  });
}

export async function showPrivacyRecoveryDialog(options = {}) {
  const {
    mode = "manual",
    graph = defaultRecoveryGraph(),
    documentRef = globalThis.document,
  } = options;
  const issues = scanPrivacyRecoveryIssues(graph);
  const model = buildPrivacyRecoveryDialogModel(issues);
  if (mode === "auto" && !issues.length) return { model, result: null };
  if (!documentRef?.createElement || !documentRef.body) return { model, result: null };
  installStyles(documentRef);
  closePrivacyRecoveryDialog(documentRef);

  return new Promise((resolve) => {
    const overlay = documentRef.createElement("div");
    overlay.className = RECOVERY_DIALOG_CLASS;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Privacy Recovery");
    overlay.tabIndex = -1;
    const previousFocus = documentRef.activeElement;
    const finish = (payload) => {
      overlay.remove();
      previousFocus?.focus?.();
      resolve(payload);
    };

    const panel = documentRef.createElement("div");
    panel.className = "helto-privacy-recovery-panel";
    overlay.append(panel);
    renderRecoveryDialogPanel(panel, model, documentRef);

    const status = documentRef.createElement("div");
    status.className = "helto-privacy-recovery-status";
    panel.append(status);

    const actions = documentRef.createElement("div");
    actions.className = "helto-privacy-keystore-actions helto-privacy-recovery-actions";
    panel.append(actions);

    const buttons = [];
    const addButton = (label, action, primary = false) => {
      const button = documentRef.createElement("button");
      button.type = "button";
      button.textContent = label;
      if (primary) button.className = "primary";
      button.addEventListener("click", async () => {
        for (const item of buttons) item.disabled = true;
        status.textContent = "Working...";
        try {
          const result = await recoverPrivacyIssues({ ...options, graph, issues, action });
          finish({ model: buildPrivacyRecoveryDialogModel(scanPrivacyRecoveryIssues(graph)), result });
        } catch (error) {
          status.textContent = sanitizeErrorMessage(error);
          for (const item of buttons) item.disabled = false;
        }
      });
      actions.append(button);
      buttons.push(button);
    };

    if (issues.length) {
      addButton("Re-encrypt", "reencrypt");
      addButton("Reset fields", "reset");
      addButton("Enable privacy", "enable_privacy");
      addButton("Safe defaults", "all_safe_defaults", true);
    }

    const closeButton = documentRef.createElement("button");
    closeButton.type = "button";
    closeButton.textContent = issues.length ? "Cancel" : "Close";
    closeButton.addEventListener("click", () => finish({ model, result: null }));
    actions.prepend(closeButton);
    buttons.push(closeButton);

    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) finish({ model, result: null });
    });
    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        finish({ model, result: null });
        return;
      }
      if (event.key === "Tab") trapFocus(event, overlay, documentRef);
      event.stopPropagation();
    });

    documentRef.body.append(overlay);
    (actions.querySelector("button.primary") ?? closeButton).focus?.();
  });
}

function renderRecoveryDialogPanel(panel, model, documentRef) {
  const title = documentRef.createElement("h3");
  title.textContent = "Privacy Recovery";
  const hint = documentRef.createElement("p");
  hint.className = "helto-privacy-keystore-hint";
  hint.textContent = model.totalIssues
    ? `${model.totalIssues} privacy issue${model.totalIssues === 1 ? "" : "s"} found.`
    : "No privacy recovery issues found.";
  panel.append(title, hint);

  if (!model.totalIssues) return;

  const counts = documentRef.createElement("div");
  counts.className = "helto-privacy-recovery-counts";
  for (const [type, count] of Object.entries(model.counts)) {
    const badge = documentRef.createElement("span");
    badge.textContent = `${count} ${recoveryTypeLabel(type)}`;
    counts.append(badge);
  }
  panel.append(counts);

  const list = documentRef.createElement("div");
  list.className = "helto-privacy-recovery-list";
  for (const node of model.nodes) {
    const item = documentRef.createElement("section");
    item.className = "helto-privacy-recovery-node";
    const heading = documentRef.createElement("h4");
    heading.textContent = node.nodeTitle || node.label || node.nodeType || "Node";
    item.append(heading);
    for (const issue of node.issues) {
      const row = documentRef.createElement("div");
      row.className = "helto-privacy-recovery-issue";
      const field = issue.fieldLabel || issue.fieldName || "Privacy setting";
      row.textContent = `${field}: ${recoveryTypeLabel(issue.type)}`;
      item.append(row);
    }
    list.append(item);
  }
  panel.append(list);
}

function recoveryTypeLabel(type) {
  return ({
    [RECOVERY_ISSUE_TYPES.LEGACY_VALUE]: "legacy value",
    [RECOVERY_ISSUE_TYPES.INVALID_ENVELOPE]: "invalid envelope",
    [RECOVERY_ISSUE_TYPES.PLAINTEXT]: "plaintext field",
    [RECOVERY_ISSUE_TYPES.MISSING_PRIVACY]: "missing privacy",
    [RECOVERY_ISSUE_TYPES.ENCRYPTION_UNAVAILABLE]: "encryption unavailable",
  })[type] || "privacy issue";
}

function trapFocus(event, overlay, documentRef) {
  const elements = [...overlay.querySelectorAll("button:not([disabled]), input:not([disabled])")];
  if (!elements.length) {
    event.preventDefault();
    return;
  }
  const first = elements[0];
  const last = elements[elements.length - 1];
  const active = documentRef?.activeElement;
  if (event.shiftKey && (active === first || active === overlay)) {
    event.preventDefault();
    last.focus?.();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus?.();
  }
}

function installStyles(documentRef) {
  if (!documentRef || documentRef.getElementById?.(STYLE_ID)) return;
  const style = documentRef.createElement("style");
  style.id = STYLE_ID;
  // Helto design tokens inlined (canonical source:
  // helto-designsystem/reference/tokens.css). Body-mounted overlays scope
  // their own token block. Gold = selection/primary, blue = focus ring only.
  style.textContent = `
    .${DIALOG_CLASS}, .${RECOVERY_DIALOG_CLASS}, .${UNREADABLE_DIALOG_CLASS} {
      --htd-bg: #0d1320; --htd-surface: #151c2a; --htd-surface-2: #1b2333; --htd-surface-3: #232d3f; --htd-surface-hover: #2c3850;
      --htd-border: #2a3346; --htd-border-strong: #3a465c; --htd-border-hover: #4c5970; --htd-text: #e7ebf3; --htd-text-dim: #9aa6bd; --htd-text-faint: #6f7c95;
      --htd-accent: #f1c75c; --htd-accent-strong: #ffd873; --htd-accent-border: rgba(241,199,92,0.55);
      --htd-focus: #5e9bff; --htd-ring: 0 0 0 2px rgba(94,155,255,0.5); --htd-danger: #f38ba8;
      --htd-danger-border: #96526a; --htd-danger-border-hover: #c56d8c; --htd-danger-gradient-start: #5c2c3d; --htd-danger-gradient-end: #482331; --htd-danger-gradient-hover-start: #6e3549; --htd-danger-gradient-hover-end: #5a2a3c; --htd-danger-text: #f9d4e0; --htd-danger-text-hover: #fdeef4;
      --htd-radius-sm: 5px; --htd-radius-lg: 10px; --htd-shadow-pop: 0 14px 36px rgba(0,0,0,0.55);
    }
    .${DIALOG_CLASS}, .${RECOVERY_DIALOG_CLASS}, .${UNREADABLE_DIALOG_CLASS} { position: fixed; inset: 0; z-index: 10090; display: flex; align-items: center; justify-content: center; background: rgba(6,9,15,0.72); backdrop-filter: blur(4px); color: var(--htd-text-dim); font: 12px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; -webkit-font-smoothing: antialiased; }
    .helto-privacy-keystore-panel { width: min(380px, calc(100vw - 28px)); display: flex; flex-direction: column; gap: 10px; background: linear-gradient(135deg, rgba(27,35,51,0.92), rgba(13,19,32,0.96)); border: 1px solid var(--htd-border-strong); border-radius: var(--htd-radius-lg); box-shadow: var(--htd-shadow-pop); padding: 16px; box-sizing: border-box; }
    .helto-privacy-keystore-panel h3 { margin: 0; font-size: 15px; font-weight: 700; color: var(--htd-text); }
    .helto-privacy-keystore-hint { margin: 0; color: var(--htd-text-dim); }
    .helto-privacy-keystore-field { display: grid; gap: 4px; color: var(--htd-text-faint); }
    .helto-privacy-keystore-field input { height: 30px; box-sizing: border-box; padding: 0 8px; background: var(--htd-bg); color: var(--htd-text); border: 1px solid var(--htd-border-strong); border-radius: var(--htd-radius-sm); font: inherit; transition: border-color .12s ease, box-shadow .12s ease; }
    .helto-privacy-keystore-field input:focus-visible { outline: none; border-color: var(--htd-focus); box-shadow: var(--htd-ring); }
    .helto-privacy-keystore-status { min-height: 16px; color: var(--htd-danger); }
    .helto-privacy-keystore-actions { display: flex; justify-content: flex-end; gap: 8px; }
    .helto-privacy-keystore-actions button { min-width: 88px; padding: 7px 14px; cursor: pointer; background: linear-gradient(180deg, var(--htd-surface-3), var(--htd-surface-2)); color: var(--htd-text); border: 1px solid var(--htd-border-strong); border-radius: var(--htd-radius-sm); font: inherit; transition: background .12s ease, border-color .12s ease, color .12s ease; }
    .helto-privacy-keystore-actions button:hover:not(:disabled) { background: linear-gradient(180deg, var(--htd-surface-hover), var(--htd-surface-3)); border-color: var(--htd-border-hover); color: #fff; }
    .helto-privacy-keystore-actions button:focus-visible { outline: none; border-color: var(--htd-focus); box-shadow: var(--htd-ring); }
    .helto-privacy-keystore-actions button:disabled { opacity: .48; cursor: not-allowed; }
    .helto-privacy-keystore-actions button.primary { border-color: var(--htd-accent-border); background: linear-gradient(180deg, #4f4322, #3c3318); color: var(--htd-accent-strong); }
    .helto-privacy-keystore-actions button.primary:hover:not(:disabled) { background: linear-gradient(180deg, #5b4d27, #46391b); color: #fff3cf; }
    .helto-privacy-keystore-actions button.danger { border-color: var(--htd-danger-border); background: linear-gradient(180deg, var(--htd-danger-gradient-start), var(--htd-danger-gradient-end)); color: var(--htd-danger-text); }
    .helto-privacy-keystore-actions button.danger:hover:not(:disabled) { border-color: var(--htd-danger-border-hover); background: linear-gradient(180deg, var(--htd-danger-gradient-hover-start), var(--htd-danger-gradient-hover-end)); color: var(--htd-danger-text-hover); }
    .helto-privacy-unreadable-panel { width: min(460px, calc(100vw - 28px)); }
    .helto-privacy-recovery-panel { width: min(520px, calc(100vw - 28px)); max-height: min(620px, calc(100vh - 32px)); display: flex; flex-direction: column; gap: 10px; background: linear-gradient(135deg, rgba(27,35,51,0.94), rgba(13,19,32,0.98)); border: 1px solid var(--htd-border-strong); border-radius: var(--htd-radius-lg); box-shadow: var(--htd-shadow-pop); padding: 16px; box-sizing: border-box; }
    .helto-privacy-recovery-panel h3 { margin: 0; font-size: 15px; font-weight: 700; color: var(--htd-text); }
    .helto-privacy-recovery-counts { display: flex; flex-wrap: wrap; gap: 6px; }
    .helto-privacy-recovery-counts span { border: 1px solid var(--htd-border); background: var(--htd-surface-2); color: var(--htd-text-dim); border-radius: var(--htd-radius-sm); padding: 3px 6px; }
    .helto-privacy-recovery-list { display: grid; gap: 8px; overflow: auto; padding-right: 2px; }
    .helto-privacy-recovery-node { display: grid; gap: 5px; border: 1px solid var(--htd-border); background: rgba(13,19,32,0.58); border-radius: var(--htd-radius-sm); padding: 8px; }
    .helto-privacy-recovery-node h4 { margin: 0; color: var(--htd-text); font-size: 12px; font-weight: 650; }
    .helto-privacy-recovery-issue { color: var(--htd-text-dim); overflow-wrap: anywhere; }
    .helto-privacy-recovery-status { min-height: 16px; color: var(--htd-danger); }
    .helto-privacy-recovery-actions { flex-wrap: wrap; }
  `;
  documentRef.head?.append(style);
}
