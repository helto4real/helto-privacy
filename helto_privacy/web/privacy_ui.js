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

import {
  PrivacyBrowserRequestError,
  changePrivacyKeystorePassword,
  ensureStoredPrivacyTokenCookie,
  fetchPrivacyStatus,
  initializePrivacyKeystore,
  isPrivacyLockedError,
  isPrivacySetupRequiredError,
  isPrivacyUnlockRequiredError,
  lockPrivacyKeystore,
  privacySessionSnapshot,
  subscribePrivacySession,
  unlockPrivacyKeystore,
} from "./privacy_client.js";

export { redactPrivateRecordShell } from "./privacy_records.js";
export {
  PrivacyArtifactLeaseError,
  normalizeArtifactLease,
  resolveArtifactLeaseURL,
} from "./privacy_artifacts.js";

export {
  PrivacyBrowserRequestError,
  changePrivacyKeystorePassword,
  ensureStoredPrivacyTokenCookie,
  fetchPrivacyStatus,
  initializePrivacyKeystore,
  isPrivacyLockedError,
  isPrivacySetupRequiredError,
  isPrivacyUnlockRequiredError,
  lockPrivacyKeystore,
  subscribePrivacySession,
  unlockPrivacyKeystore,
} from "./privacy_client.js";

const PRIVACY_ENVELOPE_ALGORITHM = "AES-256-GCM";
const LEGACY_ENCRYPTED_PREFIX = "__HELTO_ENC__:";
const DIALOG_CLASS = "helto-privacy-keystore-dialog";
const RECOVERY_DIALOG_CLASS = "helto-privacy-recovery-dialog";
const RECORD_MUTATION_DIALOG_CLASS = "helto-privacy-record-mutation-dialog";
const STYLE_ID = "helto-privacy-keystore-ui-style";
const SHARED_SURFACE_ID = "helto-privacy-surface";
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
const SHARED_PRIVACY_SURFACES = new WeakMap();
const OPEN_MODAL_CLOSERS = new WeakMap();

// Destructively remove concealed content from the DOM. The caller must fetch
// and render it again only after an authorized reveal; this module never keeps
// a plaintext copy for hover, focus, or later restoration.
export function concealPrivacyContent(element, { mode = "collapsed" } = {}) {
  if (!element || typeof element !== "object") return false;
  const tagName = String(element.tagName || "").toUpperCase();
  if (tagName === "INPUT" || tagName === "TEXTAREA") {
    element.value = "";
    element.placeholder = "";
    element.name = "";
  } else if (typeof element.replaceChildren === "function") {
    element.replaceChildren();
    element.textContent = "";
  } else {
    element.textContent = "";
  }
  for (const attribute of [
    "value", "placeholder", "name", "src", "srcset", "alt", "title",
    "aria-label", "aria-description", "data-tooltip",
  ]) element.removeAttribute?.(attribute);
  element.setAttribute?.("aria-hidden", "true");
  element.inert = true;
  element.blur?.();
  addPrivacyClass(
    element,
    mode === "masked" ? "helto-text-masked" : "helto-hidden-collapsed",
  );
  return true;
}

export function preparePrivacyReveal(element) {
  if (!element || typeof element !== "object") return false;
  element.removeAttribute?.("aria-hidden");
  element.inert = false;
  removePrivacyClass(element, "helto-text-masked");
  removePrivacyClass(element, "helto-hidden-collapsed");
  return true;
}

function addPrivacyClass(element, className) {
  const classes = new Set(String(element.className || "").split(/\s+/).filter(Boolean));
  classes.add(className);
  element.className = [...classes].join(" ");
}

function removePrivacyClass(element, className) {
  element.className = String(element.className || "")
    .split(/\s+/)
    .filter((item) => item && item !== className)
    .join(" ");
}

// ---------------------------------------------------------------------------
// One shared status, recovery, and mode surface for every attested pack
// ---------------------------------------------------------------------------

export function mountSharedPrivacySurface({
  packId,
  readiness,
  modeScopes = [],
  modeClient,
  documentRef = globalThis.document,
  fetchStatus = fetchPrivacyStatus,
}) {
  const id = String(packId || "").trim();
  if (
    !documentRef?.createElement
    || !documentRef.body
    || !/^[a-z0-9][a-z0-9._-]*$/.test(id)
    || modeClient?.id !== id
    || typeof modeClient.readAll !== "function"
    || typeof modeClient.transition !== "function"
    || typeof fetchStatus !== "function"
  ) return null;

  let controller = SHARED_PRIVACY_SURFACES.get(documentRef);
  if (!controller) {
    installStyles(documentRef);
    controller = createSharedPrivacySurface(documentRef, fetchStatus);
    SHARED_PRIVACY_SURFACES.set(documentRef, controller);
  }
  controller.registerPack({
    packId: id,
    readiness: String(readiness || "blocked"),
    modeScopes,
    modeClient,
  });
  return controller.public;
}

function createSharedPrivacySurface(documentRef, fetchStatus) {
  const root = documentRef.createElement("section");
  root.id = SHARED_SURFACE_ID;
  root.className = "helto-root helto-privacy-surface";
  root.setAttribute("role", "region");
  root.setAttribute("aria-label", "Helto privacy");
  const initialSession = privacySessionSnapshot();
  root.setAttribute("data-session-state", initialSession.state);
  documentRef.body.append(root);

  const state = {
    documentRef,
    fetchStatus,
    status: null,
    sessionState: initialSession.state,
    packs: new Map(),
    expanded: false,
    refreshing: false,
  };

  const controller = {
    registerPack(pack) {
      state.packs.set(pack.packId, {
        ...pack,
        modeScopes: normalizeBrowserModeScopes(pack.modeScopes),
        resolvedScopes: [],
        error: "",
        transitionError: "",
      });
      renderSharedPrivacySurface(state, controller.public);
    },
    async refresh() {
      if (state.refreshing) return state.refreshing;
      state.refreshing = (async () => {
        try {
          state.status = await state.fetchStatus();
        } catch {
          state.status = { ok: false, error: "PRIVACY_STATUS_UNAVAILABLE" };
        }
        await Promise.all([...state.packs.values()].map(async (pack) => {
          try {
            const result = await pack.modeClient.readAll();
            pack.resolvedScopes = Array.isArray(result?.scopes) ? result.scopes : [];
            pack.error = "";
          } catch {
            pack.resolvedScopes = [];
            pack.error = "Unavailable";
          }
        }));
        renderSharedPrivacySurface(state, controller.public);
      })().finally(() => {
        state.refreshing = false;
      });
      return state.refreshing;
    },
    async transition(packIdValue, scopeId, target) {
      const pack = state.packs.get(String(packIdValue || ""));
      const scope = pack?.modeScopes.find((item) => item.id === scopeId);
      if (!pack || !scope || !["inherit", "private", "public"].includes(target)) {
        throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_INVALID");
      }
      if (pack.readiness !== "ready" || state.status?.suiteStatus !== "active") {
        throw new PrivacyBrowserRequestError("PRIVACY_SUITE_BLOCKED", 409);
      }
      try {
        const result = await pack.modeClient.transition(
          scopeId,
          target,
        );
        if (result === null) return null;
        pack.transitionError = "";
        await controller.refresh();
        return result;
      } catch {
        pack.transitionError = "Transition failed";
        await controller.refresh();
        renderSharedPrivacySurface(state, controller.public);
        throw new PrivacyBrowserRequestError("PRIVACY_MODE_TRANSITION_FAILED");
      }
    },
    public: null,
  };
  controller.public = Object.freeze({
    root,
    refresh: () => controller.refresh(),
    transition: (packIdValue, scopeId, target) => (
      controller.transition(packIdValue, scopeId, target)
    ),
  });
  subscribePrivacySession((session) => {
    state.sessionState = session.state;
    root.setAttribute("data-session-state", session.state);
    renderSharedPrivacySurface(state, controller.public);
  }, { emitCurrent: true });
  renderSharedPrivacySurface(state, controller.public);
  return controller;
}

function normalizeBrowserModeScopes(scopes) {
  if (!Array.isArray(scopes)) return [];
  return scopes.flatMap((scope) => {
    const id = String(scope?.id || "");
    const modeResourceId = String(scope?.modeResourceId || "");
    return /^[a-z0-9][a-z0-9._-]*$/.test(id)
      && /^[a-z0-9][a-z0-9._-]*$/.test(modeResourceId)
      ? [Object.freeze({ id, modeResourceId })]
      : [];
  });
}

function renderSharedPrivacySurface(state, surface) {
  const { documentRef, status } = state;
  const header = documentRef.createElement("div");
  header.className = "helto-toolbar helto-privacy-surface-header";
  const title = documentRef.createElement("strong");
  title.textContent = "Privacy";
  const session = documentRef.createElement("span");
  session.className = `helto-pill ${state.sessionState === "unlocked" ? "is-ok" : "is-warn"}`;
  session.textContent = state.sessionState === "unlocked" ? "Unlocked" : "Locked";
  const toggle = createSurfaceButton(documentRef, state.expanded ? "Close" : "Open", "surface-toggle");
  toggle.setAttribute("aria-expanded", String(state.expanded));
  toggle.addEventListener("click", () => {
    state.expanded = !state.expanded;
    renderSharedPrivacySurface(state, surface);
  });
  header.append(title, session, toggle);

  const panel = documentRef.createElement("div");
  panel.className = "helto-panel helto-privacy-surface-panel";
  panel.hidden = !state.expanded;

  const statusLine = documentRef.createElement("div");
  statusLine.className = "helto-privacy-status";
  if (!status) statusLine.textContent = "Privacy status not checked.";
  else if (status.ok === false) statusLine.textContent = "Privacy status unavailable.";
  else if (status.suiteStatus !== "active") statusLine.textContent = "Blocked installation";
  else if (!status.keystoreInitialized) statusLine.textContent = "Set up privacy to continue.";
  else if (status.keystoreLocked) statusLine.textContent = "Privacy is locked.";
  else statusLine.textContent = "Privacy is ready.";
  panel.append(statusLine);

  const actions = documentRef.createElement("div");
  actions.className = "helto-toolbar helto-privacy-surface-actions";
  const actionSpecs = [
    ["Set up", "setup", () => showPrivacyKeystoreDialog("setup", { documentRef })],
    ["Unlock", "unlock", () => showPrivacyKeystoreDialog("unlock", { documentRef })],
    ["Change password", "change-password", () => showPrivacyKeystoreDialog("change", { documentRef })],
    ["Lock", "lock", () => lockPrivacyKeystore()],
    ["Recovery", "recovery", () => showPrivacyRecoveryDialog({ documentRef })],
  ];
  for (const [label, action, handler] of actionSpecs) {
    const button = createSurfaceButton(documentRef, label, action);
    if (action === "setup") button.className += " is-primary";
    button.disabled = ["setup", "unlock", "change-password"].includes(action)
      && (!status || status.suiteStatus !== "active");
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await handler();
        await surface.refresh();
      } finally {
        button.disabled = false;
      }
    });
    actions.append(button);
  }
  panel.append(actions);

  const packs = documentRef.createElement("div");
  packs.className = "helto-privacy-pack-list helto-scroll";
  for (const pack of [...state.packs.values()].sort((a, b) => a.packId.localeCompare(b.packId))) {
    packs.append(renderSharedPrivacyPack(state, surface, pack));
  }
  panel.append(packs);
  rootReplaceChildren(state, header, panel);
}

function renderSharedPrivacyPack(state, surface, pack) {
  const card = state.documentRef.createElement("section");
  card.className = "helto-inset helto-privacy-pack";
  const heading = state.documentRef.createElement("h3");
  heading.textContent = pack.packId;
  const readiness = state.documentRef.createElement("span");
  readiness.className = `helto-pill ${pack.readiness === "ready" ? "is-ok" : "is-blocked"}`;
  readiness.textContent = pack.readiness === "ready" ? "Ready" : "Blocked";
  card.append(heading, readiness);
  if (pack.error) {
    const unavailable = state.documentRef.createElement("p");
    unavailable.textContent = "Unavailable";
    card.append(unavailable);
    return card;
  }
  if (pack.transitionError) {
    const failed = state.documentRef.createElement("p");
    failed.className = "helto-privacy-transition-error";
    failed.setAttribute("role", "status");
    failed.textContent = "Privacy mode transition failed.";
    card.append(failed);
  }
  for (const declaredScope of pack.modeScopes) {
    const scope = pack.resolvedScopes.find((item) => item.id === declaredScope.id);
    const row = state.documentRef.createElement("div");
    row.className = "helto-privacy-mode-row";
    const scopeName = state.documentRef.createElement("span");
    scopeName.textContent = declaredScope.id;
    const effective = state.documentRef.createElement("span");
    effective.className = "helto-pill is-active";
    effective.textContent = scope?.effective === "public" ? "Public" : "Private";
    const inherited = state.documentRef.createElement("span");
    inherited.textContent = scope?.declared === "inherit" ? "Inherited" : "Explicit";
    const select = state.documentRef.createElement("select");
    select.className = "helto-select";
    select.setAttribute("aria-label", `Privacy mode for ${declaredScope.id}`);
    for (const value of ["inherit", "private", "public"]) {
      const option = state.documentRef.createElement("option");
      option.value = value;
      option.textContent = value[0].toUpperCase() + value.slice(1);
      select.append(option);
    }
    select.value = scope?.declared || "inherit";
    const apply = createSurfaceButton(state.documentRef, "Apply", "mode-transition");
    apply.disabled = pack.readiness !== "ready" || state.status?.suiteStatus !== "active";
    apply.addEventListener("click", async () => {
      apply.disabled = true;
      try {
        await surface.transition(pack.packId, declaredScope.id, select.value);
      } catch {
        /* The shared surface renders the fixed transition failure state. */
      } finally {
        apply.disabled = false;
      }
    });
    row.append(scopeName, effective, inherited, select, apply);
    card.append(row);
    const metadata = state.documentRef.createElement("div");
    metadata.className = "helto-privacy-mode-metadata";
    const source = safeModeMetadata(scope?.inheritedFrom, "unavailable");
    const transitionStatus = safeModeMetadata(scope?.transitionStatus, "unavailable");
    const transition = state.documentRef.createElement("span");
    transition.textContent = `Source: ${source} · Transition: ${transitionStatus}`;
    const floors = state.documentRef.createElement("span");
    const safeFloors = Array.isArray(scope?.floors)
      ? scope.floors.flatMap((floor) => {
        const kind = safeModeMetadata(floor?.kind, "");
        const sourceId = safeModeMetadata(floor?.sourceId, "");
        return kind && sourceId ? [`${kind}: ${sourceId}`] : [];
      })
      : [];
    floors.textContent = safeFloors.length
      ? `Active floors: ${safeFloors.join(", ")}`
      : "No active floors";
    metadata.append(transition, floors);
    card.append(metadata);
  }
  return card;
}

function safeModeMetadata(value, fallback) {
  const normalized = String(value || "").trim().toLowerCase();
  return /^[a-z0-9][a-z0-9._-]*$/.test(normalized) ? normalized : fallback;
}

function createSurfaceButton(documentRef, label, action) {
  const button = documentRef.createElement("button");
  button.type = "button";
  button.className = "helto-button";
  button.textContent = label;
  button.setAttribute("data-action", action);
  return button;
}

function rootReplaceChildren(state, ...children) {
  if (typeof state.documentRef.getElementById(SHARED_SURFACE_ID)?.replaceChildren === "function") {
    state.documentRef.getElementById(SHARED_SURFACE_ID).replaceChildren(...children);
  }
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
    nodeTitle: safeNodeTitle(node),
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

function safeNodeTitle(node) {
  const numericId = Number.isInteger(node?.id)
    ? node.id
    : (Number.isInteger(node?.node_id) ? node.node_id : null);
  return numericId === null ? "Privacy node" : `Privacy node ${numericId}`;
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
  const code = String(error?.code || "");
  const message = String(error?.message ?? error ?? "");
  const knownCode = [
    "PRIVACY_ENCRYPTION_UNAVAILABLE",
    "PRIVACY_ENCRYPTION_FAILED",
    "PRIVACY_LOCKED",
    "PRIVACY_TOKEN_REQUIRED",
    "PRIVACY_KEYSTORE_UNINITIALIZED",
    "PRIVACY_PASSWORD_INVALID",
  ].find((candidate) => code === candidate || message.includes(candidate));
  return privacyUiErrorLabel(knownCode, "Privacy recovery failed for this field.");
}

function isPrivacyEncryptionUnavailable(error) {
  const code = String(error?.code || "");
  const message = String(error?.message ?? error ?? "");
  return (
    [
      "PRIVACY_ENCRYPTION_UNAVAILABLE",
      "PRIVACY_LOCKED",
      "PRIVACY_TOKEN_REQUIRED",
      "PRIVACY_KEYSTORE_UNINITIALIZED",
    ].includes(code)
    || message.includes("PRIVACY_ENCRYPTION_UNAVAILABLE")
    || message.includes("PRIVACY_LOCKED")
    || message.includes("PRIVACY_TOKEN_REQUIRED")
    || message.includes("PRIVACY_KEYSTORE_UNINITIALIZED")
  );
}

function privacyUiErrorLabel(code, fallback = "Privacy operation failed.") {
  return ({
    PRIVACY_PASSWORD_INVALID: "The privacy password was not accepted.",
    PRIVACY_LOCKED: "Privacy is locked.",
    PRIVACY_TOKEN_REQUIRED: "Privacy must be unlocked again.",
    PRIVACY_KEYSTORE_UNINITIALIZED: "Privacy setup is required.",
    PRIVACY_ENCRYPTION_UNAVAILABLE: "Privacy encryption is unavailable.",
    PRIVACY_ENCRYPTION_FAILED: "Privacy encryption failed.",
  })[code] || fallback;
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

function closePrivacyModal(documentRef, dialogClass) {
  const closers = documentRef && OPEN_MODAL_CLOSERS.get(documentRef);
  const close = closers?.get(dialogClass);
  if (close) {
    close();
    return;
  }
  for (const dialog of documentRef?.querySelectorAll?.(`.${dialogClass}`) ?? []) {
    dialog.remove();
  }
}

function createPrivacyModalScaffold({
  documentRef,
  dialogClass,
  ariaLabel,
  panelClass,
  cancelResult,
  resolve,
}) {
  installStyles(documentRef);
  closePrivacyModal(documentRef, dialogClass);

  const overlay = documentRef.createElement("div");
  overlay.className = `${dialogClass} helto-root helto-overlay`;
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", ariaLabel);
  overlay.tabIndex = -1;
  const panel = documentRef.createElement("div");
  panel.className = `${panelClass} helto-modal`;
  overlay.append(panel);
  const previousFocus = documentRef.activeElement;
  let settled = false;
  let close;
  const finish = (result) => {
    if (settled) return;
    settled = true;
    const closers = OPEN_MODAL_CLOSERS.get(documentRef);
    if (closers?.get(dialogClass) === close) closers.delete(dialogClass);
    overlay.remove();
    previousFocus?.focus?.();
    resolve(result);
  };
  close = () => finish(cancelResult);
  let closers = OPEN_MODAL_CLOSERS.get(documentRef);
  if (!closers) {
    closers = new Map();
    OPEN_MODAL_CLOSERS.set(documentRef, closers);
  }
  closers.set(dialogClass, close);

  const activate = ({ initialFocus = overlay, onKeydown = null } = {}) => {
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) finish(cancelResult);
    });
    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        finish(cancelResult);
      } else if (event.key === "Tab") {
        trapFocus(event, overlay, documentRef);
      } else {
        onKeydown?.(event);
      }
      event.stopPropagation();
    });
    documentRef.body.append(overlay);
    (initialFocus ?? overlay).focus?.();
  };

  return { panel, finish, activate };
}

export function closePrivacyKeystoreDialog(documentRef = globalThis.document) {
  closePrivacyModal(documentRef, DIALOG_CLASS);
}

export function isPrivacyKeystoreDialogOpen(documentRef = globalThis.document) {
  return Boolean(documentRef?.querySelector?.(`.${DIALOG_CLASS}`));
}

export function closePrivacyRecoveryDialog(documentRef = globalThis.document) {
  closePrivacyModal(documentRef, RECOVERY_DIALOG_CLASS);
}

export function isPrivacyRecoveryDialogOpen(documentRef = globalThis.document) {
  return Boolean(documentRef?.querySelector?.(`.${RECOVERY_DIALOG_CLASS}`));
}

export function showPrivateRecordMutationDialog(
  operation,
  { documentRef = globalThis.document } = {},
) {
  const action = operation === "delete"
    ? { title: "Delete private record", button: "Delete" }
    : operation === "replace"
      ? { title: "Replace private record", button: "Replace" }
      : null;
  if (!action || !documentRef?.createElement || !documentRef.body) {
    return Promise.resolve(false);
  }

  return new Promise((resolve) => {
    const modal = createPrivacyModalScaffold({
      documentRef,
      dialogClass: RECORD_MUTATION_DIALOG_CLASS,
      ariaLabel: action.title,
      panelClass: "helto-privacy-record-mutation-panel",
      cancelResult: false,
      resolve,
    });
    const { panel, finish, activate } = modal;
    const header = documentRef.createElement("header");
    const title = documentRef.createElement("h3");
    title.textContent = action.title;
    header.append(title);
    const body = documentRef.createElement("div");
    body.className = "helto-privacy-record-mutation-body";
    const message = documentRef.createElement("p");
    message.textContent = "This destructive action cannot reveal or recover the record contents.";
    body.append(message);
    const footer = documentRef.createElement("footer");
    footer.className = "helto-privacy-record-mutation-actions";
    const cancelButton = documentRef.createElement("button");
    cancelButton.type = "button";
    cancelButton.className = "helto-button";
    cancelButton.textContent = "Cancel";
    const confirmButton = documentRef.createElement("button");
    confirmButton.type = "button";
    confirmButton.className = "helto-button is-danger";
    confirmButton.textContent = action.button;
    footer.append(cancelButton, confirmButton);
    panel.append(header, body, footer);

    cancelButton.addEventListener("click", () => finish(false));
    confirmButton.addEventListener("click", () => finish(true));
    activate({ initialFocus: cancelButton });
  });
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

  return new Promise((resolve) => {
    const modal = createPrivacyModalScaffold({
      documentRef,
      dialogClass: DIALOG_CLASS,
      ariaLabel: spec.title,
      panelClass: "helto-privacy-keystore-panel",
      cancelResult: null,
      resolve,
    });
    const { panel, finish, activate } = modal;

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
      input.className = "helto-field";
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
    cancelButton.className = "helto-button";
    cancelButton.textContent = "Cancel";
    const submitButton = documentRef.createElement("button");
    submitButton.type = "button";
    submitButton.className = "helto-button is-primary primary";
    submitButton.textContent = spec.action;
    actions.append(cancelButton, submitButton);
    panel.append(status, actions);

    const submit = async () => {
      const values = {};
      for (const [name, input] of inputs) values[name] = input.value || "";
      submitButton.disabled = true;
      status.textContent = "Working...";
      try {
        const result = await spec.run(values);
        finish(result);
      } catch (error) {
        status.textContent = privacyUiErrorLabel(
          String(error?.code || ""),
          "Privacy operation failed.",
        );
        submitButton.disabled = false;
      }
    };

    submitButton.addEventListener("click", submit);
    cancelButton.addEventListener("click", () => finish(null));
    activate({
      initialFocus: inputs.values().next().value,
      onKeydown: (event) => {
        if (event.key === "Enter" && event.target?.tagName === "INPUT") {
          event.preventDefault();
          submit();
        }
      },
    });
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

  return new Promise((resolve) => {
    const cancelled = { model, result: null };
    const modal = createPrivacyModalScaffold({
      documentRef,
      dialogClass: RECOVERY_DIALOG_CLASS,
      ariaLabel: "Privacy Recovery",
      panelClass: "helto-privacy-recovery-panel",
      cancelResult: cancelled,
      resolve,
    });
    const { panel, finish, activate } = modal;
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
      button.className = primary
        ? "helto-button is-primary primary"
        : "helto-button";
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
    closeButton.className = "helto-button";
    closeButton.textContent = issues.length ? "Cancel" : "Close";
    closeButton.addEventListener("click", () => finish(cancelled));
    actions.prepend(closeButton);
    buttons.push(closeButton);

    activate({ initialFocus: actions.querySelector("button.primary") ?? closeButton });
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
  // Canonical Helto tokens and component recipes. Gold is active/primary;
  // blue is focus only. Concealment rules intentionally retain !important.
  style.textContent = `
    :root {
      --helto-bg: #181825; --helto-surface: #1e1e2e; --helto-surface-2: #313244;
      --helto-surface-3: #45475a; --helto-surface-hover: #585b70;
      --helto-border: #313244; --helto-border-strong: #45475a; --helto-border-hover: #6c7086;
      --helto-text: #cdd6f4; --helto-text-dim: #a6adc8; --helto-text-faint: #7f849c;
      --helto-accent: #fab387; --helto-accent-strong: #fddcc4; --helto-accent-border: #93664a;
      --helto-accent-bg: #46301f; --helto-focus: #89b4fa;
      --helto-focus-ring: 0 0 0 3px rgba(137, 180, 250, 0.28);
      --helto-danger: #f38ba8; --helto-danger-border: #96526a; --helto-ok: #a6e3a1;
      --helto-warn: #f9e2af; --helto-info: #74c7ec;
      --helto-radius-sm: 5px; --helto-radius: 6px; --helto-radius-lg: 10px;
      --helto-shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
      --helto-shadow-pop: 0 12px 32px rgba(0, 0, 0, 0.5);
      --helto-transition: 0.12s ease;
      --helto-font-sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      --helto-font-size: 12px; --helto-line: 1.4;
    }
    .helto-root { box-sizing: border-box; color: var(--helto-text); font: var(--helto-font-size) / var(--helto-line) var(--helto-font-sans); -webkit-font-smoothing: antialiased; }
    .helto-root *, .helto-root *::before, .helto-root *::after { box-sizing: border-box; }
    .helto-panel { background: var(--helto-surface); border: 1px solid var(--helto-border); border-radius: var(--helto-radius); box-shadow: var(--helto-shadow); padding: 9px; }
    .helto-inset { background: var(--helto-bg); border: 1px solid var(--helto-border); border-radius: var(--helto-radius); }
    .helto-toolbar { display: flex; align-items: center; gap: 6px; min-height: 34px; padding: 5px; border-radius: var(--helto-radius); background: linear-gradient(180deg, var(--helto-surface-2), var(--helto-surface)); box-shadow: inset 0 0 0 1px var(--helto-border); }
    .helto-button { min-width: 28px; height: 24px; padding: 0 8px; display: inline-flex; align-items: center; justify-content: center; gap: 6px; border: 1px solid var(--helto-border-strong); border-radius: var(--helto-radius-sm); background: linear-gradient(180deg, var(--helto-surface-3), var(--helto-surface-2)); color: var(--helto-text); font: inherit; white-space: nowrap; cursor: pointer; transition: background var(--helto-transition), border-color var(--helto-transition), color var(--helto-transition), box-shadow var(--helto-transition); }
    .helto-button:hover:not(:disabled) { background: linear-gradient(180deg, var(--helto-surface-hover), var(--helto-surface-3)); border-color: var(--helto-border-hover); color: #e6ebf9; }
    .helto-button:disabled { opacity: .4; cursor: not-allowed; }
    .helto-button.is-primary, .helto-button.is-active { border-color: var(--helto-accent-border); background: linear-gradient(180deg, #4f3a2a, #3d2d20); color: var(--helto-accent-strong); }
    .helto-button.is-danger { border-color: var(--helto-danger-border); background: linear-gradient(180deg, #51293a, #3a2130); color: #f6cadb; }
    .helto-button.is-danger:hover:not(:disabled) { border-color: #b5627f; background: linear-gradient(180deg, #653247, #4a2637); color: #ffe4ee; }
    .helto-button:focus-visible, .helto-field:focus, .helto-select:focus { outline: none; border-color: var(--helto-focus); box-shadow: var(--helto-focus-ring); }
    .helto-field { height: 26px; padding: 0 8px; border: 1px solid var(--helto-border-strong); border-radius: var(--helto-radius-sm); background: var(--helto-surface-2); color: var(--helto-text); font: inherit; }
    .helto-select { height: 24px; min-width: 72px; padding: 0 8px; border: 1px solid var(--helto-border-strong); border-radius: var(--helto-radius-sm); background: var(--helto-surface-2); color: var(--helto-text); font: inherit; cursor: pointer; }
    .helto-pill { height: 24px; display: inline-flex; align-items: center; padding: 0 9px; border: 1px solid var(--helto-border-strong); border-radius: 999px; background: var(--helto-surface-2); color: #bac2de; font-weight: 600; white-space: nowrap; }
    .helto-pill.is-ok { border-color: #4f7050; background: #223423; color: var(--helto-ok); }
    .helto-pill.is-warn { border-color: #7d7147; background: #363019; color: var(--helto-warn); }
    .helto-pill.is-blocked { border-color: var(--helto-danger-border); background: #3a2130; color: #f6cadb; }
    .helto-pill.is-active { border-color: var(--helto-accent-border); color: var(--helto-accent-strong); }
    .helto-overlay, .${DIALOG_CLASS}, .${RECOVERY_DIALOG_CLASS}, .${RECORD_MUTATION_DIALOG_CLASS} { position: fixed; inset: 0; z-index: 10090; display: flex; align-items: center; justify-content: center; padding: 12px; background: rgba(17, 17, 27, .72); backdrop-filter: blur(4px); }
    .helto-modal { display: flex; flex-direction: column; overflow: hidden; border: 1px solid var(--helto-border-strong); border-radius: var(--helto-radius-lg); background: linear-gradient(135deg, rgba(49, 50, 68, .92), rgba(24, 24, 37, .96)); box-shadow: var(--helto-shadow-pop); padding: 16px; }
    .helto-privacy-keystore-panel { width: min(380px, calc(100vw - 28px)); gap: 10px; }
    .helto-privacy-recovery-panel { width: min(520px, calc(100vw - 28px)); max-height: min(620px, calc(100vh - 32px)); gap: 10px; }
    .helto-privacy-record-mutation-panel { width: min(420px, calc(100vw - 28px)); padding: 0; }
    .helto-privacy-keystore-panel h3, .helto-privacy-recovery-panel h3, .helto-privacy-record-mutation-panel h3 { margin: 0; font-size: 15px; color: var(--helto-text); }
    .helto-privacy-record-mutation-panel header, .helto-privacy-record-mutation-body, .helto-privacy-record-mutation-actions { padding: 14px 16px; }
    .helto-privacy-record-mutation-body { color: var(--helto-text-dim); }
    .helto-privacy-record-mutation-body p { margin: 0; }
    .helto-privacy-record-mutation-actions { display: flex; justify-content: flex-end; gap: 8px; border-top: 1px solid var(--helto-border); background: var(--helto-bg); }
    .helto-privacy-keystore-hint { margin: 0; color: var(--helto-text-dim); }
    .helto-privacy-keystore-field { display: grid; gap: 4px; color: var(--helto-text-faint); }
    .helto-privacy-keystore-status, .helto-privacy-recovery-status { min-height: 16px; color: var(--helto-danger); }
    .helto-privacy-keystore-actions { display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }
    .helto-privacy-recovery-counts { display: flex; flex-wrap: wrap; gap: 6px; }
    .helto-privacy-recovery-counts span { border: 1px solid var(--helto-border); background: var(--helto-surface-2); color: var(--helto-text-dim); border-radius: var(--helto-radius-sm); padding: 3px 6px; }
    .helto-privacy-recovery-list { display: grid; gap: 8px; overflow: auto; }
    .helto-privacy-recovery-node { display: grid; gap: 5px; border: 1px solid var(--helto-border); background: var(--helto-bg); border-radius: var(--helto-radius-sm); padding: 8px; }
    .helto-privacy-recovery-node h4 { margin: 0; color: var(--helto-text); font-size: 12px; }
    .helto-privacy-recovery-issue { color: var(--helto-text-dim); overflow-wrap: anywhere; }
    .helto-privacy-surface { position: fixed; z-index: 10020; top: 10px; right: 10px; width: min(520px, calc(100vw - 20px)); }
    .helto-privacy-surface-header strong { margin-right: auto; }
    .helto-privacy-surface-panel { margin-top: 6px; display: grid; gap: 8px; box-shadow: var(--helto-shadow-pop); }
    .helto-privacy-surface-panel[hidden] { display: none !important; }
    .helto-privacy-surface-actions { flex-wrap: wrap; }
    .helto-privacy-pack-list { display: grid; gap: 8px; max-height: min(420px, 60vh); overflow: auto; }
    .helto-privacy-pack { padding: 8px; display: grid; grid-template-columns: 1fr auto; gap: 7px; }
    .helto-privacy-pack h3 { margin: 0; font-size: 12px; overflow-wrap: anywhere; }
    .helto-privacy-mode-row { grid-column: 1 / -1; display: grid; grid-template-columns: minmax(70px, 1fr) auto auto auto auto; align-items: center; gap: 6px; }
    .helto-privacy-mode-metadata { grid-column: 1 / -1; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 10px; color: var(--helto-text-faint); font-size: 11px; }
    .helto-privacy-status { padding: 7px 10px; border: 1px solid #7d5a41; border-radius: var(--helto-radius); background: #30231a; color: #f8d0ae; box-shadow: var(--helto-shadow-pop); }
    .helto-hidden-collapsed { opacity: 0 !important; filter: blur(8px) !important; pointer-events: none !important; }
    .helto-text-masked { background: var(--helto-bg) !important; border-color: var(--helto-bg) !important; color: transparent !important; -webkit-text-fill-color: transparent !important; caret-color: transparent !important; text-shadow: none !important; }
    .helto-text-masked::placeholder { color: transparent !important; }
    .helto-text-masked.is-revealed { background: var(--helto-surface-2) !important; border-color: var(--helto-border-strong) !important; color: inherit !important; -webkit-text-fill-color: currentColor !important; caret-color: auto !important; }
    .helto-root.is-private .helto-private img, .helto-root.is-private .helto-private-text { opacity: 0; }
    .helto-root.is-private.is-revealed .helto-private img, .helto-root.is-private.is-revealed .helto-private-text { opacity: 1; }
    .helto-root.is-private:not(.is-revealed) .helto-private-label { color: transparent !important; text-shadow: none !important; }
    @media (max-width: 640px) { .helto-privacy-mode-row { grid-template-columns: 1fr auto; } .helto-privacy-mode-row > * { min-width: 0; } }
  `;
  documentRef.head?.append(style);
}
