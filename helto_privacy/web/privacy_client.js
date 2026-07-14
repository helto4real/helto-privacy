// Internal browser transport for the attested profile runtime and shared UI.
// Consumer packs receive compiled resource handles, never this transport.

import { isOpaquePrivateRecordId } from "./privacy_records.js";
import { normalizeArtifactLease } from "./privacy_artifacts.js";

const ROUTE_PREFIX = "/helto_privacy";
const PRIVACY_TOKEN_HEADER = "X-Helto-Privacy-Token";
const PRIVACY_PACK_HEADER = "X-Helto-Privacy-Pack";
const PRIVACY_PROFILE_HEADER = "X-Helto-Privacy-Profile";
const PRIVACY_SUITE_HEADER = "X-Helto-Privacy-Suite";
const PRIVACY_OPERATION_HEADER = "X-Helto-Privacy-Operation";
const PRIVACY_DECLASSIFICATION_HEADER = "X-Helto-Privacy-Declassification";
const PRIVACY_DESTRUCTIVE_HEADER = "X-Helto-Privacy-Destructive";
const PRIVACY_RESUME_CAPABILITY_HEADER = "X-Helto-Privacy-Resume-Capability";
const PRIVACY_OPERATION_RESUME_CAPABILITY_HEADER =
  "X-Helto-Privacy-Operation-Resume-Capability";
const PRIVACY_SERVER_BOOT_EPOCH_HEADER = "X-Helto-Privacy-Boot-Epoch";
const PRIVACY_TOKEN_STORAGE_KEY = "helto_privacy_token";
const PRIVACY_LOCKED_CODES = ["PRIVACY_LOCKED", "PRIVACY_TOKEN_REQUIRED"];
const PRIVACY_SETUP_CODES = ["PRIVACY_KEYSTORE_UNINITIALIZED"];
const PRIVACY_SESSION_SUBSCRIBERS = new Set();
let privacySessionRevision = 0;
let privacySessionState = "unknown";

function readPrivacyToken() {
  try {
    return globalThis.localStorage?.getItem(PRIVACY_TOKEN_STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

function storePrivacyToken(
  token,
  { documentRef = globalThis.document, state = token ? "unlocked" : "locked" } = {},
) {
  try {
    if (token) globalThis.localStorage?.setItem(PRIVACY_TOKEN_STORAGE_KEY, String(token));
    else globalThis.localStorage?.removeItem(PRIVACY_TOKEN_STORAGE_KEY);
  } catch {
    /* localStorage unavailable — token stays per-request. */
  }
  writePrivacyTokenCookie(token, documentRef);
  publishPrivacySession(state);
}

export function ensureStoredPrivacyTokenCookie(documentRef = globalThis.document) {
  const token = readPrivacyToken();
  if (!token) return false;
  writePrivacyTokenCookie(token, documentRef);
  return true;
}

function writePrivacyTokenCookie(token, documentRef = globalThis.document) {
  try {
    if (!documentRef) return;
    documentRef.cookie = token
      ? `${PRIVACY_TOKEN_STORAGE_KEY}=${encodeURIComponent(String(token))}; path=/; SameSite=Strict`
      : `${PRIVACY_TOKEN_STORAGE_KEY}=; path=/; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  } catch {
    /* cookies unavailable — header-based callers still work. */
  }
}

export function isPrivacyLockedError(error) {
  const code = String(error?.code || "");
  const message = String(error?.message ?? error ?? "");
  return PRIVACY_LOCKED_CODES.includes(code)
    || PRIVACY_LOCKED_CODES.some((lockedCode) => message.includes(lockedCode));
}

export function isPrivacySetupRequiredError(error) {
  const code = String(error?.code || "");
  const message = String(error?.message ?? error ?? "");
  return PRIVACY_SETUP_CODES.includes(code)
    || PRIVACY_SETUP_CODES.some((setupCode) => message.includes(setupCode));
}

export function isPrivacyUnlockRequiredError(error) {
  return isPrivacyLockedError(error) || isPrivacySetupRequiredError(error);
}

export function subscribePrivacySession(listener, { emitCurrent = false } = {}) {
  if (typeof listener !== "function") {
    throw new TypeError("Privacy session listener must be a function.");
  }
  PRIVACY_SESSION_SUBSCRIBERS.add(listener);
  if (emitCurrent) listener(privacySessionSnapshot());
  return () => PRIVACY_SESSION_SUBSCRIBERS.delete(listener);
}

export function privacySessionSnapshot() {
  return Object.freeze({
    state: privacySessionState,
    revision: privacySessionRevision,
  });
}

function publishPrivacySession(state, { force = true } = {}) {
  const nextState = ["locked", "unlocked", "setup-required"].includes(state)
    ? state
    : "unknown";
  if (!force && nextState === privacySessionState) return privacySessionSnapshot();
  privacySessionState = nextState;
  privacySessionRevision += 1;
  const snapshot = privacySessionSnapshot();
  for (const listener of PRIVACY_SESSION_SUBSCRIBERS) {
    try {
      listener(snapshot);
    } catch {
      /* A consumer listener cannot prevent other consumers from updating. */
    }
  }
  return snapshot;
}

export class PrivacyBrowserRequestError extends Error {
  constructor(code, httpStatus = 0) {
    super("Privacy browser request did not complete.");
    this.name = "PrivacyBrowserRequestError";
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

function createAttestedPrivacyRequestClient({
  packId,
  profileFingerprint,
  suiteManifestDigest,
  documentRef = globalThis.document,
  fetchImpl = globalThis.fetch,
  promptUnlock = async () => null,
}) {
  const identity = normalizeAttestedBrowserIdentity({
    packId,
    profileFingerprint,
    suiteManifestDigest,
  });
  if (typeof fetchImpl !== "function" || typeof promptUnlock !== "function") {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_CLIENT_INVALID");
  }

  async function request(operationId, target, options = {}) {
    const operation = String(operationId || "").trim();
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(operation)) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    if (!isSafePrivacyBrowserTarget(target)) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_TARGET_INVALID");
    }

    let attempt = 0;
    while (attempt < 2) {
      const token = readPrivacyToken();
      if (token) writePrivacyTokenCookie(token, documentRef);
      const headers = {
        Accept: "application/json",
        [PRIVACY_PACK_HEADER]: identity.packId,
        [PRIVACY_PROFILE_HEADER]: identity.profileFingerprint,
        [PRIVACY_SUITE_HEADER]: identity.suiteManifestDigest,
        [PRIVACY_OPERATION_HEADER]: operation,
      };
      if (token) headers[PRIVACY_TOKEN_HEADER] = token;
      if (options.declassificationConfirmed === true) {
        headers[PRIVACY_DECLASSIFICATION_HEADER] = "confirmed";
      }
      if (options.destructiveConfirmed === true) {
        headers[PRIVACY_DESTRUCTIVE_HEADER] = "confirmed";
      }
      if (options.resumeCapability) {
        headers[PRIVACY_RESUME_CAPABILITY_HEADER] = String(options.resumeCapability);
      }
      if (options.operationResumeCapability) {
        headers[PRIVACY_OPERATION_RESUME_CAPABILITY_HEADER] =
          String(options.operationResumeCapability);
      }
      if (options.serverBootEpoch) {
        headers[PRIVACY_SERVER_BOOT_EPOCH_HEADER] = String(options.serverBootEpoch);
      }
      if (options.body !== undefined) headers["Content-Type"] = "application/json";

      let response;
      try {
        response = await fetchImpl(target, {
          method: String(options.method || "POST").toUpperCase(),
          headers,
          credentials: "same-origin",
          cache: "no-store",
          ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
        });
      } catch {
        throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_REQUEST_FAILED");
      }
      const payload = await readPrivacyBrowserPayload(response);
      if (response.ok && payload?.ok !== false && !payload?.error) return payload;

      const error = privacyBrowserResponseError(response, payload);
      if (
        attempt === 0
        && options.retryUnlock !== false
        && isPrivacyUnlockRequiredError(error)
      ) {
        const unlocked = await promptUnlock({ error, identity });
        if (unlocked) {
          attempt += 1;
          continue;
        }
      }
      throw error;
    }
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_REQUEST_FAILED");
  }

  return Object.freeze({ identity, request });
}

function createAttestedPrivacyModeClient({
  packId,
  modeScopes,
  requestClient,
}) {
  const id = String(packId || "").trim();
  const scopes = Object.freeze(normalizeBrowserModeScopes(modeScopes));
  if (
    requestClient?.identity?.packId !== id
    || typeof requestClient.request !== "function"
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_CLIENT_INVALID");
  }

  async function readAll() {
    const result = await requestClient.request(
      "mode.status",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(id)}/modes`,
      { method: "GET", retryUnlock: false },
    );
    return Object.freeze({
      ...result,
      scopes: Object.freeze(
        (Array.isArray(result?.scopes) ? result.scopes : []).map(freezeBrowserModeScope),
      ),
    });
  }

  async function resolve(resourceId, scopeId, declaration = undefined, facts = undefined) {
    if (!scopes.some(
      (scope) => scope.id === scopeId && scope.modeResourceId === resourceId,
    )) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_SCOPE_INVALID");
    }
    if (declaration !== undefined) {
      if (!["inherit", "private", "public"].includes(declaration)) {
        throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_INVALID");
      }
      if (
        facts !== undefined
        && (facts === null || typeof facts !== "object" || Array.isArray(facts))
      ) {
        throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_INVALID");
      }
      return requestClient.request(
        "mode.resolve",
        `${ROUTE_PREFIX}/profiles/${encodeURIComponent(id)}/modes/${encodeURIComponent(scopeId)}/resolve`,
        { body: { declaration, ...(facts === undefined ? {} : { facts }) }, retryUnlock: false },
      );
    }
    const result = await readAll();
    const scope = result.scopes.find(
      (item) => item.id === scopeId && item.modeResourceId === resourceId,
    );
    if (!scope) throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_SCOPE_INVALID");
    return scope;
  }

  async function transition(scopeId, target) {
    if (
      !scopes.some((scope) => scope.id === scopeId)
      || !["inherit", "private", "public"].includes(target)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_INVALID");
    }
    const declassificationConfirmed = target === "public"
      ? await confirmSharedDeclassification()
      : false;
    if (target === "public" && !declassificationConfirmed) return null;
    return requestClient.request(
      "mode.transition",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(id)}/modes/${encodeURIComponent(scopeId)}/transition`,
      {
        body: { target },
        declassificationConfirmed,
      },
    );
  }

  function externalTarget(scopeId, suffix = "") {
    if (!scopes.some((scope) => scope.id === scopeId)) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_SCOPE_INVALID");
    }
    return `${ROUTE_PREFIX}/profiles/${encodeURIComponent(id)}/modes/`
      + `${encodeURIComponent(scopeId)}/transition${suffix}`;
  }

  async function reserve(scopeId, target, capability) {
    if (!capability || !["inherit", "private", "public"].includes(target)) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_INVALID");
    }
    const declassificationConfirmed = target === "public"
      ? await confirmSharedDeclassification()
      : false;
    if (target === "public" && !declassificationConfirmed) return null;
    const { resumeSecret, serverBootEpoch, ...body } = capability;
    return requestClient.request(
      "mode.transition.reserve",
      externalTarget(scopeId, "/reserve"),
      {
        body: { target, ...body },
        declassificationConfirmed,
        resumeCapability: resumeSecret,
        serverBootEpoch,
      },
    );
  }

  const status = (scopeId) => requestClient.request(
    "mode.transition.status",
    externalTarget(scopeId, "/status"),
    { method: "GET", retryUnlock: false },
  );
  const rebase = (scopeId, body) => {
    const { serverBootEpoch, ...safeBody } = body || {};
    return requestClient.request(
      "mode.transition.rebase",
      externalTarget(scopeId, "/rebase"),
      { body: safeBody, serverBootEpoch },
    );
  };
  const externalStep = (operation, scopeId, transitionId, phase, body) => {
    const { resumeSecret, serverBootEpoch, ...safeBody } = body || {};
    return requestClient.request(
      operation,
      externalTarget(
        scopeId,
        `/${encodeURIComponent(String(transitionId || ""))}/${phase}`,
      ),
      {
        body: safeBody,
        resumeCapability: resumeSecret,
        serverBootEpoch,
      },
    );
  };
  const heartbeat = (scopeId, body) => {
    const { serverBootEpoch, resumeSecret, ...safeBody } = body || {};
    return requestClient.request(
      "mode.transition.client-heartbeat",
      externalTarget(scopeId, "/client-heartbeat"),
      {
        body: safeBody,
        serverBootEpoch,
        resumeCapability: resumeSecret,
      },
    );
  };
  const prepare = (scopeId, transitionId, body) => externalStep(
    "mode.transition.prepare", scopeId, transitionId, "prepare", body,
  );
  const resume = (scopeId, transitionId, body) => externalStep(
    "mode.transition.resume", scopeId, transitionId, "resume", body,
  );
  const applyAck = (scopeId, transitionId, body) => externalStep(
    "mode.transition.apply-ack", scopeId, transitionId, "apply-ack", body,
  );
  const verify = (scopeId, transitionId, body) => externalStep(
    "mode.transition.verify", scopeId, transitionId, "verify", body,
  );
  const finalize = (scopeId, transitionId, body) => externalStep(
    "mode.transition.finalize", scopeId, transitionId, "finalize", body,
  );
  const rollback = (scopeId, transitionId, body) => externalStep(
    "mode.transition.rollback", scopeId, transitionId, "rollback", body,
  );

  return Object.freeze({
    id,
    scopes,
    readAll,
    resolve,
    transition,
    reserve,
    status,
    rebase,
    prepare,
    resume,
    applyAck,
    verify,
    finalize,
    rollback,
    heartbeat,
  });
}

async function confirmSharedDeclassification() {
  return globalThis.confirm?.(
    "Make this privacy scope public? Protected data and derivatives will be rewritten.",
  ) === true;
}

export async function connectAttestedPrivacyProfileClient({
  packId,
  profileFingerprint,
  suiteManifestDigest,
  promptUnlock = async () => null,
}) {
  const identity = normalizeAttestedBrowserIdentity({
    packId,
    profileFingerprint,
    suiteManifestDigest,
  });
  const attestation = await fetchFixedAttestation(
    `${ROUTE_PREFIX}/profiles/${encodeURIComponent(identity.packId)}`,
  );
  if (
    attestation.id !== identity.packId
    || attestation.fingerprint !== identity.profileFingerprint
    || attestation.suiteManifestDigest !== identity.suiteManifestDigest
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_ATTESTATION_DRIFT");
  }
  await attestFixedBrowserManifest(identity.suiteManifestDigest);
  const requestClient = createAttestedPrivacyRequestClient({
    packId: identity.packId,
    profileFingerprint: identity.profileFingerprint,
    suiteManifestDigest: identity.suiteManifestDigest,
    promptUnlock,
  });
  const operations = Object.freeze(
    normalizeProtectedOperations(
      attestation.protectedOperations,
      attestation.modeScopes,
      attestation.records,
      attestation.singletons,
      attestation.artifacts,
    ),
  );
  const protectedFields = Object.freeze(
    normalizeProtectedFields(attestation.protectedFields),
  );
  const executionProjections = Object.freeze(
    normalizeExecutionProjections(attestation.executionProjections),
  );
  const subjectModeBindings = Object.freeze(
    normalizeSubjectModeBindings(
      attestation.subjectModeBindings ?? [],
      attestation.modeScopes,
      attestation.requiredBrowserAdapters,
      protectedFields,
      executionProjections,
      operations,
    ),
  );
  const recordDeclarations = Object.freeze(
    normalizeRecordDeclarations(attestation.records),
  );
  const recordReferenceMigrations = Object.freeze(
    normalizeRecordReferenceMigrations(attestation.recordReferenceMigrations ?? []),
  );
  const artifactDeclarations = Object.freeze(
    normalizeArtifactDeclarations(attestation.artifacts),
  );
  const mode = createAttestedPrivacyModeClient({
    packId: requestClient.identity.packId,
    modeScopes: attestation.modeScopes,
    requestClient,
  });
  const snapshot = createAttestedPrivacySnapshotClient({
    packId: requestClient.identity.packId,
    fields: protectedFields,
    requestClient,
  });
  const execution = createAttestedPrivacyExecutionClient({
    packId: requestClient.identity.packId,
    fields: protectedFields,
    projections: executionProjections,
    requestClient,
  });
  const subjectMode = createAttestedSubjectModeClient({
    packId: requestClient.identity.packId,
    bindings: subjectModeBindings,
    requestClient,
  });
  const submissionGrants = createAttestedSubmissionGrantClient({
    packId: requestClient.identity.packId,
    profileFingerprint: requestClient.identity.profileFingerprint,
    projections: executionProjections,
    bindings: subjectModeBindings,
    requestClient,
  });
  const records = createAttestedPrivacyRecordClient({
    packId: requestClient.identity.packId,
    declarations: recordDeclarations,
    referenceMigrations: recordReferenceMigrations,
    requestClient,
  });
  const artifacts = createAttestedPrivacyArtifactClient({
    packId: requestClient.identity.packId,
    declarations: artifactDeclarations,
    requestClient,
  });
  const externalOperations = createAttestedExternalOperationClient({
    packId: requestClient.identity.packId,
    operations,
    requestClient,
  });

  function invoke(resourceId, operationId, body = undefined) {
    const operation = operations.find(
      (item) => item.id === operationId
        && item.resourceId === resourceId
        && item.route !== null,
    );
    if (!operation) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    return requestClient.request(
      operation.id,
      operation.route,
      {
        method: operation.method,
        ...(body === undefined ? {} : { body }),
      },
    );
  }

  function revokeReferences(references) {
    if (
      !Array.isArray(references)
      || !references.length
      || references.length > 256
      || references.some((value) => !/^hp-ref-[A-Za-z0-9_-]{32}$/.test(value))
      || new Set(references).size !== references.length
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_OPAQUE_REFERENCE_UNAVAILABLE");
    }
    return requestClient.request(
      "reference.revoke",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(identity.packId)}/references/revoke`,
      { body: { references } },
    );
  }

  function claimAssociation(associationId) {
    const value = String(associationId || "");
    if (!/^hp-assoc-[A-Za-z0-9_-]{32}$/.test(value)) {
      throw new PrivacyBrowserRequestError("PRIVACY_OPERATION_ASSOCIATION_UNAVAILABLE");
    }
    return requestClient.request(
      "association.claim",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(identity.packId)}`
        + `/associations/${encodeURIComponent(value)}/claim`,
      { body: {} },
    );
  }

  return Object.freeze({
    attestation: Object.freeze({ ...attestation }),
    identity: requestClient.identity,
    operations,
    executionProjections,
    subjectModeBindings,
    recordDeclarations,
    recordReferenceMigrations,
    artifactDeclarations,
    mode,
    snapshot,
    execution,
    subjectMode,
    submissionGrants,
    records,
    artifacts,
    externalOperations,
    invoke,
    revokeReferences,
    claimAssociation,
  });
}

function createAttestedExternalOperationClient({
  packId,
  operations,
  requestClient,
}) {
  const declaration = (operationId) => {
    const operation = operations.find((item) => (
      item.id === String(operationId || "")
      && item.externalOperationBinding !== null
    ));
    if (!operation) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    return operation;
  };
  const base = (operation) => (
    `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/operations/`
    + `${encodeURIComponent(operation.id)}/external`
  );
  const transactionTarget = (operation, transactionId, action) => {
    const transaction = String(transactionId || "");
    if (!/^hp-operation-[A-Za-z0-9_-]{32}$/.test(transaction)) {
      throw new PrivacyBrowserRequestError("PRIVACY_EXTERNAL_OPERATION_INVALID");
    }
    return `${base(operation)}/${encodeURIComponent(transaction)}/${action}`;
  };
  const capability = (value) => {
    const normalized = String(value || "");
    if (!/^hp-operation-resume-[A-Za-z0-9_-]{43}$/.test(normalized)) {
      throw new PrivacyBrowserRequestError("PRIVACY_EXTERNAL_OPERATION_FENCED");
    }
    return normalized;
  };
  const prepare = (operationId, body) => {
    const operation = declaration(operationId);
    return requestClient.request(
      operation.id,
      `${base(operation)}/prepare`,
      { body },
    ).then(normalizeExternalOperationResponse);
  };
  const status = (operationId, transactionId) => {
    const operation = declaration(operationId);
    return requestClient.request(
      operation.id,
      transactionTarget(operation, transactionId, "status"),
      { method: "GET", retryUnlock: false },
    ).then(normalizeExternalOperationStatusResponse);
  };
  const action = (operationId, transactionId, resumeCapability, name, body = {}) => {
    const operation = declaration(operationId);
    return requestClient.request(
      operation.id,
      transactionTarget(operation, transactionId, name),
      {
        body,
        operationResumeCapability: capability(resumeCapability),
      },
    ).then(normalizeExternalOperationResponse);
  };
  return Object.freeze({
    prepare,
    status,
    resume: (operationId, transactionId, resumeCapability) => action(
      operationId, transactionId, resumeCapability, "resume",
    ),
    apply: (operationId, transactionId, resumeCapability, currentExact) => action(
      operationId,
      transactionId,
      resumeCapability,
      "apply",
      { currentExact },
    ),
    rollback: (operationId, transactionId, resumeCapability) => action(
      operationId, transactionId, resumeCapability, "rollback",
    ),
  });
}

function normalizeExternalOperationResponse(value) {
  const normalized = normalizeExternalOperationStatusResponse(value);
  const phase = normalized.phase;
  const active = normalized.active;
  if (active) {
    if (
      value.ownerIdentity === undefined
      || typeof value.originalExact !== "string"
      || (value.targetExact !== null && typeof value.targetExact !== "string")
      || value.browserValue === undefined
      || (value.resumeCapability !== undefined
        && !/^hp-operation-resume-[A-Za-z0-9_-]{43}$/.test(value.resumeCapability))
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_EXTERNAL_OPERATION_INVALID");
    }
  } else if (
    value.ownerIdentity === undefined
    || typeof value.exact !== "string"
    || (phase === "completed" && (!value.result || typeof value.result !== "object"))
    || (phase === "rolled-back" && value.result !== null)
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_EXTERNAL_OPERATION_INVALID");
  }
  return Object.freeze({ ...value });
}

function normalizeExternalOperationStatusResponse(value) {
  const phase = String(value?.phase || "");
  const active = value?.active === true;
  const transactionId = String(value?.transactionId || "");
  const operationId = String(value?.operationId || "");
  if (
    value?.ok !== true
    || !/^hp-operation-[A-Za-z0-9_-]{32}$/.test(transactionId)
    || !isStablePrivacyId(operationId)
    || ![
      "captured",
      "prepared",
      "applied",
      "rollback-required",
      "completed",
      "rolled-back",
    ].includes(phase)
    || active !== ["captured", "prepared", "applied", "rollback-required"].includes(phase)
    || !Number.isInteger(value?.expiresInSeconds)
    || value.expiresInSeconds < 0
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_EXTERNAL_OPERATION_INVALID");
  }
  if (
    value.receiptId !== null
    && !/^hp-operation-receipt-[a-f0-9]{32}$/.test(String(value.receiptId || ""))
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_EXTERNAL_OPERATION_INVALID");
  }
  return Object.freeze({ ...value });
}

function createAttestedSubmissionGrantClient({
  packId,
  profileFingerprint,
  projections,
  bindings,
  requestClient,
}) {
  const revoke = (references) => {
    if (!Array.isArray(references) || references.length > 2048) {
      throw new PrivacyBrowserRequestError("PRIVACY_SUBMISSION_GRANTS_INVALID");
    }
    const cloned = references.map((reference) => {
      if (!reference || typeof reference !== "object" || Array.isArray(reference)) {
        throw new PrivacyBrowserRequestError("PRIVACY_SUBMISSION_GRANTS_INVALID");
      }
      const schema = reference.schema;
      const valid = schema === "helto.private-execution-reference"
        ? reference.version === 2
          && reference.packId === packId
          && /^[0-9a-f]{64}$/.test(reference.subject)
          && projections.some(
            (item) => item.executionResourceId === reference.executionResourceId,
          )
        : schema === "helto.subject-mode-reference"
          ? reference.version === 2
          && reference.packId === packId
          && reference.profileFingerprint === profileFingerprint
          && /^[0-9a-f]{64}$/.test(reference.subject)
          && bindings.some((item) => (
            item.id === reference.bindingId
            && item.scopeId === reference.scopeId
          ))
          : false;
      if (!valid) {
        throw new PrivacyBrowserRequestError("PRIVACY_SUBMISSION_GRANTS_INVALID");
      }
      try {
        return JSON.parse(JSON.stringify(reference));
      } catch {
        throw new PrivacyBrowserRequestError("PRIVACY_SUBMISSION_GRANTS_INVALID");
      }
    });
    return requestClient.request(
      "submission-grants.revoke",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/submission-grants/revoke`,
      { body: { references: cloned }, retryUnlock: false },
    );
  };
  return Object.freeze({ revoke });
}

function createAttestedSubjectModeClient({ packId, bindings, requestClient }) {
  const prepare = (bindingId, subjectId, declaration, facts = undefined) => {
    const id = String(bindingId || "");
    if (
      !bindings.some((binding) => binding.id === id)
      || !String(subjectId ?? "")
      || !["inherit", "private", "public"].includes(declaration)
      || (facts !== undefined && (!facts || typeof facts !== "object" || Array.isArray(facts)))
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_REFERENCE_INVALID");
    }
    return requestClient.request(
      "subject-mode.prepare",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/subject-modes/`
        + `${encodeURIComponent(id)}/prepare`,
      {
        body: {
          subjectId: String(subjectId),
          declaration,
          ...(facts === undefined ? {} : { facts }),
        },
      },
    );
  };
  return Object.freeze({ prepare });
}

function createAttestedPrivacyArtifactClient({ packId, declarations, requestClient }) {
  const declaration = (resourceId, artifactKind) => {
    const resource = String(resourceId || "");
    const kind = String(artifactKind || "");
    const match = declarations.find(
      (item) => item.resourceId === resource && item.id === kind,
    );
    if (!match) {
      throw new PrivacyBrowserRequestError("PRIVACY_ARTIFACT_DECLARATION_INVALID");
    }
    return match;
  };
  const lease = (resourceId, artifactKind, reference, operation) => {
    const item = declaration(resourceId, artifactKind);
    const safeOperation = String(operation || "");
    if (!item.operations.includes(safeOperation)) {
      throw new PrivacyBrowserRequestError("PRIVACY_ARTIFACT_OPERATION_INVALID");
    }
    const artifactId = normalizeArtifactReference(reference);
    return requestClient.request(
      `artifact.${safeOperation}`,
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/artifacts/`
        + `${encodeURIComponent(item.resourceId)}/${encodeURIComponent(item.id)}/`
        + `${encodeURIComponent(artifactId)}/lease/${encodeURIComponent(safeOperation)}`,
    ).then((result) => {
      try {
        return normalizeArtifactLease(result?.lease);
      } catch {
        throw new PrivacyBrowserRequestError("PRIVACY_ARTIFACT_LEASE_INVALID");
      }
    });
  };
  return Object.freeze({ lease });
}

function normalizeArtifactReference(reference) {
  if (
    !reference
    || Object.keys(reference).sort().join(",") !== "id,schema,version"
    || reference.schema !== "helto.private-artifact-reference"
    || reference.version !== 1
    || !/^hp-art-[A-Za-z0-9_-]{32}$/.test(String(reference.id || ""))
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_ARTIFACT_REFERENCE_INVALID");
  }
  return String(reference.id);
}

function createAttestedPrivacySnapshotClient({ packId, fields, requestClient }) {
  const declaredIds = new Set(fields.map((field) => field.id));
  const requireField = (fieldId) => {
    const id = String(fieldId || "");
    if (!declaredIds.has(id)) {
      throw new PrivacyBrowserRequestError("PRIVACY_SNAPSHOT_FIELD_INVALID");
    }
    return id;
  };
  const disposition = (fieldId, protectedValue) => {
    const id = requireField(fieldId);
    return requestClient.request(
      "snapshot.disposition",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/fields/${encodeURIComponent(id)}/disposition`,
      {
        body: { protectedValue },
        retryUnlock: false,
      },
    );
  };
  const protect = (fieldId, value) => {
    const id = requireField(fieldId);
    return requestClient.request(
      "snapshot.protect",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/fields/${encodeURIComponent(id)}/protect`,
      { body: { value } },
    );
  };
  const reveal = (fieldId, protectedValue) => {
    const id = requireField(fieldId);
    return requestClient.request(
      "snapshot.reveal",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/fields/${encodeURIComponent(id)}/reveal`,
      { body: { protectedValue } },
    );
  };
  return Object.freeze({ disposition, protect, reveal });
}

function createAttestedPrivacyExecutionClient({
  packId,
  fields,
  projections,
  requestClient,
}) {
  const prepare = (
    executionResourceId,
    projectionId,
    subjectId,
    protectedFields,
  ) => {
    const executionId = String(executionResourceId || "");
    const subjectScalar = typeof subjectId === "string"
      || (typeof subjectId === "number" && Number.isSafeInteger(subjectId));
    const subject = String(subjectId ?? "");
    const projection = projections.find(
      (item) => item.id === projectionId
        && item.executionResourceId === executionId,
    );
    if (
      !projection
      || !subjectScalar
      || !subject
      || new TextEncoder().encode(subject).length > 512
      || !Array.isArray(protectedFields)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_EXECUTION_PROJECTION_INVALID");
    }
    const expected = fields
      .filter((field) => (
        field.execution
        && field.workflowResourceId === projection.workflowResourceId
      ))
      .map((field) => field.id)
      .sort();
    const supplied = protectedFields.map((item) => String(item?.fieldId || ""));
    if (
      !expected.length
      || supplied.length !== new Set(supplied).size
      || JSON.stringify([...supplied].sort()) !== JSON.stringify(expected)
      || protectedFields.some((item) => !("protectedValue" in (item || {})))
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_EXECUTION_REFERENCE_INVALID");
    }
    return requestClient.request(
      "execution.prepare",
      `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/executions/${encodeURIComponent(executionId)}/prepare`,
      {
        body: {
          projectionId: projection.id,
          subjectId: subject,
          fields: protectedFields.map((item) => ({
            fieldId: String(item.fieldId),
            protectedValue: item.protectedValue,
          })),
        },
      },
    );
  };
  return Object.freeze({ prepare });
}

function createAttestedPrivacyRecordClient({
  packId,
  declarations,
  referenceMigrations,
  requestClient,
}) {
  const declaration = (resourceId, recordKind) => {
    const resource = String(resourceId || "");
    const kind = String(recordKind || "");
    const match = declarations.find(
      (item) => item.resourceId === resource && item.id === kind,
    );
    if (!match) throw new PrivacyBrowserRequestError("PRIVACY_RECORD_DECLARATION_INVALID");
    return match;
  };
  const base = (item) => (
    `${ROUTE_PREFIX}/profiles/${encodeURIComponent(packId)}/records/`
    + `${encodeURIComponent(item.resourceId)}/${encodeURIComponent(item.id)}`
  );
  const recordTarget = (item, recordId) => {
    const id = String(recordId || "");
    if (!isOpaquePrivateRecordId(id)) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_ID_INVALID");
    }
    return `${base(item)}/${encodeURIComponent(id)}`;
  };
  const list = (resourceId, recordKind) => {
    const item = declaration(resourceId, recordKind);
    return requestClient.request(
      "record.list",
      base(item),
      { method: "GET", retryUnlock: false },
    );
  };
  const reveal = (resourceId, recordKind, recordId, operation) => {
    const item = declaration(resourceId, recordKind);
    const safeOperation = String(operation || "");
    if (!item.revealOperations.includes(safeOperation)) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_OPERATION_INVALID");
    }
    return requestClient.request(
      `record.${safeOperation}`,
      `${recordTarget(item, recordId)}/reveal/${encodeURIComponent(safeOperation)}`,
    );
  };
  const remove = (resourceId, recordKind, recordId, confirmed) => {
    if (confirmed !== true) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_CONFIRMATION_REQUIRED");
    }
    const item = declaration(resourceId, recordKind);
    return requestClient.request(
      "record.delete",
      `${recordTarget(item, recordId)}/delete`,
      { retryUnlock: false, destructiveConfirmed: true },
    );
  };
  const replace = (resourceId, recordKind, recordId, protectedValue, confirmed) => {
    if (confirmed !== true) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_CONFIRMATION_REQUIRED");
    }
    const item = declaration(resourceId, recordKind);
    return requestClient.request(
      "record.replace",
      `${recordTarget(item, recordId)}/replace`,
      {
        body: { protectedValue },
        retryUnlock: false,
        destructiveConfirmed: true,
      },
    );
  };
  const mutate = (resourceId, recordKind, operation, value, recordId = null) => {
    const item = declaration(resourceId, recordKind);
    const safeOperation = String(operation || "");
    if (!item.mutationOperations.includes(safeOperation)) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_MUTATION_INVALID");
    }
    const target = safeOperation === "create"
      ? `${base(item)}/mutate/create`
      : `${recordTarget(item, recordId)}/mutate/${encodeURIComponent(safeOperation)}`;
    return requestClient.request(
      `record.${safeOperation}`,
      target,
      { body: { value } },
    );
  };
  const referenceOperation = (
    resourceId,
    recordKind,
    migrationId,
    reference,
    operation,
  ) => {
    const item = declaration(resourceId, recordKind);
    const migration = referenceMigrations.find(
      (candidate) => candidate.id === migrationId
        && candidate.resourceId === item.resourceId
        && candidate.recordKind === item.id,
    );
    if (!migration || !["migrate", "resolve"].includes(operation)) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_REFERENCE_INVALID");
    }
    if (typeof reference !== "string" || reference.length === 0) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_REFERENCE_INVALID");
    }
    return requestClient.request(
      `record.reference.${operation}`,
      `${base(item)}/reference-migrations/${encodeURIComponent(migration.id)}/${operation}`,
      { body: { reference } },
    );
  };
  return Object.freeze({
    list,
    reveal,
    delete: remove,
    replace,
    mutate,
    migrateLegacyReference: (...args) => referenceOperation(...args, "migrate"),
    resolveLegacyReference: (...args) => referenceOperation(...args, "resolve"),
  });
}

function normalizeRecordReferenceMigrations(values) {
  if (!Array.isArray(values)) {
    throw new PrivacyBrowserRequestError("PRIVACY_RECORD_REFERENCE_INVALID");
  }
  const seen = new Set();
  return values.map((item) => {
    const migration = Object.freeze({
      id: String(item?.id || ""),
      resourceId: String(item?.resourceId || ""),
      recordKind: String(item?.recordKind || ""),
      legacyBindingId: String(item?.legacyBindingId || ""),
    });
    if (
      Object.values(migration).some((value) => !/^[a-z0-9][a-z0-9._-]*$/.test(value))
      || seen.has(migration.id)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_REFERENCE_INVALID");
    }
    seen.add(migration.id);
    return migration;
  });
}

function normalizeProtectedFields(fields) {
  if (!Array.isArray(fields)) return [];
  const seen = new Set();
  return fields.map((field) => {
    const id = String(field?.id || "");
    const workflowResourceId = String(field?.workflowResourceId || "");
    const scopeId = String(field?.scopeId || "");
    const browserAdapter = String(field?.browserAdapter || "");
    const execution = field?.execution === true;
    const stateAuthority = String(field?.stateAuthority || "");
    const externalTransitionPolicy = field?.externalTransitionPolicy;
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
    if (
      !/^[a-z0-9][a-z0-9._-]*$/.test(id)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(workflowResourceId)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(scopeId)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(browserAdapter)
      || !nodeTypes.length
      || !["server-durable", "external-browser-workflow"].includes(stateAuthority)
      || !validExternalTransitionPolicy(stateAuthority, externalTransitionPolicy)
      || legacyReaderIds.some(
        (value, index) => (
          !/^[a-z0-9][a-z0-9._-]*$/.test(value)
          || legacyReaderIds.indexOf(value) !== index
        ),
      )
      || seen.has(id)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_SNAPSHOT_FIELD_INVALID");
    }
    seen.add(id);
    return Object.freeze({
      id,
      workflowResourceId,
      scopeId,
      browserAdapter,
      nodeTypes,
      legacyReaderIds,
      execution,
      stateAuthority,
      externalTransitionPolicy: externalTransitionPolicy === null
        ? null
        : Object.freeze({ ...externalTransitionPolicy }),
    });
  });
}

function validExternalTransitionPolicy(authority, policy) {
  if (authority === "server-durable") return policy === null;
  return policy
    && typeof policy === "object"
    && !Array.isArray(policy)
    && policy.ownerIdentity === "graph-node-field-v1"
    && Number.isInteger(policy.maxOwners)
    && policy.maxOwners >= 1
    && policy.maxOwners <= 4096
    && Number.isInteger(policy.maxOriginalBytesPerOwner)
    && policy.maxOriginalBytesPerOwner >= 1024
    && policy.maxOriginalBytesPerOwner <= 16 * 1024 * 1024
    && Number.isInteger(policy.maxTargetBytesPerOwner)
    && policy.maxTargetBytesPerOwner >= 1024
    && policy.maxTargetBytesPerOwner <= 16 * 1024 * 1024
    && Number.isInteger(policy.maxTotalBytes)
    && policy.maxTotalBytes >= Math.max(
      policy.maxOriginalBytesPerOwner,
      policy.maxTargetBytesPerOwner,
    )
    && policy.maxTotalBytes <= 64 * 1024 * 1024
    && Number.isInteger(policy.leaseSeconds)
    && policy.leaseSeconds >= 30
    && policy.leaseSeconds <= 900;
}

function normalizeExecutionProjections(projections) {
  if (!Array.isArray(projections)) return [];
  const seen = new Set();
  return projections.map((projection) => {
    const id = String(projection?.id || "");
    const executionResourceId = String(projection?.executionResourceId || "");
    const workflowResourceId = String(projection?.workflowResourceId || "");
    const subjectModeBindingId = String(projection?.subjectModeBindingId || "");
    const inputName = String(projection?.inputName || "");
    if (
      !/^[a-z0-9][a-z0-9._-]*$/.test(id)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(executionResourceId)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(workflowResourceId)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(subjectModeBindingId)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(inputName)
      || seen.has(id)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_EXECUTION_PROJECTION_INVALID");
    }
    seen.add(id);
    return Object.freeze({
      id,
      executionResourceId,
      workflowResourceId,
      subjectModeBindingId,
      inputName,
    });
  });
}

function normalizeSubjectModeBindings(
  bindings,
  modeScopes,
  requiredAdapters,
  protectedFields,
  executionProjections,
  operations,
) {
  if (!Array.isArray(bindings)) {
    throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_BINDING_INVALID");
  }
  const seen = new Set();
  const injectedInputs = new Set();
  const normalized = bindings.map((binding) => {
    const id = String(binding?.id || "");
    const scopeId = String(binding?.scopeId || "");
    const inputName = String(binding?.inputName || "");
    const nodeTypes = Object.freeze(
      (Array.isArray(binding?.nodeTypes) ? binding.nodeTypes : [])
        .map((value) => String(value || ""))
        .filter(Boolean),
    );
    const scope = modeScopes?.find((item) => item?.id === scopeId);
    const editor = requiredAdapters?.find((item) => item?.id === scope?.modeEditorAdapter);
    if (
      ![id, scopeId, inputName].every(
        (value) => /^[a-z0-9][a-z0-9._-]*$/.test(value),
      )
      || !nodeTypes.length
      || !modeScopes?.some(
        (scope) => scope?.id === scopeId && scope?.modeEditorAdapter,
      )
      || nodeTypes.some((nodeType) => !editor?.nodeTypes?.includes(nodeType))
      || seen.has(id)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_BINDING_INVALID");
    }
    for (const nodeType of nodeTypes) {
      const key = `${nodeType}:${inputName}`;
      if (injectedInputs.has(key)) {
        throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_BINDING_INVALID");
      }
      injectedInputs.add(key);
    }
    seen.add(id);
    return Object.freeze({ id, scopeId, inputName, nodeTypes });
  });
  for (const projection of executionProjections) {
    const binding = normalized.find(
      (item) => item.id === projection.subjectModeBindingId,
    );
    const executionFields = protectedFields.filter((field) => (
      field.execution && field.workflowResourceId === projection.workflowResourceId
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
      throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_BINDING_INVALID");
    }
    for (const nodeType of binding.nodeTypes) {
      const key = `${nodeType}:${projection.inputName}`;
      if (injectedInputs.has(key)) {
        throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_BINDING_INVALID");
      }
      injectedInputs.add(key);
    }
  }
  const used = new Set(executionProjections.map((item) => item.subjectModeBindingId));
  for (const operation of operations) {
    if (operation.subjectModeBindingId === null) continue;
    const binding = normalized.find((item) => item.id === operation.subjectModeBindingId);
    if (!binding || operation.scopeId !== binding.scopeId) {
      throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_BINDING_INVALID");
    }
    used.add(binding.id);
  }
  if (normalized.some((binding) => !used.has(binding.id))) {
    throw new PrivacyBrowserRequestError("PRIVACY_SUBJECT_MODE_BINDING_INVALID");
  }
  return normalized;
}

function normalizeRecordDeclarations(records) {
  if (!Array.isArray(records)) return [];
  const seen = new Set();
  return records.map((record) => {
    const id = String(record?.id || "");
    const resourceId = String(record?.resourceId || "");
    const scopeId = String(record?.scopeId || "");
    const revealOperations = Object.freeze(
      (Array.isArray(record?.revealOperations) ? record.revealOperations : [])
        .map((value) => String(value || "")),
    );
    const mutationOperations = Object.freeze(
      (Array.isArray(record?.mutationOperations) ? record.mutationOperations : [])
        .map((value) => String(value || "")),
    );
    const safeProjection = Object.freeze(
      (Array.isArray(record?.safeProjection) ? record.safeProjection : [])
        .map((value) => String(value || "")),
    );
    const fixedPrivateLabel = String(record?.fixedPrivateLabel || "");
    if (
      !/^[a-z0-9][a-z0-9._-]*$/.test(id)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(resourceId)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(scopeId)
      || revealOperations.some(
        (operation) => !["use", "preview", "details"].includes(operation),
      )
      || revealOperations.length !== new Set(revealOperations).size
      || mutationOperations.some(
        (operation) => !["create", "replace", "patch", "duplicate"].includes(operation),
      )
      || mutationOperations.length !== new Set(mutationOperations).size
      || safeProjection.length !== 0
      || fixedPrivateLabel !== "Private record"
      || seen.has(id)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_RECORD_DECLARATION_INVALID");
    }
    seen.add(id);
    return Object.freeze({
      id,
      resourceId,
      scopeId,
      revealOperations,
      mutationOperations,
      safeProjection,
      fixedPrivateLabel,
    });
  });
}

function normalizeArtifactDeclarations(artifacts) {
  if (!Array.isArray(artifacts)) return [];
  const seen = new Set();
  return artifacts.map((artifact) => {
    const id = String(artifact?.id || "");
    const resourceId = String(artifact?.resourceId || "");
    const scopeId = String(artifact?.scopeId || "");
    const retention = String(artifact?.retention || "");
    const mediaType = String(artifact?.mediaType || "");
    const payloadMode = String(artifact?.payloadMode || "");
    const suppliedStream = artifact?.streamContract;
    const operations = Object.freeze(
      (Array.isArray(artifact?.operations) ? artifact.operations : [])
        .map((value) => String(value || "")),
    );
    const key = `${resourceId}:${id}`;
    const exactArtifactKeys = [
      "id", "mediaType", "operations", "payloadMode", "resourceId", "retention",
      "scopeId", "streamContract",
    ];
    if (
      !artifact
      || typeof artifact !== "object"
      || Array.isArray(artifact)
      || Object.keys(artifact).sort().join("\0") !== exactArtifactKeys.join("\0")
      || !/^[a-z0-9][a-z0-9._-]*$/.test(id)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(resourceId)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(scopeId)
      || ![
        "durable-adjunct",
        "regenerable-cache",
        "run-scoped-spill",
        "served-transient",
      ].includes(retention)
      || !["bounded-bytes-v1", "stream-v1"].includes(payloadMode)
      || !/^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/i.test(mediaType)
      || (!operations.length && retention !== "run-scoped-spill")
      || operations.some((operation) => !/^[a-z0-9][a-z0-9._-]*$/.test(operation))
      || operations.length !== new Set(operations).size
      || seen.has(key)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_ARTIFACT_DECLARATION_INVALID");
    }
    let streamContract = null;
    if (payloadMode === "stream-v1") {
      const safeInteger = (value) => Number.isSafeInteger(value) && value > 0;
      if (
        retention === "durable-adjunct"
        ||
        !suppliedStream
        || typeof suppliedStream !== "object"
        || Array.isArray(suppliedStream)
        || Object.keys(suppliedStream).sort().join("\0") !== [
          "codecSchema", "codecVersion", "decodedOutput", "maxMaterializedOutputBytes",
          "maxOwnerPlaintextBytes", "maxPlaintextBytes",
        ].join("\0")
        || !/^[a-z0-9][a-z0-9._-]*$/.test(String(suppliedStream.codecSchema || ""))
        || !safeInteger(suppliedStream.codecVersion)
        || !safeInteger(suppliedStream.maxPlaintextBytes)
        || !["materialized", "stream"].includes(suppliedStream.decodedOutput)
        || (suppliedStream.maxOwnerPlaintextBytes !== null
          && !safeInteger(suppliedStream.maxOwnerPlaintextBytes))
        || (suppliedStream.maxOwnerPlaintextBytes !== null
          && suppliedStream.maxOwnerPlaintextBytes < suppliedStream.maxPlaintextBytes)
        || (suppliedStream.decodedOutput === "materialized"
          && !safeInteger(suppliedStream.maxMaterializedOutputBytes))
        || (suppliedStream.decodedOutput === "stream"
          && suppliedStream.maxMaterializedOutputBytes !== null)
      ) {
        throw new PrivacyBrowserRequestError("PRIVACY_ARTIFACT_DECLARATION_INVALID");
      }
      streamContract = Object.freeze({
        codecSchema: String(suppliedStream.codecSchema),
        codecVersion: suppliedStream.codecVersion,
        maxPlaintextBytes: suppliedStream.maxPlaintextBytes,
        maxOwnerPlaintextBytes: suppliedStream.maxOwnerPlaintextBytes,
        decodedOutput: String(suppliedStream.decodedOutput),
        maxMaterializedOutputBytes: suppliedStream.maxMaterializedOutputBytes,
      });
    } else if (suppliedStream !== null) {
      throw new PrivacyBrowserRequestError("PRIVACY_ARTIFACT_DECLARATION_INVALID");
    }
    seen.add(key);
    return Object.freeze({
      id,
      resourceId,
      scopeId,
      retention,
      operations,
      mediaType,
      payloadMode,
      streamContract,
    });
  });
}

async function fetchFixedAttestation(target) {
  let response;
  try {
    response = await globalThis.fetch(target, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_ATTESTATION_UNAVAILABLE");
  }
  const payload = await readPrivacyBrowserPayload(response);
  if (!response.ok || payload?.ok === false || payload?.error) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_ATTESTATION_UNAVAILABLE");
  }
  return payload;
}

async function attestFixedBrowserManifest(manifestDigest) {
  let response;
  try {
    response = await globalThis.fetch(`${ROUTE_PREFIX}/suite/browser-attestation`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      credentials: "same-origin",
      cache: "no-store",
      body: JSON.stringify({ manifestDigest }),
    });
  } catch {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_ATTESTATION_UNAVAILABLE");
  }
  const payload = await readPrivacyBrowserPayload(response);
  if (!response.ok || payload?.ok === false || payload?.error) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_ATTESTATION_UNAVAILABLE");
  }
}

function normalizeProtectedOperations(
  operations,
  modeScopes,
  recordDeclarations,
  singletonDeclarations,
  artifactDeclarations,
) {
  if (!Array.isArray(operations)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  const seen = new Set();
  return operations.map((operation) => {
    const id = String(operation?.id || "");
    const resourceId = String(operation?.resourceId || "");
    const route = operation?.route == null ? null : String(operation.route);
    const method = String(operation?.method || "").toUpperCase();
    const scopeId = operation?.scopeId == null ? null : String(operation.scopeId);
    const subjectModeBindingId = operation?.subjectModeBindingId == null
      ? null
      : String(operation.subjectModeBindingId);
    const sensitiveFields = Array.isArray(operation?.sensitiveFields)
      ? operation.sensitiveFields.map((field) => Object.freeze({
        path: String(field?.path || ""),
        class: String(field?.class || ""),
      }))
      : null;
    const safeProjection = Array.isArray(operation?.safeProjection)
      ? operation.safeProjection.map((field) => Object.freeze({
        path: String(field?.path || ""),
        kind: String(field?.kind || ""),
      }))
      : null;
    const referenceInputs = Array.isArray(operation?.referenceInputs)
      ? operation.referenceInputs.map((item) => Object.freeze({
        name: String(item?.name || ""),
        referenceKindId: String(item?.referenceKindId || ""),
        revokeOnSuccess: item?.revokeOnSuccess === true,
      }))
      : [];
    const referenceOutputs = Array.isArray(operation?.referenceOutputs)
      ? operation.referenceOutputs.map((item) => Object.freeze({
        referenceKindId: String(typeof item === "string" ? item : item?.referenceKindId || ""),
        minimum: Number(typeof item === "string" ? 1 : item?.minimum),
        maximum: Number(typeof item === "string" ? 1 : item?.maximum),
      }))
      : [];
    const returnsLease = operation?.returnsLease === true;
    const safePayloadProjectionId = operation?.safePayloadProjectionId == null
      ? null : String(operation.safePayloadProjectionId);
    const deferredUi = operation?.deferredUi === true;
    const recordDependencies = normalizeRecordOperationDependencies(
      operation?.recordDependencies ?? [],
      scopeId,
      recordDeclarations,
    );
    const singletonDependencies = normalizeSingletonOperationDependencies(
      operation?.singletonDependencies ?? [],
      scopeId,
      singletonDeclarations,
    );
    const artifactDependencies = normalizeArtifactOperationDependencies(
      operation?.artifactDependencies ?? [],
      scopeId,
      artifactDeclarations,
    );
    const externalOperationBinding = normalizeExternalOperationBinding(
      operation?.externalOperationBinding ?? null,
      scopeId,
      route,
      method,
      referenceOutputs,
      returnsLease,
      deferredUi,
      subjectModeBindingId,
    );
    if (
      !/^[a-z0-9][a-z0-9._-]*$/.test(id)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(resourceId)
      || (route !== null && !isSafePrivacyBrowserTarget(route))
      || !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)
      || sensitiveFields === null
      || safeProjection === null
      || (scopeId !== null && !/^[a-z0-9][a-z0-9._-]*$/.test(scopeId))
      || (
        subjectModeBindingId !== null
        && !/^[a-z0-9][a-z0-9._-]*$/.test(subjectModeBindingId)
      )
      || sensitiveFields.some((field) => (
        (field.path !== "*" && !isProjectionPath(field.path))
        || !["user-authored", "path-or-name", "debug", "consumer-derived"]
          .includes(field.class)
      ))
      || safeProjection.some((field) => (
        !isProjectionPath(field.path) || !["boolean", "count"].includes(field.kind)
      ))
      || new Set(sensitiveFields.map((field) => field.path)).size !== sensitiveFields.length
      || new Set(safeProjection.map((field) => field.path)).size !== safeProjection.length
      || ((sensitiveFields.length || safeProjection.length) && scopeId === null)
      || (scopeId !== null && !modeScopes?.some((scope) => scope?.id === scopeId))
      || ((sensitiveFields.length || safeProjection.length) && !sensitiveFields.some(
        (field) => field.path === "*" && field.class === "consumer-derived",
      ))
      || referenceInputs.some((item) => (
        !/^[a-z0-9][a-z0-9._-]*$/.test(item.name)
        || !/^[a-z0-9][a-z0-9._-]*$/.test(item.referenceKindId)
      ))
      || new Set(referenceInputs.map((item) => item.name)).size !== referenceInputs.length
      || referenceOutputs.some((item) => (
        !/^[a-z0-9][a-z0-9._-]*$/.test(item.referenceKindId)
        || !Number.isInteger(item.minimum)
        || !Number.isInteger(item.maximum)
        || item.minimum < 0
        || item.maximum < item.minimum
        || item.maximum > 256
      ))
      || new Set(referenceOutputs.map((item) => item.referenceKindId)).size
        !== referenceOutputs.length
      || seen.has(id)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    seen.add(id);
    return Object.freeze({
      id,
      resourceId,
      route,
      method,
      scopeId,
      subjectModeBindingId,
      sensitiveFields: Object.freeze(sensitiveFields),
      safeProjection: Object.freeze(safeProjection),
      referenceInputs: Object.freeze(referenceInputs),
      referenceOutputs: Object.freeze(referenceOutputs),
      returnsLease,
      safePayloadProjectionId,
      deferredUi,
      recordDependencies,
      singletonDependencies,
      artifactDependencies,
      externalOperationBinding,
    });
  });
}

function normalizeExternalOperationBinding(
  value,
  scopeId,
  route,
  method,
  referenceOutputs,
  returnsLease,
  deferredUi,
  subjectModeBindingId,
) {
  if (value === null) return null;
  const keys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort().join("\0") : "";
  const policy = value?.policy;
  const policyKeys = policy && typeof policy === "object" && !Array.isArray(policy)
    ? Object.keys(policy).sort().join("\0") : "";
  const normalized = {
    fieldId: String(value?.fieldId || ""),
    browserAdapter: String(value?.browserAdapter || ""),
    policy: {
      ownerIdentity: String(policy?.ownerIdentity || ""),
      maxIdentityBytes: Number(policy?.maxIdentityBytes),
      maxOriginalBytes: Number(policy?.maxOriginalBytes),
      maxTargetBytes: Number(policy?.maxTargetBytes),
      leaseSeconds: Number(policy?.leaseSeconds),
    },
  };
  if (
    keys !== "browserAdapter\0fieldId\0policy"
    || policyKeys !== [
      "leaseSeconds",
      "maxIdentityBytes",
      "maxOriginalBytes",
      "maxTargetBytes",
      "ownerIdentity",
    ].join("\0")
    || !isStablePrivacyId(normalized.fieldId)
    || !isStablePrivacyId(normalized.browserAdapter)
    || normalized.policy.ownerIdentity !== "graph-node-v1"
    || !Number.isInteger(normalized.policy.maxIdentityBytes)
    || normalized.policy.maxIdentityBytes < 256
    || normalized.policy.maxIdentityBytes > 64 * 1024
    || !Number.isInteger(normalized.policy.maxOriginalBytes)
    || normalized.policy.maxOriginalBytes < 1024
    || normalized.policy.maxOriginalBytes > 16 * 1024 * 1024
    || !Number.isInteger(normalized.policy.maxTargetBytes)
    || normalized.policy.maxTargetBytes < 1024
    || normalized.policy.maxTargetBytes > 16 * 1024 * 1024
    || !Number.isInteger(normalized.policy.leaseSeconds)
    || normalized.policy.leaseSeconds < 30
    || normalized.policy.leaseSeconds > 900
    || scopeId === null
    || route !== null
    || method !== "POST"
    || referenceOutputs.length
    || returnsLease
    || deferredUi
    || subjectModeBindingId !== null
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  return Object.freeze({
    ...normalized,
    policy: Object.freeze(normalized.policy),
  });
}

function normalizeRecordOperationDependencies(values, scopeId, declarations) {
  if (!Array.isArray(values)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  if (!values.length) return Object.freeze([]);
  if (!Array.isArray(declarations)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  const seen = new Set();
  return Object.freeze(values.map((value) => {
    const keys = value && typeof value === "object" && !Array.isArray(value)
      ? Object.keys(value).sort().join("\0") : "";
    const resourceId = String(value?.resourceId || "");
    const recordKind = String(value?.recordKind || "");
    const operation = String(value?.operation || "");
    const key = `${resourceId}\0${recordKind}\0${operation}`;
    const declaration = declarations.find(
      (item) => item?.id === recordKind && item?.resourceId === resourceId,
    );
    if (
      keys !== "operation\0recordKind\0resourceId"
      || !isStablePrivacyId(resourceId)
      || !isStablePrivacyId(recordKind)
      || !isStablePrivacyId(operation)
      || !declaration
      || declaration.scopeId !== scopeId
      || !Array.isArray(declaration.revealOperations)
      || !declaration.revealOperations.includes(operation)
      || seen.has(key)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    seen.add(key);
    return Object.freeze({ resourceId, recordKind, operation });
  }));
}

function normalizeSingletonOperationDependencies(values, scopeId, declarations) {
  const allowed = new Set(["status", "reveal", "replace", "delete"]);
  if (!Array.isArray(values)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  if (!values.length) return Object.freeze([]);
  if (!Array.isArray(declarations)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  const seen = new Set();
  return Object.freeze(values.map((value) => {
    const keys = value && typeof value === "object" && !Array.isArray(value)
      ? Object.keys(value).sort().join("\0") : "";
    const singletonId = String(value?.singletonId || "");
    const verbs = Array.isArray(value?.verbs) ? value.verbs.map(String) : null;
    const declaration = declarations.find((item) => item?.id === singletonId);
    if (
      keys !== "singletonId\0verbs"
      || !isStablePrivacyId(singletonId)
      || !verbs?.length
      || verbs.some((verb) => !allowed.has(verb))
      || new Set(verbs).size !== verbs.length
      || [...verbs].sort().join("\0") !== verbs.join("\0")
      || !declaration
      || declaration.scopeId !== scopeId
      || seen.has(singletonId)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    seen.add(singletonId);
    return Object.freeze({ singletonId, verbs: Object.freeze(verbs) });
  }));
}

function normalizeArtifactOperationDependencies(values, scopeId, declarations) {
  const allowed = new Set([
    "write", "read", "retire", "release-owner", "reconcile-owner",
  ]);
  if (!Array.isArray(values)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  if (!values.length) return Object.freeze([]);
  if (!Array.isArray(declarations)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  const seen = new Set();
  return Object.freeze(values.map((value) => {
    const keys = value && typeof value === "object" && !Array.isArray(value)
      ? Object.keys(value).sort().join("\0") : "";
    const artifactKind = String(value?.artifactKind || "");
    const verbs = Array.isArray(value?.verbs) ? value.verbs.map(String) : null;
    const declaration = declarations.find((item) => item?.id === artifactKind);
    if (
      keys !== "artifactKind\0verbs"
      || !isStablePrivacyId(artifactKind)
      || !verbs?.length
      || verbs.some((verb) => (
        !allowed.has(verb)
        && !(verb.startsWith("lease.")
          && declaration?.operations?.includes(verb.slice(6)))
      ))
      || new Set(verbs).size !== verbs.length
      || [...verbs].sort().join("\0") !== verbs.join("\0")
      || !declaration
      || declaration.scopeId !== scopeId
      || (verbs.includes("reconcile-owner") && declaration.retention !== "durable-adjunct")
      || (verbs.includes("write") && declaration.retention === "run-scoped-spill")
      || seen.has(artifactKind)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    seen.add(artifactKind);
    return Object.freeze({ artifactKind, verbs: Object.freeze(verbs) });
  }));
}

function isStablePrivacyId(value) {
  return /^[a-z0-9][a-z0-9._-]*$/.test(String(value || ""));
}

function isProjectionPath(value) {
  return String(value || "").split(".").every(
    (segment) => /^[a-z0-9][a-z0-9._-]*$/.test(segment),
  );
}

async function fetchPrivacyJson(endpoint, payload = null) {
  const headers = { "Content-Type": "application/json" };
  const token = readPrivacyToken();
  if (token) headers[PRIVACY_TOKEN_HEADER] = token;
  ensureStoredPrivacyTokenCookie();
  const options = {
    method: payload ? "POST" : "GET",
    headers,
    credentials: "same-origin",
    cache: "no-store",
    ...(payload ? { body: JSON.stringify(payload) } : {}),
  };
  let response;
  try {
    response = await globalThis.fetch(`${ROUTE_PREFIX}/${endpoint}`, options);
  } catch {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_REQUEST_FAILED");
  }
  const data = await readPrivacyBrowserPayload(response);
  if (!response.ok || data.ok === false || data.error) {
    throw privacyBrowserResponseError(response, data);
  }
  return data;
}

export async function fetchPrivacyStatus() {
  const result = await fetchPrivacyJson("status");
  publishPrivacySession(
    !result.keystoreInitialized
      ? "setup-required"
      : (!result.keystoreLocked && readPrivacyToken() ? "unlocked" : "locked"),
    { force: false },
  );
  return result;
}

export async function initializePrivacyKeystore(password) {
  const result = await fetchPrivacyJson("keystore/init", { password });
  storePrivacyToken(result.token || "");
  return privacyResultWithoutToken(result);
}

export async function unlockPrivacyKeystore(password) {
  const result = await fetchPrivacyJson("unlock", { password });
  storePrivacyToken(result.token || "");
  return privacyResultWithoutToken(result);
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
  return privacyResultWithoutToken(result);
}

function privacyResultWithoutToken(result) {
  const { token: _token, ...safe } = result || {};
  return Object.freeze(safe);
}

function normalizeBrowserModeScopes(scopes) {
  if (!Array.isArray(scopes)) return [];
  return scopes.flatMap((scope) => {
    const id = String(scope?.id || "");
    const modeResourceId = String(scope?.modeResourceId || "");
    const modeEditorAdapter = scope?.modeEditorAdapter == null
      ? null
      : String(scope.modeEditorAdapter || "");
    return /^[a-z0-9][a-z0-9._-]*$/.test(id)
      && /^[a-z0-9][a-z0-9._-]*$/.test(modeResourceId)
      && (modeEditorAdapter === null || /^[a-z0-9][a-z0-9._-]*$/.test(modeEditorAdapter))
      ? [Object.freeze({ id, modeResourceId, modeEditorAdapter })]
      : [];
  });
}

function freezeBrowserModeScope(scope) {
  return Object.freeze({
    ...scope,
    floors: Object.freeze(
      (Array.isArray(scope?.floors) ? scope.floors : []).map(
        (floor) => Object.freeze({ ...floor }),
      ),
    ),
  });
}

function normalizeAttestedBrowserIdentity({ packId, profileFingerprint, suiteManifestDigest }) {
  const id = String(packId || "").trim();
  const fingerprint = String(profileFingerprint || "").trim();
  const suiteDigest = String(suiteManifestDigest || "").trim();
  if (
    !/^[a-z0-9][a-z0-9._-]*$/.test(id)
    || !/^[0-9a-f]{64}$/.test(fingerprint)
    || !/^[0-9a-f]{64}$/.test(suiteDigest)
  ) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_IDENTITY_INVALID");
  }
  return Object.freeze({
    packId: id,
    profileFingerprint: fingerprint,
    suiteManifestDigest: suiteDigest,
  });
}

function isSafePrivacyBrowserTarget(target) {
  const value = String(target || "");
  return value.startsWith("/")
    && !value.startsWith("//")
    && !value.includes("?")
    && !value.includes("#")
    && !value.includes("\\");
}

async function readPrivacyBrowserPayload(response) {
  let text = "";
  try {
    text = await response.text();
    return text ? JSON.parse(text) : {};
  } catch {
    throw new PrivacyBrowserRequestError(
      "PRIVACY_BROWSER_RESPONSE_INVALID",
      Number(response?.status || 0),
    );
  }
}

function privacyBrowserResponseError(response, payload) {
  const candidate = String(payload?.error || "");
  const code = /^PRIVACY_[A-Z0-9_]+$/.test(candidate)
    ? candidate
    : "PRIVACY_BROWSER_REQUEST_FAILED";
  return new PrivacyBrowserRequestError(code, Number(response?.status || 0));
}
