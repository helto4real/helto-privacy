// Internal browser transport for the attested profile runtime and shared UI.
// Consumer packs receive compiled resource handles, never this transport.

const ROUTE_PREFIX = "/helto_privacy";
const PRIVACY_TOKEN_HEADER = "X-Helto-Privacy-Token";
const PRIVACY_PACK_HEADER = "X-Helto-Privacy-Pack";
const PRIVACY_PROFILE_HEADER = "X-Helto-Privacy-Profile";
const PRIVACY_SUITE_HEADER = "X-Helto-Privacy-Suite";
const PRIVACY_OPERATION_HEADER = "X-Helto-Privacy-Operation";
const PRIVACY_DECLASSIFICATION_HEADER = "X-Helto-Privacy-Declassification";
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
      ? `${PRIVACY_TOKEN_STORAGE_KEY}=${encodeURIComponent(String(token))}; path=/; SameSite=Lax`
      : `${PRIVACY_TOKEN_STORAGE_KEY}=; path=/; SameSite=Lax; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
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

  async function resolve(resourceId, scopeId) {
    if (!scopes.some(
      (scope) => scope.id === scopeId && scope.modeResourceId === resourceId,
    )) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_MODE_SCOPE_INVALID");
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

  return Object.freeze({ id, scopes, readAll, resolve, transition });
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
    normalizeProtectedOperations(attestation.protectedOperations),
  );
  const mode = createAttestedPrivacyModeClient({
    packId: requestClient.identity.packId,
    modeScopes: attestation.modeScopes,
    requestClient,
  });

  function invoke(resourceId, operationId, body = undefined) {
    const operation = operations.find(
      (item) => item.id === operationId && item.resourceId === resourceId,
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

  return Object.freeze({
    attestation: Object.freeze({ ...attestation }),
    identity: requestClient.identity,
    operations,
    mode,
    invoke,
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

function normalizeProtectedOperations(operations) {
  if (!Array.isArray(operations)) {
    throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
  }
  const seen = new Set();
  return operations.map((operation) => {
    const id = String(operation?.id || "");
    const resourceId = String(operation?.resourceId || "");
    const route = String(operation?.route || "");
    const method = String(operation?.method || "").toUpperCase();
    if (
      !/^[a-z0-9][a-z0-9._-]*$/.test(id)
      || !/^[a-z0-9][a-z0-9._-]*$/.test(resourceId)
      || !isSafePrivacyBrowserTarget(route)
      || !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)
      || seen.has(id)
    ) {
      throw new PrivacyBrowserRequestError("PRIVACY_BROWSER_OPERATION_INVALID");
    }
    seen.add(id);
    return Object.freeze({ id, resourceId, route, method });
  });
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
    return /^[a-z0-9][a-z0-9._-]*$/.test(id)
      && /^[a-z0-9][a-z0-9._-]*$/.test(modeResourceId)
      ? [Object.freeze({ id, modeResourceId })]
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
