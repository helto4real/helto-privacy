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
const DIALOG_CLASS = "helto-privacy-keystore-dialog";
const STYLE_ID = "helto-privacy-keystore-ui-style";

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
    .${DIALOG_CLASS} {
      --htd-bg: #0d1320; --htd-surface: #151c2a; --htd-surface-2: #1b2333; --htd-surface-3: #232d3f; --htd-surface-hover: #2c3850;
      --htd-border: #2a3346; --htd-border-strong: #3a465c; --htd-border-hover: #4c5970; --htd-text: #e7ebf3; --htd-text-dim: #9aa6bd; --htd-text-faint: #6f7c95;
      --htd-accent: #f1c75c; --htd-accent-strong: #ffd873; --htd-accent-border: rgba(241,199,92,0.55);
      --htd-focus: #5e9bff; --htd-ring: 0 0 0 2px rgba(94,155,255,0.5); --htd-danger: #ec5a6b;
      --htd-radius-sm: 5px; --htd-radius-lg: 10px; --htd-shadow-pop: 0 14px 36px rgba(0,0,0,0.55);
    }
    .${DIALOG_CLASS} { position: fixed; inset: 0; z-index: 10090; display: flex; align-items: center; justify-content: center; background: rgba(6,9,15,0.72); backdrop-filter: blur(4px); color: var(--htd-text-dim); font: 12px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; -webkit-font-smoothing: antialiased; }
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
  `;
  documentRef.head?.append(style);
}
