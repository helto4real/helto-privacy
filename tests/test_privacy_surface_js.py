import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVACY_UI = ROOT / "helto_privacy" / "web" / "privacy_ui.js"
PRIVACY_CLIENT = ROOT / "helto_privacy" / "web" / "privacy_client.js"
PRIVACY_RECORDS = ROOT / "helto_privacy" / "web" / "privacy_records.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module_path = tmp_path / "privacy_ui.js"
    module_path.write_text(PRIVACY_UI.read_text(encoding="utf-8"), encoding="utf-8")
    client_path = tmp_path / "privacy_client.js"
    client_path.write_text(PRIVACY_CLIENT.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "privacy_records.js").write_text(
        PRIVACY_RECORDS.read_text(encoding="utf-8"), encoding="utf-8"
    )
    script_path = tmp_path / "test.mjs"
    script_path.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import * as privacy from {module_path.as_uri()!r};

            class FakeElement {{
              constructor(tag, ownerDocument) {{
                this.tagName = tag.toUpperCase();
                this.ownerDocument = ownerDocument;
                this.children = [];
                this.listeners = {{}};
                this.attributes = {{}};
                this.className = "";
                this.id = "";
                this.textContent = "";
                this.value = "";
                this.disabled = false;
                this.hidden = false;
              }}
              append(...items) {{
                for (const item of items) {{ item.parentNode = this; this.children.push(item); }}
              }}
              prepend(...items) {{
                for (const item of [...items].reverse()) {{ item.parentNode = this; this.children.unshift(item); }}
              }}
              replaceChildren(...items) {{ this.children = []; this.append(...items); }}
              remove() {{
                const index = this.parentNode?.children.indexOf(this) ?? -1;
                if (index >= 0) this.parentNode.children.splice(index, 1);
              }}
              setAttribute(name, value) {{
                this.attributes[name] = String(value);
                if (name === "id") this.id = String(value);
              }}
              getAttribute(name) {{ return this.attributes[name] ?? null; }}
              removeAttribute(name) {{ delete this.attributes[name]; }}
              addEventListener(type, fn) {{ (this.listeners[type] ??= []).push(fn); }}
              focus() {{ this.ownerDocument.activeElement = this; }}
              blur() {{ if (this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = null; }}
              querySelector(selector) {{ return this.querySelectorAll(selector)[0] || null; }}
              querySelectorAll(selector) {{
                const found = [];
                const match = (element) => {{
                  if (selector.startsWith("#")) return element.id === selector.slice(1);
                  if (selector.startsWith(".")) return String(element.className).split(/\\s+/).includes(selector.slice(1));
                  const action = selector.match(/^\\[data-action="([^"]+)"\\]$/);
                  if (action) return element.getAttribute("data-action") === action[1];
                  return element.tagName === selector.toUpperCase();
                }};
                const visit = (element) => {{
                  if (match(element)) found.push(element);
                  for (const child of element.children || []) visit(child);
                }};
                visit(this);
                return found;
              }}
            }}

            class FakeDocument {{
              constructor() {{
                this.head = new FakeElement("head", this);
                this.body = new FakeElement("body", this);
                this.activeElement = null;
                this.cookie = "";
              }}
              createElement(tag) {{ return new FakeElement(tag, this); }}
              getElementById(id) {{
                return [...this.head.querySelectorAll(`#${{id}}`), ...this.body.querySelectorAll(`#${{id}}`)][0] || null;
              }}
              querySelector(selector) {{ return this.body.querySelector(selector); }}
              querySelectorAll(selector) {{ return this.body.querySelectorAll(selector); }}
            }}

            function treeText(element) {{
              return [element.textContent, ...(element.children || []).map(treeText)].join(" ");
            }}

            {textwrap.dedent(body)}
            """
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        ["node", str(script_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_shared_surface_mounts_once_and_exposes_complete_accessible_controls(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const documentRef = new FakeDocument();
        const requests = [];
        const client = (packId) => ({
          id: packId,
          readAll: async () => {
            requests.push({ packId, operation: "mode.status" });
            return {
              ok: true,
              packId,
              scopes: [{
                id: "global",
                modeResourceId: "privacy-mode",
                declared: "inherit",
                effective: "private",
                inheritedFrom: "global",
                floors: [{ kind: "global", sourceId: "global" }],
                transitionStatus: "idle",
              }],
            };
          },
          transition: async (scopeId, target, options) => {
            requests.push({ packId, operation: "mode.transition", scopeId, target, options });
            return { ok: true };
          },
        });
        const fetchStatus = async () => ({
          ok: true,
          keystoreInitialized: true,
          keystoreLocked: true,
          suiteStatus: "active",
          suiteIssueCodes: [],
        });

        const first = privacy.mountSharedPrivacySurface({
          packId: "helto.first",
          readiness: "ready",
          modeScopes: [{ id: "global", modeResourceId: "privacy-mode" }],
          modeClient: client("helto.first"),
          documentRef,
          fetchStatus,
        });
        const second = privacy.mountSharedPrivacySurface({
          packId: "helto.second",
          readiness: "ready",
          modeScopes: [{ id: "global", modeResourceId: "privacy-mode" }],
          modeClient: client("helto.second"),
          documentRef,
          fetchStatus,
        });

        assert.equal(first, second);
        assert.equal(documentRef.querySelectorAll("#helto-privacy-surface").length, 1);
        await first.refresh();
        const root = documentRef.getElementById("helto-privacy-surface");
        assert.equal(root.getAttribute("role"), "region");
        assert.equal(root.getAttribute("aria-label"), "Helto privacy");
        const text = treeText(root);
        for (const label of [
          "Privacy", "Set up", "Unlock", "Change password", "Lock", "Recovery",
          "helto.first", "helto.second", "Private", "Inherited",
          "Source: global", "Transition: idle", "Active floors: global: global",
        ]) assert(text.includes(label), label);
        assert.equal(requests.filter((item) => item.operation === "mode.status").length, 2);
        assert(!text.includes("SYNTHETIC_TOKEN_CANARY"));

        globalThis.document = documentRef;
        globalThis.localStorage = {
          getItem: () => "",
          setItem() {},
          removeItem() {},
        };
        globalThis.fetch = async () => ({
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ ok: true, token: "SYNTHETIC_TOKEN_CANARY" }),
        });
        await privacy.unlockPrivacyKeystore("synthetic password");
        assert.equal(root.getAttribute("data-session-state"), "unlocked");
        assert(!treeText(root).includes("SYNTHETIC_TOKEN_CANARY"));

        const style = documentRef.getElementById("helto-privacy-keystore-ui-style").textContent;
        assert(style.includes("--helto-accent: #fab387"));
        assert(style.includes("--helto-focus: #89b4fa"));
        assert(style.includes(".helto-text-masked::placeholder"));
        assert(style.includes("caret-color: transparent !important"));
        assert(style.includes("pointer-events: none !important"));
        assert(style.includes(".helto-root.is-private.is-revealed"));

        const secret = documentRef.createElement("input");
        secret.value = "SYNTHETIC_DOM_CANARY";
        secret.placeholder = "SYNTHETIC_PLACEHOLDER_CANARY";
        secret.name = "SYNTHETIC_NAME_CANARY";
        secret.setAttribute("title", "SYNTHETIC_TITLE_CANARY");
        root.append(secret);
        assert.equal(privacy.concealPrivacyContent(secret, { mode: "masked" }), true);
        assert.equal(secret.value, "");
        assert.equal(secret.placeholder, "");
        assert.equal(secret.name, "");
        assert.equal(secret.getAttribute("title"), null);
        assert.equal(secret.getAttribute("aria-hidden"), "true");
        assert.equal(secret.inert, true);
        assert(String(secret.className).includes("helto-text-masked"));
        assert(!treeText(root).includes("SYNTHETIC_DOM_CANARY"));
        privacy.preparePrivacyReveal(secret);
        assert.equal(secret.getAttribute("aria-hidden"), null);
        assert.equal(secret.inert, false);
        assert(!String(secret.className).includes("helto-text-masked"));
        assert.equal(secret.value, "");

        const shell = privacy.redactPrivateRecordShell({
          id: "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          kind: "prompt-record",
          private: true,
          label: "SYNTHETIC_LABEL_CANARY",
          name: "SYNTHETIC_NAME_CANARY",
          path: "/SYNTHETIC/PRIVATE/PATH",
          timestamp: "SYNTHETIC_TIMESTAMP_CANARY",
        });
        assert.deepEqual(shell, {
          id: "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          kind: "prompt-record",
          private: true,
          label: "Private record",
        });
        assert(Object.isFrozen(shell));
        assert(!JSON.stringify(shell).includes("SYNTHETIC"));
        assert.equal(privacy.redactPrivateRecordShell({ id: "user-authored-name" }), null);
        assert.equal(privacy.redactPrivateRecordShell({
          id: "0123456789abcdef0123456789abcdef",
          kind: "prompt-record",
          private: true,
        }), null);
        """,
    )


def test_surface_rechecks_missing_routes_and_applies_public_transition(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const documentRef = new FakeDocument();
        let statusCalls = 0;
        const transitions = [];
        const modeClient = {
          id: "helto.test",
          readAll: async () => {
              statusCalls += 1;
              if (statusCalls === 1) throw Object.assign(new Error("safe"), { code: "PRIVACY_ROUTE_UNAVAILABLE" });
              return { ok: true, scopes: [] };
          },
          transition: async (scopeId, target, options) => {
            transitions.push({ scopeId, target, options });
            return { ok: true, scopeId: "global", declared: "public", effective: "public", transitionStatus: "idle" };
          },
        };
        const surface = privacy.mountSharedPrivacySurface({
          packId: "helto.test",
          readiness: "ready",
          modeScopes: [{ id: "global", modeResourceId: "privacy-mode" }],
          modeClient,
          documentRef,
          fetchStatus: async () => ({ ok: true, keystoreInitialized: true, keystoreLocked: false, suiteStatus: "active" }),
        });

        await surface.refresh();
        assert(treeText(surface.root).includes("Unavailable"));
        await surface.refresh();
        assert.equal(statusCalls, 2);
        assert(!treeText(surface.root).includes("Unavailable"));
        await surface.transition("helto.test", "global", "public");
        assert.equal(transitions.length, 1);
        assert.equal(transitions[0].target, "public");
        """,
    )


def test_private_record_mutation_dialog_is_generic_styled_and_cancel_first(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const documentRef = new FakeDocument();
        const pendingDelete = privacy.showPrivateRecordMutationDialog(
          "delete",
          { documentRef },
        );
        const dialog = documentRef.querySelector(".helto-privacy-record-mutation-dialog");
        assert(dialog);
        assert.equal(dialog.getAttribute("role"), "dialog");
        assert.equal(dialog.getAttribute("aria-modal"), "true");
        assert.equal(documentRef.activeElement.textContent, "Cancel");
        const text = treeText(dialog);
        assert(text.includes("Delete private record"));
        assert(!text.includes("hp-rec-"));
        assert(!text.includes("prompt-record"));
        assert(!text.includes("SYNTHETIC"));
        const buttons = dialog.querySelectorAll("button");
        const destructive = buttons.find((button) => button.textContent === "Delete");
        assert(String(destructive.className).includes("is-danger"));
        destructive.listeners.click[0]();
        assert.equal(await pendingDelete, true);
        assert.equal(documentRef.querySelector(".helto-privacy-record-mutation-dialog"), null);

        const pendingReplace = privacy.showPrivateRecordMutationDialog(
          "replace",
          { documentRef },
        );
        const replaceDialog = documentRef.querySelector(
          ".helto-privacy-record-mutation-dialog",
        );
        const cancel = replaceDialog.querySelectorAll("button")
          .find((button) => button.textContent === "Cancel");
        cancel.listeners.click[0]();
        assert.equal(await pendingReplace, false);
        assert.equal(await privacy.showPrivateRecordMutationDialog(
          "merge",
          { documentRef },
        ), false);

        const first = privacy.showPrivateRecordMutationDialog(
          "delete",
          { documentRef },
        );
        const second = privacy.showPrivateRecordMutationDialog(
          "replace",
          { documentRef },
        );
        assert.equal(await first, false);
        assert.equal(documentRef.querySelectorAll(
          ".helto-privacy-record-mutation-dialog",
        ).length, 1);
        const current = documentRef.querySelector(
          ".helto-privacy-record-mutation-dialog",
        );
        assert(treeText(current).includes("Replace private record"));
        current.querySelectorAll("button")
          .find((button) => button.textContent === "Cancel")
          .listeners.click[0]();
        assert.equal(await second, false);
        """,
    )


def test_failed_transition_refreshes_blocked_status_and_is_handled_by_apply(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const documentRef = new FakeDocument();
        let blocked = false;
        let reads = 0;
        const modeClient = {
          id: "helto.test",
          readAll: async () => {
            reads += 1;
            return {
              ok: true,
              scopes: [{
                id: "global",
                modeResourceId: "privacy-mode",
                declared: "private",
                effective: "private",
                inheritedFrom: "global",
                floors: [],
                transitionStatus: blocked ? "blocked" : "idle",
              }],
            };
          },
          transition: async () => {
            blocked = true;
            throw Object.assign(new Error("MUST_NOT_RENDER"), {
              code: "PRIVACY_MODE_TRANSITION_FAILED",
            });
          },
        };
        const surface = privacy.mountSharedPrivacySurface({
          packId: "helto.test",
          readiness: "ready",
          modeScopes: [{ id: "global", modeResourceId: "privacy-mode" }],
          modeClient,
          documentRef,
          fetchStatus: async () => ({
            ok: true,
            keystoreInitialized: true,
            keystoreLocked: false,
            suiteStatus: "active",
          }),
        });
        await surface.refresh();

        const apply = surface.root.querySelector('[data-action="mode-transition"]');
        await apply.listeners.click[0]();

        const text = treeText(surface.root);
        assert(reads >= 2);
        assert(text.includes("Privacy mode transition failed."));
        assert(text.includes("Transition: blocked"));
        assert(!text.includes("MUST_NOT_RENDER"));
        """,
    )
