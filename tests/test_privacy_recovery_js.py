import subprocess
import textwrap
from pathlib import Path

from tests.privacy_js_test_support import write_privacy_client_dependencies


ROOT = Path(__file__).resolve().parents[1]
PRIVACY_UI = ROOT / "helto_privacy" / "web" / "privacy_ui.js"
PRIVACY_CLIENT = ROOT / "helto_privacy" / "web" / "privacy_client.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module_path = tmp_path / "privacy_ui.js"
    module_path.write_text(PRIVACY_UI.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "privacy_client.js").write_text(
        PRIVACY_CLIENT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    write_privacy_client_dependencies(tmp_path)
    script_path = tmp_path / "test.mjs"
    script_path.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import * as privacy from {module_path.as_uri()!r};

            function envelope(schema = "helto.test", extra = {{}}) {{
              return {{
                version: 1,
                encrypted: true,
                algorithm: "AES-256-GCM",
                schema,
                keyId: "key",
                nonce: "nonce",
                ciphertext: "ciphertext",
                ...extra,
              }};
            }}

            function descriptor(overrides = {{}}) {{
              return {{
                nodeType: "HeltoImageSelector",
                label: "Helto Multi-Image Selector",
                schema: "helto.test",
                privacy: {{ property: "privacyMode", default: true }},
                fields: [
                  {{
                    kind: "widget",
                    name: "selected_images",
                    label: "Selected images",
                    defaultValue: "[]",
                    sensitive: true,
                    runtimeProperty: "runtimeSecret",
                  }},
                ],
                ...overrides,
              }};
            }}

            function node(value, properties = {{ privacyMode: true }}) {{
              return {{
                id: 7,
                type: "HeltoImageSelector",
                title: "Selector node",
                properties,
                widgets: [{{ name: "selected_images", value }}],
                setDirtyCanvas() {{ this.dirty = true; }},
              }};
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


def test_descriptor_registration_is_idempotent(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const first = privacy.registerPrivacyRecoveryDescriptors("utils", [descriptor(), descriptor()]);
        const second = privacy.registerPrivacyRecoveryDescriptors("utils", [descriptor()]);

        assert.equal(first.descriptorCount, 1);
        assert.equal(second.descriptorCount, 1);
        assert.equal(second.totalDescriptors, 1);
        assert.deepEqual(
          privacy.registeredPrivacyRecoveryDescriptors().map((item) => item.sourceId),
          ["utils"],
        );
        """,
    )


def test_scan_detects_recovery_categories_without_leaking_values(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        privacy.registerPrivacyRecoveryDescriptors("utils", [descriptor()]);
        const titledNode = node("VERY_SECRET_PATH");
        titledNode.title = "SYNTHETIC_PRIVATE_TITLE_CANARY";
        titledNode.label = "SYNTHETIC_PRIVATE_LABEL_CANARY";
        const graph = { nodes: [
          node("__HELTO_ENC__:private-path"),
          titledNode,
          node(JSON.stringify(envelope("wrong.schema"))),
          node("[]", {}),
        ] };

        const issues = privacy.scanPrivacyRecoveryIssues(graph);
        const types = issues.map((issue) => issue.type).sort();

        assert.deepEqual(types, [
          "invalid_encrypted_value",
          "legacy_encrypted_value",
          "missing_privacy_setting",
          "plaintext_sensitive_value",
        ].sort());

        const publicIssues = JSON.stringify(issues);
        const dialogModel = JSON.stringify(privacy.buildPrivacyRecoveryDialogModel(issues));
        assert(!publicIssues.includes("VERY_SECRET_PATH"));
        assert(!publicIssues.includes("private-path"));
        assert(!dialogModel.includes("VERY_SECRET_PATH"));
        assert(!dialogModel.includes("private-path"));
        assert(!dialogModel.includes("SYNTHETIC_PRIVATE_TITLE_CANARY"));
        assert(!dialogModel.includes("SYNTHETIC_PRIVATE_LABEL_CANARY"));
        """,
    )


def test_reset_applies_defaults_clears_runtime_memo_and_marks_dirty(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        privacy.registerPrivacyRecoveryDescriptors("utils", [descriptor()]);
        const graphNode = node("__HELTO_ENC__:old-secret");
        graphNode.runtimeSecret = "runtime-only";
        const graph = { nodes: [graphNode] };
        privacy.rememberPrivacyEnvelope(
          graphNode,
          "selected_images",
          "plain secret",
          envelope(),
          { schema: "helto.test" },
        );

        const result = await privacy.recoverPrivacyIssues({ action: "reset", graph });

        assert.equal(result.ok, true);
        assert.equal(graphNode.widgets[0].value, "[]");
        assert.equal("runtimeSecret" in graphNode, false);
        assert.equal(graphNode.dirty, true);

        let encryptCalls = 0;
        await privacy.ensureEncryptedPrivacyValue({
          owner: graphNode,
          fieldName: "selected_images",
          value: "plain secret",
          schema: "helto.test",
          encrypt: () => {
            encryptCalls += 1;
            return envelope();
          },
        });
        assert.equal(encryptCalls, 1);
        """,
    )


def test_reencrypt_writes_registered_json_envelope(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let captured = "";
        privacy.registerPrivacyRecoveryDescriptors("utils", [descriptor({
          fields: [{
            kind: "widget",
            name: "selected_images",
            defaultValue: "[]",
            sensitive: true,
            schema: "helto.test",
            reencrypt: (plaintext, context) => {
              captured = plaintext;
              assert.equal("token" in context, false);
              return { encrypted: envelope("helto.test") };
            },
          }],
        })]);
        const graphNode = node("VERY_SECRET_PATH");
        const result = await privacy.recoverPrivacyIssues({ action: "reencrypt", graph: { nodes: [graphNode] } });

        assert.equal(result.ok, true);
        assert.equal(captured, "VERY_SECRET_PATH");
        assert.equal(JSON.parse(graphNode.widgets[0].value).schema, "helto.test");
        """,
    )


def test_locked_encryption_opens_auto_unlock_flow_and_retries(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        function fakeResponse(payload, status = 200) {
          return {
            ok: status < 400,
            status,
            statusText: status < 400 ? "OK" : "Error",
            text: async () => JSON.stringify(payload),
          };
        }

        class FakeElement {
          constructor(tag, ownerDocument) {
            this.tagName = tag.toUpperCase();
            this.ownerDocument = ownerDocument;
            this.children = [];
            this.listeners = {};
            this.className = "";
            this.value = "";
            this.disabled = false;
          }
          append(...items) {
            for (const item of items) {
              item.parentNode = this;
              this.children.push(item);
            }
          }
          remove() {
            this.parentNode?.children.splice(this.parentNode.children.indexOf(this), 1);
          }
          setAttribute() {}
          focus() { this.ownerDocument.activeElement = this; }
          addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
          click() { for (const fn of this.listeners.click ?? []) fn({ target: this }); }
          querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
          querySelectorAll(selector) {
            const found = [];
            const matches = (el) => {
              if (selector === "input") return el.tagName === "INPUT";
              if (selector === "button.primary") return el.tagName === "BUTTON" && String(el.className).split(/\\s+/).includes("primary");
              if (selector.startsWith(".")) return String(el.className).split(/\\s+/).includes(selector.slice(1));
              return false;
            };
            const visit = (el) => {
              if (matches(el)) found.push(el);
              for (const child of el.children || []) visit(child);
            };
            visit(this);
            return found;
          }
        }

        class FakeDocument {
          constructor() {
            this.head = new FakeElement("head", this);
            this.body = new FakeElement("body", this);
            this.activeElement = null;
          }
          createElement(tag) { return new FakeElement(tag, this); }
          getElementById() { return null; }
          querySelector(selector) { return this.body.querySelector(selector); }
          querySelectorAll(selector) { return this.body.querySelectorAll(selector); }
        }

        const storage = new Map();
        globalThis.localStorage = {
          getItem: (key) => storage.get(key) || "",
          setItem: (key, value) => storage.set(key, String(value)),
          removeItem: (key) => storage.delete(key),
        };
        globalThis.document = new FakeDocument();
        const fetchCalls = [];
        globalThis.fetch = async (url) => {
          fetchCalls.push(String(url));
          if (String(url).endsWith("/status")) {
            return fakeResponse({ ok: true, keystoreInitialized: true, keystoreLocked: true });
          }
          if (String(url).endsWith("/unlock")) {
            return fakeResponse({ ok: true, token: "token-1", keystoreInitialized: true, keystoreLocked: false });
          }
          throw new Error(`Unexpected fetch: ${url}`);
        };

        let encryptCalls = 0;
        const pending = privacy.ensureEncryptedPrivacyValue({
          value: "VERY_SECRET_PATH",
          schema: "helto.test",
          encrypt: () => {
            encryptCalls += 1;
            if (encryptCalls === 1) throw new Error("PRIVACY_LOCKED: locked");
            return envelope();
          },
        });
        for (let i = 0; i < 20 && !globalThis.document.querySelector("input"); i += 1) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
        const input = globalThis.document.querySelector("input");
        input.value = "correct horse battery";
        globalThis.document.querySelector("button.primary").click();
        const encrypted = await pending;

        assert.equal(encryptCalls, 2);
        assert.equal(JSON.parse(encrypted).schema, "helto.test");
        assert(fetchCalls.some((url) => url.endsWith("/status")));
        assert(fetchCalls.some((url) => url.endsWith("/unlock")));
        assert.equal(storage.get("helto_privacy_token"), "token-1");
        """,
    )


def test_fail_closed_helper_rejects_invalid_encryption_response(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        await assert.rejects(
          () => privacy.ensureEncryptedPrivacyValue({
            value: "VERY_SECRET_PATH",
            schema: "helto.test",
            encrypt: () => "",
          }),
          /PRIVACY_ENCRYPTION_FAILED/,
        );
        """,
    )
