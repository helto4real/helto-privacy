import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVACY_PROFILE = ROOT / "helto_privacy" / "web" / "privacy_profile.js"
PRIVACY_UI = ROOT / "helto_privacy" / "web" / "privacy_ui.js"
PRIVACY_CLIENT = ROOT / "helto_privacy" / "web" / "privacy_client.js"
PRIVACY_SNAPSHOT = ROOT / "helto_privacy" / "web" / "privacy_snapshot.js"
PRIVACY_RECORDS = ROOT / "helto_privacy" / "web" / "privacy_records.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    (tmp_path / "privacy.js").write_text(PRIVACY_UI.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "privacy_client.js").write_text(
        PRIVACY_CLIENT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "privacy_snapshot.js").write_text(
        PRIVACY_SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "privacy_records.js").write_text(
        PRIVACY_RECORDS.read_text(encoding="utf-8"), encoding="utf-8"
    )
    module_path = tmp_path / "privacy_profile" / "privacy_profile.js"
    module_path.parent.mkdir()
    module_path.write_text(PRIVACY_PROFILE.read_text(encoding="utf-8"), encoding="utf-8")
    script_path = tmp_path / "test.mjs"
    script_path.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import * as privacy from {module_path.as_uri()!r};

            const fingerprint = "a".repeat(64);
            const suiteDigest = "d".repeat(64);
            const attestation = (overrides = {{}}) => ({{
              id: "helto.director",
              contract: privacy.PRIVACY_CONTRACT_V2,
              fingerprint,
              status: "ready",
              suiteStatus: "active",
              suiteManifestDigest: suiteDigest,
              requiredBrowserAdapters: [{{
                id: "timeline-editor",
                nodeTypes: ["HeltoTimeline"],
                methods: [
                  "apply",
                  "clear",
                  "normalize",
                  "onPrivacySessionChange",
                  "readProtected",
                  "reconcileNode",
                  "reconcileNodeDefinition",
                  "writeProtected",
                ],
              }}],
              resources: [
                {{ id: "privacy-mode", kind: "mode" }},
                {{ id: "timeline", kind: "workflow" }},
                {{ id: "library", kind: "record" }},
                {{ id: "thumbnail", kind: "artifact" }},
                {{ id: "render", kind: "execution" }},
              ],
              modeScopes: [
                {{ id: "global", modeResourceId: "privacy-mode" }},
              ],
              protectedFields: [{{
                id: "timeline-state",
                workflowResourceId: "timeline",
                scopeId: "global",
                browserAdapter: "timeline-editor",
                nodeTypes: ["HeltoTimeline"],
                execution: true,
              }}],
              executionProjections: [{{
                id: "timeline-render",
                executionResourceId: "render",
                workflowResourceId: "timeline",
              }}],
              records: [{{
                id: "prompt-record",
                resourceId: "library",
                scopeId: "global",
                revealOperations: ["use", "details"],
              }}],
              artifacts: [{{
                id: "thumbnail",
                resourceId: "thumbnail",
                scopeId: "global",
                retention: "regenerable-cache",
                operations: ["preview"],
                mediaType: "image/webp",
              }}],
              protectedOperations: [],
              ...overrides,
            }});
            let serverAttestation = () => attestation();
            const executionBodies = [];
            const recordCalls = [];
            const artifactCalls = [];
            globalThis.fetch = async (url, options = {{}}) => {{
              const target = String(url);
              let payload = {{ ok: true }};
              if (target.endsWith("/disposition")) {{
                payload = {{ ok: true, disposition: "verified-current" }};
              }} else if (target.endsWith("/protect")) {{
                payload = {{ ok: true, envelope: "SYNTHETIC_CURRENT_ENVELOPE" }};
              }} else if (target.endsWith("/modes")) {{
                payload = {{ ok: true, scopes: [{{
                  id: "global",
                  modeResourceId: "privacy-mode",
                  declared: "private",
                  effective: "private",
                  inheritedFrom: "base-private",
                  floors: [],
                  transitionStatus: "idle",
                }}] }};
              }} else if (target.endsWith("/executions/render/prepare")) {{
                executionBodies.push(JSON.parse(options.body));
                payload = {{
                  ok: true,
                  reference: {{
                    schema: "helto.private-execution-reference",
                    version: 1,
                    grant: "SYNTHETIC_OPAQUE_GRANT",
                  }},
                }};
              }} else if (target.includes("/records/library/prompt-record")) {{
                recordCalls.push({{ target, options }});
                if (options.method === "GET") payload = {{ ok: true, records: [{{
                  id: "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
                  kind: "prompt-record",
                  private: true,
                  label: "SYNTHETIC_LABEL_CANARY",
                  name: "SYNTHETIC_NAME_CANARY",
                  path: "/SYNTHETIC/PRIVATE/PATH",
                }}] }};
                else if (target.endsWith("/reveal/use")) payload = {{
                  ok: true,
                  value: {{ prompt: "SYNTHETIC_AUTHORIZED_PROMPT" }},
                  correlationId: "hp-record-abcdefghijklmnop",
                }};
                else payload = {{ ok: true, operation: target.split("/").at(-1) }};
              }} else if (target.includes("/artifacts/thumbnail/thumbnail/")) {{
                artifactCalls.push({{ target, options }});
                payload = {{
                  ok: true,
                  lease: {{
                    url: "/helto_privacy/artifacts/hp-lease-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
                    expiresInSeconds: 60,
                  }},
                }};
              }} else if (target.includes("/profiles/") && !target.endsWith("/modes")) {{
                payload = serverAttestation();
              }} else if (target.endsWith("/unlock")) {{
                payload = {{ ok: true, token: "SYNTHETIC_SESSION_TOKEN" }};
              }}
              return {{
                ok: true,
                status: 200,
                async json() {{ return payload; }},
                async text() {{ return JSON.stringify(payload); }},
              }};
            }};

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


def test_browser_connection_attests_and_reconciles_existing_and_future_nodes(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const calls = [];
        const sessionCalls = [];
        const existingNode = {
          id: 1,
          type: "HeltoTimeline",
          live: { value: "initial" },
          protected: "SYNTHETIC_ENVELOPE",
        };
        const nestedNode = {
          id: 5,
          type: "HeltoTimeline",
          live: { value: "nested" },
          protected: "SYNTHETIC_ENVELOPE",
        };
        const adapter = {
          secret: "MUST_NOT_ESCAPE",
          apply() {},
          clear() {},
          normalize(node) { return node.live || {}; },
          readProtected(node) { return node.protected || "SYNTHETIC_ENVELOPE"; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange(session) { sessionCalls.push(session); },
          reconcileNode(node, context) { calls.push([node.id, context.phase]); },
          reconcileNodeDefinition(_nodeType, nodeData, context) {
            calls.push([nodeData.name, context.phase]);
          },
        };
        const app = {
          rootGraph: {
            _nodes: [existingNode, { id: 2, type: "Other" }],
            subgraphs: new Map([["nested", { _nodes: [nestedNode] }]]),
          },
          registeredNodeTypes: {
            HeltoTimeline: { nodeData: { name: "HeltoTimeline" } },
            Other: { nodeData: { name: "Other" } },
          },
          registerExtension(extension) { this.extension = extension; this.registerCount = (this.registerCount || 0) + 1; },
        };
        const options = {
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        };

        const pack = await privacy.connectPrivacyPack(options);
        assert.equal(pack.readiness.state, "ready");
        assert.equal(pack.suiteManifestDigest, suiteDigest);
        pack.readiness.requireReady();
        assert.equal(app.registerCount, 1);
        assert.deepEqual(calls, [
          ["HeltoTimeline", "definition-existing"],
          [1, "existing"],
          [5, "existing"],
        ]);
        assert(pack.authorization instanceof privacy.BrowserAuthorizationHandle);
        assert.equal(typeof pack.authorization.request, "undefined");
        assert(typeof pack.session.subscribe === "function");
        assert(pack.mode("privacy-mode") instanceof privacy.BrowserModeHandle);
        const timeline = pack.workflow("timeline");
        assert(timeline instanceof privacy.BrowserWorkflowHandle);
        assert.equal(typeof timeline.runWithSnapshot, "function");
        existingNode.live = { value: "edited" };
        timeline.markEdited(existingNode, "timeline-state");
        await timeline.settle("manual-save");
        assert.equal(
          timeline.workflowProjection(existingNode, "timeline-state"),
          "SYNTHETIC_CURRENT_ENVELOPE",
        );
        assert.equal(
          timeline.executionProjection(existingNode, "timeline-state"),
          "SYNTHETIC_CURRENT_ENVELOPE",
        );
        assert(pack.records("library") instanceof privacy.BrowserRecordHandle);
        const records = pack.records("library");
        assert.equal(typeof records.invoke, "undefined");
        const shells = await records.list("prompt-record");
        assert.deepEqual(shells, [{
          id: "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          kind: "prompt-record",
          private: true,
          label: "Private record",
        }]);
        assert(!JSON.stringify(shells).includes("SYNTHETIC"));
        assert.deepEqual(
          await records.reveal(
            "prompt-record",
            "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            "use",
          ),
          {
            ok: true,
            value: { prompt: "SYNTHETIC_AUTHORIZED_PROMPT" },
            correlationId: "hp-record-abcdefghijklmnop",
          },
        );
        class ConfirmationElement {
          constructor(tag, ownerDocument) {
            this.tagName = tag.toUpperCase(); this.ownerDocument = ownerDocument;
            this.children = []; this.listeners = {}; this.attributes = {};
            this.className = ""; this.textContent = "";
          }
          append(...items) { for (const item of items) { item.parentNode = this; this.children.push(item); } }
          remove() { const index = this.parentNode?.children.indexOf(this) ?? -1; if (index >= 0) this.parentNode.children.splice(index, 1); }
          setAttribute(name, value) { this.attributes[name] = String(value); }
          addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
          focus() { this.ownerDocument.activeElement = this; }
          querySelectorAll(selector) {
            const matches = [];
            const visit = (element) => {
              const match = selector.startsWith(".")
                ? String(element.className).split(/\\s+/).includes(selector.slice(1))
                : element.tagName === selector.toUpperCase();
              if (match) matches.push(element);
              for (const child of element.children) visit(child);
            };
            visit(this);
            return matches;
          }
        }
        class ConfirmationDocument {
          constructor() {
            this.head = new ConfirmationElement("head", this);
            this.body = new ConfirmationElement("body", this);
            this.activeElement = null;
            this.cookie = "";
          }
          createElement(tag) { return new ConfirmationElement(tag, this); }
          querySelectorAll(selector) { return this.body.querySelectorAll(selector); }
          querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
          getElementById(id) {
            return [...this.head.children, ...this.body.children]
              .find((element) => element.id === id) || null;
          }
        }
        globalThis.document = new ConfirmationDocument();
        const confirmationMessages = [];
        const finishRecordConfirmation = async (pending, buttonLabel) => {
          const dialog = document.querySelector(".helto-privacy-record-mutation-dialog");
          const text = (element) => [
            element.textContent,
            ...element.children.map(text),
          ].join(" ");
          confirmationMessages.push(text(dialog));
          const button = dialog.querySelectorAll("button")
            .find((candidate) => candidate.textContent === buttonLabel);
          button.listeners.click[0]();
          return pending;
        };
        await finishRecordConfirmation(records.delete(
          "prompt-record",
          "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        ), "Delete");
        await finishRecordConfirmation(records.replace(
          "prompt-record",
          "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          "SYNTHETIC_PROTECTED_VALUE",
        ), "Replace");
        assert.equal(confirmationMessages.length, 2);
        assert(confirmationMessages.every(
          (message) => !message.includes("hp-rec-") && !message.includes("prompt-record"),
        ));
        const recordCallCount = recordCalls.length;
        const cancelled = records.delete(
          "prompt-record",
          "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        );
        const cancelDialog = document.querySelector(".helto-privacy-record-mutation-dialog");
        cancelDialog.querySelectorAll("button")
          .find((button) => button.textContent === "Cancel")
          .listeners.click[0]();
        assert.equal(
          await cancelled,
          null,
        );
        assert.equal(recordCalls.length, recordCallCount);
        const browserArtifacts = pack.artifacts("thumbnail");
        assert(browserArtifacts instanceof privacy.BrowserArtifactHandle);
        assert.equal(typeof browserArtifacts.invoke, "undefined");
        const artifactLease = await browserArtifacts.lease(
          "thumbnail",
          {
            schema: "helto.private-artifact-reference",
            version: 1,
            id: "hp-art-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          },
          "preview",
        );
        assert.deepEqual(artifactLease, {
          url: "/helto_privacy/artifacts/hp-lease-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          expiresInSeconds: 60,
        });
        assert.equal(artifactCalls.length, 1);
        assert.equal(
          artifactCalls[0].target,
          "/helto_privacy/profiles/helto.director/artifacts/thumbnail/thumbnail/"
            + "hp-art-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6/lease/preview",
        );
        assert(pack.execution("render") instanceof privacy.BrowserExecutionHandle);
        assert.throws(
          () => pack.execution("render").prepare(existingNode),
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_INVALID",
        );
        await assert.rejects(
          timeline.runWithSnapshot(
            "manual-save",
            () => pack.execution("render").prepare(existingNode),
          ),
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_INVALID",
        );
        const preparedExecution = await timeline.runWithSnapshot(
          "direct-queue",
          () => pack.execution("render").prepare(existingNode),
        );
        assert.equal(preparedExecution.reference.grant, "SYNTHETIC_OPAQUE_GRANT");
        assert.deepEqual(executionBodies, [{
          projectionId: "timeline-render",
          fields: [{
            fieldId: "timeline-state",
            protectedValue: "SYNTHETIC_CURRENT_ENVELOPE",
          }],
        }]);
        assert.throws(
          () => records.reveal(
            "prompt-record",
            "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            "merge",
          ),
          (error) => error.code === "unknown_browser_record_operation",
        );

        await app.extension.nodeCreated({ id: 3, type: "HeltoTimeline" });
        await app.extension.loadedGraphNode({ id: 4, comfyClass: "HeltoTimeline" });
        await app.extension.beforeRegisterNodeDef(class HeltoTimeline {}, { name: "HeltoTimeline" });
        assert.deepEqual(calls, [
          ["HeltoTimeline", "definition-existing"],
          [1, "existing"],
          [5, "existing"],
          [3, "created"],
          [4, "loaded"],
          ["HeltoTimeline", "definition"],
        ]);

        assert.equal(await privacy.connectPrivacyPack(options), pack);
        assert.equal(app.registerCount, 1);
        assert(!JSON.stringify(pack).includes("MUST_NOT_ESCAPE"));
        assert.equal("token" in pack, false);
        assert.equal("decrypt" in pack, false);

        const sessionEvents = [];
        const unsubscribe = pack.session.subscribe((event) => sessionEvents.push(event));
        globalThis.localStorage = {
          getItem: () => "",
          setItem() {},
          removeItem() {},
        };
        const shared = await import(new URL("./privacy.js", import.meta.url));
        await shared.unlockPrivacyKeystore("synthetic password");
        assert.equal(sessionEvents.at(-1).state, "unlocked");
        assert.equal(sessionCalls.at(-1).state, "unlocked");
        assert(!JSON.stringify(sessionEvents).includes("SYNTHETIC_SESSION_TOKEN"));
        assert(!JSON.stringify(sessionCalls).includes("SYNTHETIC_SESSION_TOKEN"));
        unsubscribe();
        """,
    )


def test_browser_connection_blocks_drift_missing_adapters_and_partial_readiness(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const app = { graph: { nodes: [] }, registerExtension() {} };
        const base = {
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": {
                apply() {}, clear() {}, normalize(node) { return node.live || {}; },
                readProtected(node) { return node.protected || "SYNTHETIC_ENVELOPE"; },
                writeProtected(node, value) { node.protected = value; },
                onPrivacySessionChange() {},
                reconcileNode() {}, reconcileNodeDefinition() {},
          } },
        };

        serverAttestation = () => attestation({ fingerprint: "b".repeat(64) });
        await assert.rejects(
          () => privacy.connectPrivacyPack(base),
          (error) => error.code === "browser_server_attestation_drift"
            && !error.message.includes("helto.director"),
        );
        serverAttestation = () => attestation();
        await assert.rejects(
          () => privacy.connectPrivacyPack({
            ...base,
            suiteManifestDigest: "e".repeat(64),
          }),
          (error) => error.code === "browser_server_attestation_drift",
        );
        await assert.rejects(
          () => privacy.connectPrivacyPack({
            ...base,
            adapters: {},
          }),
          (error) => error.code === "browser_adapter_mismatch",
        );
        await assert.rejects(
          () => privacy.connectPrivacyPack({
            ...base,
            adapters: { "timeline-editor": {} },
          }),
          (error) => error.code === "browser_adapter_mismatch",
        );
        serverAttestation = () => attestation({ status: "waiting_for_prompt_server" });
        await assert.rejects(
          () => privacy.connectPrivacyPack(base),
          (error) => error.code === "server_profile_not_ready",
        );

        serverAttestation = () => attestation({ suiteStatus: "activation-required" });
        const verificationPack = await privacy.connectPrivacyPack(base);
        verificationPack.readiness.requireReady();
        assert.throws(
          () => verificationPack.authorization.requireReady(),
          (error) => error.code === "server_suite_not_active",
        );
        """,
    )


def test_browser_same_fingerprint_is_idempotent_but_different_fingerprint_conflicts(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const app = { graph: { nodes: [] }, registerExtension() {} };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live || {}; },
          readProtected(node) { return node.protected || "SYNTHETIC_ENVELOPE"; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {},
          reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });

        assert.equal(await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": {
                    apply() {}, clear() {}, normalize(node) { return node.live || {}; },
                    readProtected(node) { return node.protected || "SYNTHETIC_ENVELOPE"; },
                    writeProtected(node, value) { node.protected = value; },
                onPrivacySessionChange() {},
                reconcileNode() {}, reconcileNodeDefinition() {},
          } },
        }), pack);
        await assert.rejects(
          () => privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: { "timeline-editor": {} },
          }),
          (error) => error.code === "browser_adapter_mismatch",
        );
        assert.equal(pack.readiness.state, "ready");

        await assert.rejects(
          () => privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: "b".repeat(64),
            suiteManifestDigest: suiteDigest,
            adapters: { "timeline-editor": adapter },
          }),
          (error) => error.code === "browser_profile_conflict",
        );
        assert.equal(pack.readiness.state, "conflict");
        assert.throws(() => pack.readiness.requireReady(), /incomplete or conflicting/);
        await assert.rejects(
          () => privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: { "timeline-editor": adapter },
          }),
          (error) => error.code === "browser_pack_blocked",
        );
        """,
    )
