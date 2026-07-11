import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVACY_PROFILE = ROOT / "helto_privacy" / "web" / "privacy_profile.js"
PRIVACY_UI = ROOT / "helto_privacy" / "web" / "privacy_ui.js"
PRIVACY_CLIENT = ROOT / "helto_privacy" / "web" / "privacy_client.js"
PRIVACY_SNAPSHOT = ROOT / "helto_privacy" / "web" / "privacy_snapshot.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    (tmp_path / "privacy.js").write_text(PRIVACY_UI.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "privacy_client.js").write_text(
        PRIVACY_CLIENT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "privacy_snapshot.js").write_text(
        PRIVACY_SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8"
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
              protectedOperations: [
                {{
                  id: "record.use",
                  resourceId: "library",
                  route: "/helto-test/records/use",
                  method: "POST",
                }},
              ],
              ...overrides,
            }});
            let serverAttestation = () => attestation();
            const executionBodies = [];
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
        assert(typeof pack.records("library").invoke === "function");
        assert(pack.artifacts("thumbnail") instanceof privacy.BrowserArtifactHandle);
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
        assert.deepEqual(
          await pack.records("library").invoke(
            "record.use",
            { recordId: "synthetic-record" },
          ),
          { ok: true },
        );
        assert.throws(
          () => pack.records("library").invoke(
            "record.delete",
          ),
          (error) => error.code === "unknown_browser_operation",
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
