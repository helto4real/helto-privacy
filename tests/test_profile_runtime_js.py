import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRIVACY_PROFILE = ROOT / "helto_privacy" / "web" / "privacy_profile.js"


def run_node_module_test(tmp_path, body: str) -> None:
    module_path = tmp_path / "privacy_profile.mjs"
    module_path.write_text(PRIVACY_PROFILE.read_text(encoding="utf-8"), encoding="utf-8")
    script_path = tmp_path / "test.mjs"
    script_path.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import * as privacy from {module_path.as_uri()!r};

            const fingerprint = "a".repeat(64);
            const attestation = (overrides = {{}}) => ({{
              id: "helto.director",
              contract: privacy.PRIVACY_CONTRACT_V2,
              fingerprint,
              status: "ready",
              requiredBrowserAdapters: [{{ id: "timeline-editor", nodeTypes: ["HeltoTimeline"] }}],
              resources: [
                {{ id: "privacy-mode", kind: "mode" }},
                {{ id: "timeline", kind: "workflow" }},
                {{ id: "library", kind: "record" }},
                {{ id: "thumbnail", kind: "artifact" }},
                {{ id: "render", kind: "execution" }},
              ],
              ...overrides,
            }});

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
        const adapter = {
          secret: "MUST_NOT_ESCAPE",
          reconcileNode(node, context) { calls.push([node.id, context.phase]); },
          reconcileNodeDefinition(_nodeType, nodeData, context) {
            calls.push([nodeData.name, context.phase]);
          },
        };
        const app = {
          graph: { _nodes: [{ id: 1, type: "HeltoTimeline" }, { id: 2, type: "Other" }] },
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
          adapters: { "timeline-editor": adapter },
          fetchProfile: async () => attestation(),
        };

        const pack = await privacy.connectPrivacyPack(options);
        assert.equal(pack.readiness.state, "ready");
        pack.readiness.requireReady();
        assert.equal(app.registerCount, 1);
        assert.deepEqual(calls, [["HeltoTimeline", "definition-existing"], [1, "existing"]]);
        assert(pack.authorization instanceof privacy.BrowserAuthorizationHandle);
        assert(pack.mode("privacy-mode") instanceof privacy.BrowserModeHandle);
        assert(pack.workflow("timeline") instanceof privacy.BrowserWorkflowHandle);
        assert(pack.records("library") instanceof privacy.BrowserRecordHandle);
        assert(pack.artifacts("thumbnail") instanceof privacy.BrowserArtifactHandle);
        assert(pack.execution("render") instanceof privacy.BrowserExecutionHandle);

        await app.extension.nodeCreated({ id: 3, type: "HeltoTimeline" });
        await app.extension.loadedGraphNode({ id: 4, comfyClass: "HeltoTimeline" });
        await app.extension.beforeRegisterNodeDef(class HeltoTimeline {}, { name: "HeltoTimeline" });
        assert.deepEqual(calls, [
          ["HeltoTimeline", "definition-existing"],
          [1, "existing"],
          [3, "created"],
          [4, "loaded"],
          ["HeltoTimeline", "definition"],
        ]);

        assert.equal(await privacy.connectPrivacyPack(options), pack);
        assert.equal(app.registerCount, 1);
        assert(!JSON.stringify(pack).includes("MUST_NOT_ESCAPE"));
        assert.equal("token" in pack, false);
        assert.equal("decrypt" in pack, false);
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
          adapters: { "timeline-editor": {} },
        };

        await assert.rejects(
          () => privacy.connectPrivacyPack({
            ...base,
            fetchProfile: async () => attestation({ fingerprint: "b".repeat(64) }),
          }),
          (error) => error.code === "browser_server_attestation_drift"
            && !error.message.includes("helto.director"),
        );
        await assert.rejects(
          () => privacy.connectPrivacyPack({
            ...base,
            adapters: {},
            fetchProfile: async () => attestation(),
          }),
          (error) => error.code === "browser_adapter_mismatch",
        );
        await assert.rejects(
          () => privacy.connectPrivacyPack({
            ...base,
            fetchProfile: async () => attestation({ status: "waiting_for_prompt_server" }),
          }),
          (error) => error.code === "server_profile_not_ready",
        );
        """,
    )


def test_browser_same_fingerprint_is_idempotent_but_different_fingerprint_conflicts(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const app = { graph: { nodes: [] }, registerExtension() {} };
        const adapter = {};
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          adapters: { "timeline-editor": adapter },
          fetchProfile: async () => attestation(),
        });

        assert.equal(await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          adapters: { "timeline-editor": {} },
          fetchProfile: async () => attestation(),
        }), pack);

        await assert.rejects(
          () => privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: "b".repeat(64),
            adapters: { "timeline-editor": adapter },
            fetchProfile: async () => attestation({ fingerprint: "b".repeat(64) }),
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
            adapters: { "timeline-editor": adapter },
            fetchProfile: async () => attestation(),
          }),
          (error) => error.code === "browser_pack_blocked",
        );
        """,
    )
