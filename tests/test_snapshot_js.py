import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "helto_privacy" / "web" / "privacy_snapshot.js"
SUBMISSION = ROOT / "helto_privacy" / "web" / "privacy_submission.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module_path = tmp_path / "privacy_snapshot.js"
    module_path.write_text(SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "privacy_submission.js").write_text(
        SUBMISSION.read_text(encoding="utf-8"), encoding="utf-8"
    )
    script_path = tmp_path / "test.mjs"
    script_path.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import {{
              ENVELOPE_DISPOSITION,
              PrivacySnapshotError,
              createPrivacySnapshotCoordinator,
              installGraphSerializationBarrier,
              installPrivacyConnectionSerializationGate,
            }} from {module_path.as_uri()!r};

            const field = {{
              id: "private-state",
              workflowResourceId: "state",
              browserAdapter: "state-ui",
              nodeTypes: ["SyntheticNode"],
              currentSchema: "helto.snapshot-test.v1",
            }};

            function adapter() {{
              return {{
                normalize: (node) => node.live,
                readProtected: (node) => node.protected,
                writeProtected: (node, value) => {{ node.protected = value; node.writes.push(value); }},
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


def test_connection_gate_wraps_graph_created_after_extension_import(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const extensions = [];
        class TestApi {
          async fetchApi() { return new Response(); }
          async queuePrompt() { return {}; }
        }
        class TestApp {
          constructor() { this.api = new TestApi(); }
          registerExtension(extension) { extensions.push(extension); }
          async graphToPrompt() { return { workflow: { nodes: [] }, output: {} }; }
          async queuePrompt() { return {}; }
        }
        const app = new TestApp();
        const attempt = installPrivacyConnectionSerializationGate(app);
        attempt.markUnavailable();
        assert.equal(extensions.length, 1);

        app.rootGraph = {
          serialize: () => ({ nodes: [{ type: "SyntheticNode", private: "PLAINTEXT" }] }),
        };
        extensions[0].nodeCreated({ type: "SyntheticNode" });

        assert.throws(
          () => app.rootGraph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_equal_concurrent_preparation_is_deduplicated_and_stale_result_loses(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const node = {
          type: "SyntheticNode",
          live: { value: "initial" },
          protected: "ENVELOPE_INITIAL",
          writes: [],
        };
        const pending = [];
        let protectCalls = 0;
        const transport = {
          disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
          protect: async (_fieldId, value) => {
            protectCalls += 1;
            return await new Promise((resolve) => pending.push({ value, resolve }));
          },
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport,
        });
        await coordinator.registerNode(node);

        node.live = { value: "first" };
        const firstGeneration = coordinator.markEdited(node, "private-state");
        const firstA = coordinator.settle("manual-save");
        const firstB = coordinator.settle("graph-to-prompt");
        await Promise.resolve();
        assert.equal(protectCalls, 1);

        node.live = { value: "second" };
        const secondGeneration = coordinator.markEdited(node, "private-state");
        assert(secondGeneration > firstGeneration);
        const second = coordinator.settle("queue");
        await Promise.resolve();
        assert.equal(protectCalls, 2);

        pending[0].resolve({ envelope: "ENVELOPE_STALE" });
        await Promise.resolve();
        assert(!node.writes.includes("ENVELOPE_STALE"));
        pending[1].resolve({ envelope: "ENVELOPE_SECOND" });
        const settled = await second;
        await Promise.allSettled([firstA, firstB]);

        assert.deepEqual(node.writes, ["ENVELOPE_SECOND"]);
        assert.equal(settled.fields[0].generation, secondGeneration);
        assert.equal(coordinator.workflowProjection(node, "private-state"), "ENVELOPE_SECOND");
        """,
    )


def test_adapter_context_exposes_resolved_effective_mode(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const seen = [];
        const node = {
          type: "SyntheticNode",
          live: { value: "edited" },
          protected: "ENVELOPE_INITIAL",
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: {
            "state-ui": {
              ...adapter(),
              normalize(owner, context) {
                seen.push(context.effectiveMode);
                return owner.live;
              },
            },
          },
          transport: {
            disposition: async () => ({
              disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT,
            }),
            protect: async () => ({ envelope: "ENVELOPE_EDITED" }),
          },
          resolvePrivate: async () => true,
        });
        await coordinator.registerNode(node);
        coordinator.markEdited(node, "private-state");
        await coordinator.settle("manual-save");
        assert.deepEqual(seen, ["private", "private"]);
        """,
    )


def test_locked_and_failed_ciphertext_is_save_only_and_byte_exact(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        for (const disposition of [
          ENVELOPE_DISPOSITION.LOCKED_CURRENT,
          ENVELOPE_DISPOSITION.FAILED_CURRENT,
        ]) {
          const exact = `EXACT_${disposition}_CIPHERTEXT`;
          const node = {
            type: "SyntheticNode",
            live: { value: "MUST_NOT_SUBSTITUTE" },
            protected: exact,
            writes: [],
          };
          const coordinator = createPrivacySnapshotCoordinator({
            packId: "helto.test",
            fields: [field],
            adapters: { "state-ui": adapter() },
            transport: {
              disposition: async () => ({ disposition }),
              protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
            },
          });
          await coordinator.registerNode(node);

          await coordinator.settle("manual-save");
          assert.equal(coordinator.workflowProjection(node, "private-state"), exact);
          assert.deepEqual(node.writes, []);
          assert.throws(
            () => coordinator.executionProjection(node, "private-state"),
            (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
          );
          assert.throws(
            () => coordinator.markEdited(node, "private-state"),
            (error) => error.code === "PRIVACY_SNAPSHOT_REPLACEMENT_BLOCKED",
          );
          assert.equal(node.protected, exact);
          await assert.rejects(
            () => coordinator.settle("direct-queue"),
            (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
          );
        }
        """,
    )


def test_legacy_replacement_is_staged_for_isolated_workflow_projections(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const legacyNode = {
          id: 1,
          type: "SyntheticNode",
          live: {},
          protected: "LEGACY_EXACT",
          writes: [],
        };
        const legacyField = { ...field, legacyReaderIds: ["state-v0"] };
        const projectionContexts = [];
        let legacyDispositionCalls = 0;
        const legacyAdapter = {
          ...adapter(),
          apply(owner, value) { owner.live = value; },
          writeWorkflowProjection(owner, serializedNode, value, context) {
            assert.equal(owner, legacyNode);
            projectionContexts.push(context);
            serializedNode.protected = value;
          },
        };
        const legacy = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [legacyField],
          adapters: { "state-ui": legacyAdapter },
          transport: {
            disposition: async () => {
              legacyDispositionCalls += 1;
              return {
                disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
                replacementEnvelope: `CURRENT_REPLACEMENT_${legacyDispositionCalls}`,
                migrationObligationId: "hp-obligation-synthetic",
              };
            },
            reveal: async (_fieldId, protectedValue) => ({
              value: { revealedFrom: protectedValue },
            }),
            protect: async () => ({ envelope: "EDITED_CURRENT" }),
          },
        });
        await legacy.registerNode(legacyNode);
        const firstTransaction = await legacy.settle("manual-save");
        const secondTransaction = await legacy.settle("export");
        assert.equal(legacy.workflowProjection(legacyNode, "private-state"), "CURRENT_REPLACEMENT_1");
        assert.equal(legacy.executionProjection(legacyNode, "private-state"), "CURRENT_REPLACEMENT_1");
        assert.equal(
          firstTransaction.fields[0].migrationObligationId,
          "hp-obligation-synthetic",
        );
        assert.equal(
          secondTransaction.fields[0].migrationObligationId,
          "hp-obligation-synthetic",
        );
        assert.deepEqual(legacyNode.writes, []);
        assert.equal(legacyNode.protected, "LEGACY_EXACT");
        assert.deepEqual(legacyNode.live, { revealedFrom: "CURRENT_REPLACEMENT_1" });
        await legacy.onSessionChange({ state: "unlocked" });
        await legacy.settle("manual-save");
        assert.equal(legacyDispositionCalls, 2);
        assert.equal(legacy.workflowProjection(legacyNode, "private-state"), "CURRENT_REPLACEMENT_1");

        let rawWorkflow;
        const graph = {
          serialize() {
            rawWorkflow = { nodes: [{ id: 1, type: "SyntheticNode", protected: "LEGACY_EXACT" }] };
            return rawWorkflow;
          },
        };
        legacyNode.graph = graph;
        const app = {
          rootGraph: graph,
          graphToPrompt: async () => ({ workflow: graph.serialize(), output: {} }),
          queuePrompt: async function queuePrompt() { return this.graphToPrompt(); },
        };
        const barrier = installGraphSerializationBarrier(app, () => [legacy]);

        const direct = graph.serialize();
        assert.notEqual(direct, rawWorkflow);
        assert.equal(direct.nodes[0].protected, "CURRENT_REPLACEMENT_1");
        assert.equal(rawWorkflow.nodes[0].protected, "LEGACY_EXACT");
        assert.equal(legacyNode.protected, "LEGACY_EXACT");
        assert(!JSON.stringify(direct).includes("hp-obligation"));
        assert(!JSON.stringify(direct).includes("receipt"));

        const prompt = await app.graphToPrompt();
        assert.equal(prompt.workflow.nodes[0].protected, "CURRENT_REPLACEMENT_1");
        const queued = await app.queuePrompt();
        assert.equal(queued.workflow.nodes[0].protected, "CURRENT_REPLACEMENT_1");
        const exported = await barrier.runWithSnapshot("export", () => graph.serialize());
        assert.equal(exported.nodes[0].protected, "CURRENT_REPLACEMENT_1");
        assert(projectionContexts.every((context) => !("migrationObligationId" in context)));

        legacyNode.live = { value: "edited" };
        legacy.markEdited(legacyNode, "private-state");
        const editedTransaction = await legacy.settle("manual-save");
        assert.equal(legacyNode.protected, "LEGACY_EXACT");
        assert.deepEqual(legacyNode.writes, []);
        assert.equal(
          editedTransaction.fields[0].migrationObligationId,
          "hp-obligation-synthetic",
        );
        assert.equal(graph.serialize().nodes[0].protected, "EDITED_CURRENT");

        const missingProjectionAdapter = adapter();
        assert.throws(
          () => createPrivacySnapshotCoordinator({
            packId: "helto.test",
            fields: [legacyField],
            adapters: { "state-ui": missingProjectionAdapter },
            transport: {
              disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.UNSUPPORTED }),
              protect: async () => ({}),
            },
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_ADAPTER_INVALID",
        );

        const malformedLegacy = createPrivacySnapshotCoordinator({
          packId: "helto.test-malformed",
          fields: [legacyField],
          adapters: { "state-ui": legacyAdapter },
          transport: {
            disposition: async () => ({
              disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
              replacementEnvelope: "CURRENT_REPLACEMENT",
            }),
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
        });
        await assert.rejects(
          () => malformedLegacy.registerNode({
            id: 2,
            type: "SyntheticNode",
            live: {},
            protected: "LEGACY_EXACT",
            writes: [],
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED",
        );

        const unsupportedNode = {
          type: "SyntheticNode",
          live: { value: "MUST_NOT_FALL_BACK" },
          protected: "UNSUPPORTED_EXACT",
          writes: [],
        };
        const unsupported = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.UNSUPPORTED }),
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
        });
        await unsupported.registerNode(unsupportedNode);
        assert.throws(
          () => unsupported.requireSettled("export"),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSUPPORTED",
        );
        assert.throws(
          () => unsupported.workflowProjection(unsupportedNode, "private-state"),
          PrivacySnapshotError,
        );
        assert.deepEqual(unsupportedNode.writes, []);
        """,
    )


def test_graph_barrier_waits_async_paths_and_aborts_unsettled_sync_serialization(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let settled = false;
        let release;
        const wait = new Promise((resolve) => { release = () => { settled = true; resolve(); }; });
        const events = [];
        const coordinator = {
          settle: async (reason) => {
            events.push(`settle:${reason}`);
            await wait;
            return { reason };
          },
          requireSettled: (reason) => {
            events.push(`require:${reason}`);
            if (!settled) throw new PrivacySnapshotError("PRIVACY_SNAPSHOT_UNSETTLED");
          },
          activateTransaction: () => events.push("activate"),
          requireActiveTransaction: () => {},
          releaseTransaction: () => events.push("release"),
        };
        const graph = {
          serialize() { events.push("serialize"); return { nodes: [] }; },
        };
        const app = {
          rootGraph: graph,
          async graphToPrompt() { events.push("graphToPrompt"); return { workflow: graph.serialize(), output: {} }; },
          async queuePrompt() { events.push("queuePrompt"); return this.graphToPrompt(); },
        };
        installGraphSerializationBarrier(app, () => [coordinator]);

        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSETTLED",
        );
        const queued = app.queuePrompt();
        await Promise.resolve();
        assert(!events.includes("queuePrompt"));
        assert(!events.includes("graphToPrompt"));
        release();
        await queued;

        assert(events.includes("settle:queue"));
        assert(events.includes("queuePrompt"));
        assert(events.includes("require:serialize"));
        assert(events.includes("serialize"));
        assert(events.includes("activate"));
        assert(events.includes("release"));
        """,
    )


def test_lock_and_source_changes_invalidate_inflight_legacy_io(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const legacyField = { ...field, legacyReaderIds: ["state-v0"] };
        const applied = [];
        const cleared = [];
        const guardedAdapter = {
          ...adapter(),
          apply(_owner, value) { applied.push(value); },
          clear() { cleared.push(true); },
          writeWorkflowProjection(_owner, serializedNode, value) {
            serializedNode.protected = value;
          },
        };

        let releaseDisposition;
        let dispositionStarted;
        const dispositionEntered = new Promise((resolve) => { dispositionStarted = resolve; });
        const lockedNode = {
          id: 21,
          type: "SyntheticNode",
          live: {},
          protected: "LOCK_RACE_LEGACY",
          writes: [],
        };
        const lockedCoordinator = createPrivacySnapshotCoordinator({
          packId: "helto.lock-race",
          fields: [legacyField],
          adapters: { "state-ui": guardedAdapter },
          transport: {
            disposition: async () => {
              dispositionStarted();
              return new Promise((resolve) => { releaseDisposition = resolve; });
            },
            reveal: async () => ({ value: { canary: "MUST_NOT_APPLY" } }),
            protect: async () => { throw new Error("MUST_NOT_PROTECT"); },
          },
        });
        const lockedRegistration = lockedCoordinator.registerNode(lockedNode);
        await dispositionEntered;
        await lockedCoordinator.onSessionChange({ state: "locked" });
        releaseDisposition({
          disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
          replacementEnvelope: "LOCK_RACE_CURRENT",
          migrationObligationId: "hp-obligation-lock-race",
        });
        await assert.rejects(
          lockedRegistration,
          (error) => error.code === "PRIVACY_SNAPSHOT_STALE",
        );
        assert.deepEqual(applied, []);
        assert.equal(lockedNode.protected, "LOCK_RACE_LEGACY");
        assert(cleared.length >= 1);
        assert.throws(
          () => lockedCoordinator.requireSettled("serialize"),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSETTLED",
        );

        let releaseSourceDisposition;
        let sourceDispositionStarted;
        const sourceEntered = new Promise((resolve) => { sourceDispositionStarted = resolve; });
        const sourceNode = {
          id: 22,
          type: "SyntheticNode",
          live: {},
          protected: "SOURCE_RACE_LEGACY",
          writes: [],
        };
        const sourceCoordinator = createPrivacySnapshotCoordinator({
          packId: "helto.source-race",
          fields: [legacyField],
          adapters: { "state-ui": guardedAdapter },
          transport: {
            disposition: async () => {
              sourceDispositionStarted();
              return new Promise((resolve) => { releaseSourceDisposition = resolve; });
            },
            reveal: async () => ({ value: { canary: "MUST_NOT_APPLY" } }),
            protect: async () => { throw new Error("MUST_NOT_PROTECT"); },
          },
        });
        const sourceRegistration = sourceCoordinator.registerNode(sourceNode);
        await sourceEntered;
        sourceNode.protected = "SOURCE_CHANGED_DURING_DISPOSITION";
        releaseSourceDisposition({
          disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
          replacementEnvelope: "SOURCE_RACE_CURRENT",
          migrationObligationId: "hp-obligation-source-race",
        });
        await assert.rejects(
          sourceRegistration,
          (error) => error.code === "PRIVACY_SNAPSHOT_STALE",
        );
        assert.deepEqual(applied, []);

        let editPrivate = false;
        let releaseEditDisposition;
        let editDispositionStarted;
        const editEntered = new Promise((resolve) => { editDispositionStarted = resolve; });
        const editNode = {
          id: 24,
          type: "SyntheticNode",
          live: { value: "public" },
          protected: "EDIT_RACE_SOURCE",
          writes: [],
        };
        const editApplied = [];
        const editAdapter = {
          ...guardedAdapter,
          apply(_owner, value) { editApplied.push(value); },
        };
        const editCoordinator = createPrivacySnapshotCoordinator({
          packId: "helto.edit-race",
          fields: [legacyField],
          adapters: { "state-ui": editAdapter },
          resolvePrivate: async () => editPrivate,
          transport: {
            disposition: async () => {
              editDispositionStarted();
              return new Promise((resolve) => { releaseEditDisposition = resolve; });
            },
            protect: async () => ({ envelope: "EDIT_RACE_CURRENT" }),
          },
        });
        await editCoordinator.registerNode(editNode);
        editApplied.length = 0;
        editPrivate = true;
        editNode.protected = "EDIT_RACE_TRANSITIONED_SOURCE";
        const editRefresh = editCoordinator.refreshModes();
        await editEntered;
        editNode.live = { value: "edited-during-disposition" };
        editCoordinator.markEdited(editNode, "private-state");
        releaseEditDisposition({
          disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
          replacementEnvelope: "STALE_EDIT_REPLACEMENT",
          migrationObligationId: "hp-obligation-edit-race",
        });
        await assert.rejects(
          editRefresh,
          (error) => error.code === "PRIVACY_SNAPSHOT_STALE",
        );
        assert.deepEqual(editApplied, []);

        let releaseReveal;
        let revealStarted;
        const revealEntered = new Promise((resolve) => { revealStarted = resolve; });
        const revealNode = {
          id: 23,
          type: "SyntheticNode",
          live: {},
          protected: "REVEAL_RACE_LEGACY",
          writes: [],
        };
        const revealCoordinator = createPrivacySnapshotCoordinator({
          packId: "helto.reveal-race",
          fields: [legacyField],
          adapters: { "state-ui": guardedAdapter },
          transport: {
            disposition: async () => ({
              disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
              replacementEnvelope: "REVEAL_RACE_CURRENT",
              migrationObligationId: "hp-obligation-reveal-race",
            }),
            reveal: async () => {
              revealStarted();
              return new Promise((resolve) => { releaseReveal = resolve; });
            },
            protect: async () => { throw new Error("MUST_NOT_PROTECT"); },
          },
        });
        const revealRegistration = revealCoordinator.registerNode(revealNode);
        await revealEntered;
        await revealCoordinator.onSessionChange({ state: "locked" });
        releaseReveal({ value: { canary: "MUST_NOT_APPLY" } });
        await assert.rejects(
          revealRegistration,
          (error) => error.code === "PRIVACY_SNAPSHOT_REVEAL_FAILED",
        );
        assert.deepEqual(applied, []);
        assert.equal(revealNode.protected, "REVEAL_RACE_LEGACY");
        """,
    )


def test_legacy_projection_is_atomic_and_scoped_to_each_serialized_graph(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const legacyField = { ...field, legacyReaderIds: ["state-v0"] };
        const rootGraph = {};
        const subgraph = { id: "nested-graph" };
        const rootNode = {
          id: 7,
          type: "SyntheticNode",
          graph: rootGraph,
          live: {},
          protected: "ROOT_LEGACY",
          writes: [],
        };
        const subgraphNode = {
          id: 7,
          type: "SyntheticNode",
          graph: subgraph,
          live: {},
          protected: "SUBGRAPH_LEGACY",
          writes: [],
        };
        let failProjection = false;
        const projectionAdapter = {
          ...adapter(),
          writeWorkflowProjection(owner, serializedNode, value) {
            serializedNode.protected = value;
            if (failProjection && owner === rootNode) throw new Error("SYNTHETIC_FAILURE");
          },
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [legacyField],
          adapters: { "state-ui": projectionAdapter },
          transport: {
            disposition: async (_fieldId, source) => ({
              disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
              replacementEnvelope: source === "ROOT_LEGACY" ? "ROOT_CURRENT" : "SUBGRAPH_CURRENT",
              migrationObligationId: source === "ROOT_LEGACY"
                ? "hp-obligation-root"
                : "hp-obligation-subgraph",
            }),
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
        });
        await coordinator.registerNode(rootNode);
        await coordinator.registerNode(subgraphNode);

        let rootRaw;
        rootGraph.serialize = () => {
          rootRaw = {
            nodes: [{ id: 7, type: "SyntheticNode", protected: "ROOT_LEGACY" }],
            definitions: { subgraphs: [{
              id: "nested-graph",
              nodes: [{ id: 7, type: "SyntheticNode", protected: "SUBGRAPH_LEGACY" }],
            }] },
          };
          return rootRaw;
        };
        let subgraphRaw;
        subgraph.serialize = () => {
          subgraphRaw = { nodes: [{ id: 7, type: "SyntheticNode", protected: "SUBGRAPH_LEGACY" }] };
          return subgraphRaw;
        };
        rootGraph.subgraphs = [subgraph];
        installGraphSerializationBarrier({ rootGraph }, () => [coordinator]);

        const projectedRoot = rootGraph.serialize();
        assert.equal(projectedRoot.nodes[0].protected, "ROOT_CURRENT");
        assert.equal(
          projectedRoot.definitions.subgraphs[0].nodes[0].protected,
          "SUBGRAPH_CURRENT",
        );
        assert.equal(subgraph.serialize().nodes[0].protected, "SUBGRAPH_CURRENT");
        assert.equal(rootRaw.nodes[0].protected, "ROOT_LEGACY");
        assert.equal(subgraphRaw.nodes[0].protected, "SUBGRAPH_LEGACY");
        assert.equal(rootNode.protected, "ROOT_LEGACY");
        assert.equal(subgraphNode.protected, "SUBGRAPH_LEGACY");

        failProjection = true;
        assert.throws(
          () => rootGraph.serialize(),
          (error) => error.code === "PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED",
        );
        assert.equal(rootRaw.nodes[0].protected, "ROOT_LEGACY");
        assert.equal(rootNode.protected, "ROOT_LEGACY");
        """,
    )


def test_session_rotation_invalidates_inflight_current_reserved_and_legacy_protection(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const legacyField = { ...field, legacyReaderIds: ["state-v0"] };
        const applied = [];
        const guardedAdapter = {
          ...adapter(),
          apply(_owner, value) { applied.push(value); },
          clear() {},
          writeWorkflowProjection(_owner, serializedNode, value) {
            serializedNode.protected = value;
          },
        };

        async function runRotationCase({
          packId,
          node,
          declaration = field,
          disposition,
          initialize = true,
        }) {
          let releaseProtect;
          let protectStarted;
          const protectEntered = new Promise((resolve) => { protectStarted = resolve; });
          const coordinator = createPrivacySnapshotCoordinator({
            packId,
            fields: [declaration],
            adapters: { "state-ui": guardedAdapter },
            transport: {
              disposition: async () => disposition,
              reveal: async (_fieldId, protectedValue) => ({
                value: { revealedFrom: protectedValue },
              }),
              protect: async () => {
                protectStarted();
                return new Promise((resolve) => { releaseProtect = resolve; });
              },
            },
          });

          let operation;
          if (initialize) {
            await coordinator.registerNode(node);
            applied.length = 0;
            node.live = { value: "edited" };
            coordinator.markEdited(node, "private-state");
            operation = coordinator.settle("manual-save");
            await new Promise((resolve) => setTimeout(resolve, 0));
          } else {
            operation = coordinator.registerNode(node);
          }
          await protectEntered;
          await coordinator.onSessionChange({ state: "unlocked" });
          releaseProtect({ envelope: `STALE_${packId}_CURRENT` });
          await assert.rejects(
            operation,
            (error) => error.code === "PRIVACY_SNAPSHOT_STALE",
          );
          assert.deepEqual(node.writes, []);
          assert.deepEqual(applied, []);
          return coordinator;
        }

        const currentNode = {
          id: 51,
          type: "SyntheticNode",
          live: {},
          protected: "CURRENT_SOURCE_EXACT",
          writes: [],
        };
        await runRotationCase({
          packId: "helto.rotation-current",
          node: currentNode,
          disposition: { disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT },
        });
        assert.equal(currentNode.protected, "CURRENT_SOURCE_EXACT");

        const reservedNode = {
          id: 52,
          type: "SyntheticNode",
          live: { value: "reserved" },
          protected: "",
          writes: [],
        };
        await runRotationCase({
          packId: "helto.rotation-reserved",
          node: reservedNode,
          disposition: { disposition: ENVELOPE_DISPOSITION.UNSUPPORTED },
          initialize: false,
        });
        assert.equal(reservedNode.protected, "");

        const legacyNode = {
          id: 53,
          type: "SyntheticNode",
          live: {},
          protected: "LEGACY_ROTATION_SOURCE_EXACT",
          writes: [],
        };
        const legacyCoordinator = await runRotationCase({
          packId: "helto.rotation-legacy",
          node: legacyNode,
          declaration: legacyField,
          disposition: {
            disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
            replacementEnvelope: "LEGACY_ROTATION_STAGED_INITIAL",
            migrationObligationId: "hp-obligation-rotation-legacy",
          },
        });
        assert.equal(legacyNode.protected, "LEGACY_ROTATION_SOURCE_EXACT");
        assert.throws(
          () => legacyCoordinator.requireSettled("serialize"),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSETTLED",
        );
        """,
    )


def test_public_mode_bypasses_private_protection_but_private_transition_rechecks(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let isPrivate = false;
        let dispositionCalls = 0;
        let protectCalls = 0;
        const node = {
          type: "SyntheticNode",
          live: { value: "PUBLIC_SYNTHETIC" },
          protected: "PUBLIC_SYNTHETIC",
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          resolvePrivate: async () => isPrivate,
          transport: {
            disposition: async () => {
              dispositionCalls += 1;
              return { disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT };
            },
            protect: async () => {
              protectCalls += 1;
              return { envelope: "MUST_NOT_PROTECT_PUBLIC" };
            },
          },
        });
        await coordinator.registerNode(node);
        coordinator.markEdited(node, "private-state");
        await coordinator.settle("manual-save");
        assert.equal(coordinator.workflowProjection(node, "private-state"), "PUBLIC_SYNTHETIC");
        assert.equal(dispositionCalls, 0);
        assert.equal(protectCalls, 0);

        isPrivate = true;
        node.protected = "CURRENT_PRIVATE_ENVELOPE";
        await coordinator.refreshModes();
        await coordinator.settle("manual-save");
        assert.equal(dispositionCalls, 1);
        assert.equal(
          coordinator.executionProjection(node, "private-state"),
          "CURRENT_PRIVATE_ENVELOPE",
        );
        """,
    )


def test_declared_mode_change_invalidates_sync_serialization_and_protects_public_plaintext(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let isPrivate = false;
        const secret = "SYNTHETIC_MODE_CHANGE_PRIVATE_TEXT";
        const node = {
          type: "SyntheticNode",
          live: { value: secret },
          protected: secret,
          writes: [],
        };
        const modeAwareAdapter = {
          normalize: (owner) => owner.live,
          readProtected: (owner) => owner.protected,
          writeProtected: (owner, value) => {
            owner.protected = value;
            owner.writes.push(value);
          },
          writePublic: (owner) => {
            owner.protected = owner.live.value;
            owner.writes.push(owner.protected);
            return owner.protected;
          },
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.mode-notification",
          fields: [field],
          adapters: { "state-ui": modeAwareAdapter },
          resolvePrivate: async () => isPrivate,
          transport: {
            disposition: async (_fieldId, value) => ({
              disposition: value === "CURRENT_PRIVATE_ENVELOPE"
                ? ENVELOPE_DISPOSITION.VERIFIED_CURRENT
                : ENVELOPE_DISPOSITION.UNSUPPORTED,
            }),
            protect: async (_fieldId, value) => {
              assert.deepEqual(value, { value: secret });
              return { envelope: "CURRENT_PRIVATE_ENVELOPE" };
            },
          },
        });
        await coordinator.registerNode(node);

        isPrivate = true;
        coordinator.notifyModeChange();
        assert.throws(
          () => coordinator.requireSettled("serialize"),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSETTLED",
        );
        await coordinator.settle("manual-save");
        assert.equal(node.protected, "CURRENT_PRIVATE_ENVELOPE");
        assert.equal(JSON.stringify({ widgets_values: [node.protected] }).includes(secret), false);
        assert.equal(coordinator.workflowProjection(node, "private-state"), "CURRENT_PRIVATE_ENVELOPE");

        isPrivate = false;
        coordinator.notifyModeChange();
        assert.throws(
          () => coordinator.requireSettled("serialize"),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSETTLED",
        );
        await coordinator.settle("manual-save");
        assert.equal(node.protected, secret);
        assert.equal(coordinator.workflowProjection(node, "private-state"), secret);
        """,
    )


def test_cached_workflows_are_recursively_projected_and_ambiguous_nodes_fail(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const legacyField = { ...field, legacyReaderIds: ["state-v0"] };
        const nestedGraph = { id: "nested-cached" };
        const rootGraph = {
          subgraphs: [nestedGraph],
          serialize() { throw new Error("CACHED_PATH_MUST_NOT_SERIALIZE"); },
        };
        const rootNodeWithoutGraph = {
          id: 31,
          type: "SyntheticNode",
          live: {},
          protected: "ROOT_CACHED_LEGACY",
          writes: [],
        };
        const nestedNode = {
          id: 32,
          type: "SyntheticNode",
          graph: nestedGraph,
          live: {},
          protected: "NESTED_CACHED_LEGACY",
          writes: [],
        };
        const projectionAdapter = {
          ...adapter(),
          writeWorkflowProjection(_owner, serializedNode, value) {
            serializedNode.protected = value;
          },
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.cached",
          fields: [legacyField],
          adapters: { "state-ui": projectionAdapter },
          transport: {
            disposition: async (_fieldId, source) => ({
              disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
              replacementEnvelope: source === "ROOT_CACHED_LEGACY"
                ? "ROOT_CACHED_CURRENT"
                : "NESTED_CACHED_CURRENT",
              migrationObligationId: source === "ROOT_CACHED_LEGACY"
                ? "hp-obligation-root-cached"
                : "hp-obligation-nested-cached",
            }),
            protect: async () => { throw new Error("MUST_NOT_PROTECT"); },
          },
        });
        await coordinator.registerNode(rootNodeWithoutGraph);
        await coordinator.registerNode(nestedNode);
        const cachedWorkflow = {
          nodes: [{
            id: 31,
            type: "SyntheticNode",
            protected: "ROOT_CACHED_LEGACY",
          }],
          definitions: { subgraphs: [{
            id: "nested-cached",
            nodes: [{
              id: 32,
              type: "SyntheticNode",
              protected: "NESTED_CACHED_LEGACY",
            }],
          }] },
        };
        const app = {
          rootGraph,
          graphToPrompt: async () => ({ workflow: cachedWorkflow, output: {} }),
          queuePrompt: async () => ({ workflow: cachedWorkflow, output: {} }),
        };
        installGraphSerializationBarrier(app, () => [coordinator]);

        const prompt = await app.graphToPrompt();
        assert.equal(prompt.workflow.nodes[0].protected, "ROOT_CACHED_CURRENT");
        assert.equal(
          prompt.workflow.definitions.subgraphs[0].nodes[0].protected,
          "NESTED_CACHED_CURRENT",
        );
        const queued = await app.queuePrompt();
        assert.equal(queued.workflow.nodes[0].protected, "ROOT_CACHED_CURRENT");
        assert.equal(
          queued.workflow.definitions.subgraphs[0].nodes[0].protected,
          "NESTED_CACHED_CURRENT",
        );
        assert.equal(cachedWorkflow.nodes[0].protected, "ROOT_CACHED_LEGACY");
        assert.equal(
          cachedWorkflow.definitions.subgraphs[0].nodes[0].protected,
          "NESTED_CACHED_LEGACY",
        );

        const ambiguousNode = {
          id: 41,
          type: "SyntheticNode",
          live: {},
          protected: "AMBIGUOUS_LEGACY",
          writes: [],
        };
        const ambiguous = createPrivacySnapshotCoordinator({
          packId: "helto.ambiguous",
          fields: [legacyField],
          adapters: { "state-ui": projectionAdapter },
          transport: {
            disposition: async () => ({
              disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
              replacementEnvelope: "AMBIGUOUS_CURRENT",
              migrationObligationId: "hp-obligation-ambiguous",
            }),
            protect: async () => { throw new Error("MUST_NOT_PROTECT"); },
          },
        });
        await ambiguous.registerNode(ambiguousNode);
        const duplicateWorkflow = {
          nodes: [{ id: 41, type: "SyntheticNode", protected: "AMBIGUOUS_LEGACY" }],
          definitions: { subgraphs: [{
            id: "duplicate",
            nodes: [{ id: 41, type: "SyntheticNode", protected: "AMBIGUOUS_LEGACY" }],
          }] },
        };
        const ambiguousApp = {
          rootGraph: { serialize: () => duplicateWorkflow },
          graphToPrompt: async () => ({ workflow: duplicateWorkflow, output: {} }),
        };
        installGraphSerializationBarrier(ambiguousApp, () => [ambiguous]);
        await assert.rejects(
          () => ambiguousApp.graphToPrompt(),
          (error) => error.code === "PRIVACY_SNAPSHOT_LEGACY_REWRITE_FAILED",
        );
        assert.equal(duplicateWorkflow.nodes[0].protected, "AMBIGUOUS_LEGACY");
        """,
    )


def test_settlement_timeout_and_write_readback_fail_closed(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const timeoutNode = {
          type: "SyntheticNode",
          live: { value: "edited" },
          protected: "CURRENT",
          writes: [],
        };
        const timeout = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          timeoutMs: 10,
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => await new Promise(() => {}),
          },
        });
        await timeout.registerNode(timeoutNode);
        timeout.markEdited(timeoutNode, "private-state");
        await assert.rejects(
          () => timeout.settle("autosave"),
          (error) => error.code === "PRIVACY_SNAPSHOT_TIMEOUT",
        );
        assert.deepEqual(timeoutNode.writes, []);

        const writeNode = {
          type: "SyntheticNode",
          live: { value: "edited" },
          protected: "CURRENT",
          writes: [],
        };
        const brokenAdapter = adapter();
        brokenAdapter.writeProtected = () => {};
        const writeFailure = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": brokenAdapter },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => ({ envelope: "NEW_CURRENT" }),
          },
        });
        await writeFailure.registerNode(writeNode);
        writeFailure.markEdited(writeNode, "private-state");
        await assert.rejects(
          () => writeFailure.settle("export"),
          (error) => error.code === "PRIVACY_SNAPSHOT_WRITE_FAILED",
        );
        assert.equal(writeNode.protected, "CURRENT");
        """,
    )


def test_adapter_must_return_exact_serialized_protected_value(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const node = {
          type: "SyntheticNode",
          live: { value: "SYNTHETIC" },
          protected: { envelope: "OBJECT_IS_NOT_BYTE_EXACT" },
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
        });
        await assert.rejects(
          () => coordinator.registerNode(node),
          (error) => error.code === "PRIVACY_SNAPSHOT_READ_FAILED",
        );
        assert.deepEqual(node.writes, []);
        """,
    )


def test_reserved_node_blocks_until_registration_finishes(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let protectCalls = 0;
        const node = {
          type: "SyntheticNode",
          live: { value: "SYNTHETIC" },
          protected: "",
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => {
              protectCalls += 1;
              return { envelope: "CURRENT" };
            },
          },
        });
        coordinator.reserveNode(node);
        await assert.rejects(
          () => coordinator.settle("autosave"),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSETTLED",
        );
        assert.equal(protectCalls, 0);

        await coordinator.registerNode(node);
        await coordinator.settle("manual-save");
        assert.equal(coordinator.workflowProjection(node, "private-state"), "CURRENT");
        assert.equal(protectCalls, 1);
        """,
    )


def test_failed_registration_can_be_retried(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let attempts = 0;
        const node = {
          type: "SyntheticNode",
          live: { value: "SYNTHETIC" },
          protected: "CURRENT",
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => {
              attempts += 1;
              if (attempts === 1) throw new Error("SYNTHETIC_FAILURE");
              return { disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT };
            },
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
        });
        await assert.rejects(
          () => coordinator.registerNode(node),
          (error) => error.code === "PRIVACY_SNAPSHOT_DISPOSITION_FAILED",
        );
        await coordinator.registerNode(node);
        await coordinator.settle("manual-save");
        assert.equal(attempts, 2);
        assert.equal(coordinator.executionProjection(node, "private-state"), "CURRENT");
        """,
    )


def test_graph_operation_pins_one_transaction_across_both_projections(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const node = {
          type: "SyntheticNode",
          live: { value: "first" },
          protected: "ENVELOPE_FIRST",
          writes: [],
        };
        let protectCalls = 0;
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => {
              protectCalls += 1;
              return { envelope: "ENVELOPE_SECOND" };
            },
          },
        });
        await coordinator.registerNode(node);
        const observed = [];
        const graph = {
          serialize() {
            observed.push(coordinator.workflowProjection(node, "private-state"));
            return { nodes: [] };
          },
        };
        const app = {
          rootGraph: graph,
          async graphToPrompt() {
            const workflow = graph.serialize();
            node.live = { value: "second" };
            coordinator.markEdited(node, "private-state");
            await coordinator.settle("manual-save");
            observed.push(coordinator.executionProjection(node, "private-state"));
            return { workflow, output: {} };
          },
        };
        installGraphSerializationBarrier(app, () => [coordinator]);
        await assert.rejects(
          app.graphToPrompt(),
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );

        assert.deepEqual(observed, ["ENVELOPE_FIRST"]);
        await coordinator.settle("manual-save");
        assert.equal(protectCalls, 1);
        assert.equal(
          coordinator.workflowProjection(node, "private-state"),
          "ENVELOPE_SECOND",
        );
        """,
    )


def test_lock_invalidates_execution_from_an_active_transaction(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const node = {
          type: "SyntheticNode",
          live: { value: "first" },
          protected: "ENVELOPE_FIRST",
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
        });
        await coordinator.registerNode(node);
        const graph = { serialize: () => ({ nodes: [] }) };
        const app = {
          rootGraph: graph,
          async graphToPrompt() {
            assert.equal(
              coordinator.workflowProjection(node, "private-state"),
              "ENVELOPE_FIRST",
            );
            await coordinator.onSessionChange({ state: "locked" });
            assert.throws(
              () => coordinator.executionProjection(node, "private-state"),
              (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
            );
            return { workflow: graph.serialize(), output: {} };
          },
        };
        installGraphSerializationBarrier(app, () => [coordinator]);
        await assert.rejects(
          app.graphToPrompt(),
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );
        """,
    )


def test_consumer_async_operation_pins_snapshot_until_callback_finishes(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const node = {
          type: "SyntheticNode",
          live: { value: "first" },
          protected: "ENVELOPE_FIRST",
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => ({ envelope: "ENVELOPE_SECOND" }),
          },
        });
        await coordinator.registerNode(node);
        const barrier = installGraphSerializationBarrier(
          { rootGraph: { serialize: () => ({ nodes: [] }) } },
          () => [coordinator],
        );
        const observed = [];
        await assert.rejects(
          barrier.runWithSnapshot("export", async () => {
            observed.push(coordinator.workflowProjection(node, "private-state"));
            node.live = { value: "second" };
            coordinator.markEdited(node, "private-state");
            await coordinator.settle("manual-save");
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );

        assert.deepEqual(observed, ["ENVELOPE_FIRST"]);
        await coordinator.settle("manual-save");
        assert.equal(
          coordinator.workflowProjection(node, "private-state"),
          "ENVELOPE_SECOND",
        );
        assert.throws(
          () => barrier.runWithSnapshot("export", null),
          (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
        );
        """,
    )


def test_scoped_graph_invoker_reuses_snapshot_and_unrelated_calls_queue(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const node = {
          type: "SyntheticNode",
          live: { value: "first" },
          protected: "ENVELOPE_FIRST",
          writes: [],
        };
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => ({ envelope: "ENVELOPE_SECOND" }),
          },
        });
        await coordinator.registerNode(node);
        const observed = [];
        const events = [];
        const graph = {
          serialize() {
            observed.push(coordinator.workflowProjection(node, "private-state"));
            return { nodes: [] };
          },
        };
        const app = {
          rootGraph: graph,
          async graphToPrompt() {
            events.push("graph");
            const workflow = graph.serialize();
            observed.push(coordinator.executionProjection(node, "private-state"));
            return { workflow, output: {} };
          },
        };
        const barrier = installGraphSerializationBarrier(app, () => [coordinator]);
        await Promise.race([
          barrier.runWithSnapshot(
            "queue-manager",
            ({ graphToPrompt }) => graphToPrompt(),
          ),
          new Promise((_, reject) => setTimeout(
            () => reject(new Error("SCOPED_OPERATION_TIMED_OUT")),
            100,
          )),
        ]);
        assert.deepEqual(observed, ["ENVELOPE_FIRST", "ENVELOPE_FIRST"]);

        events.length = 0;
        let releaseOuter;
        let enterOuter;
        const enteredOuter = new Promise((resolve) => { enterOuter = resolve; });
        const holdOuter = new Promise((resolve) => { releaseOuter = resolve; });
        const outer = barrier.runWithSnapshot("export", async () => {
          events.push("outer:start");
          enterOuter();
          await holdOuter;
          events.push("outer:end");
        });
        await enteredOuter;
        const separate = app.graphToPrompt().then(() => events.push("separate:end"));
        await Promise.resolve();
        assert.deepEqual(events, ["outer:start"]);
        releaseOuter();
        await outer;
        await separate;
        assert.deepEqual(events, ["outer:start", "outer:end", "graph", "separate:end"]);

        await assert.rejects(
          () => barrier.runWithSnapshot("queue-manager", async ({ graphToPrompt }) => {
            node.live = { value: "second" };
            coordinator.markEdited(node, "private-state");
            await graphToPrompt();
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );
        """,
    )


def test_privacy_owned_queue_interceptor_preserves_protected_direct_submission(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const events = [];
        class TestApi {
          constructor() { this.clientId = "synthetic-client"; }
          async fetchApi(route, options) {
            events.push(["fetch", route, JSON.parse(options.body)]);
            return new Response(JSON.stringify({ prompt_id: "protected-core" }), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          }
          async queuePrompt(number, data, options = undefined) {
            const body = {
              client_id: this.clientId ?? "",
              prompt: data.output,
              ...(options?.partialExecutionTargets
                ? { partial_execution_targets: options.partialExecutionTargets }
                : {}),
              extra_data: {
                extra_pnginfo: { workflow: data.workflow },
                ...(options?.previewMethod && options.previewMethod !== "default"
                  ? { preview_method: options.previewMethod }
                  : {}),
              },
              ...(number === -1 ? { front: true } : {}),
              ...(number !== 0 && number !== -1 ? { number } : {}),
            };
            const response = await this.fetchApi("/prompt", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body),
            });
            return response.json();
          }
        }
        class TestApp {
          constructor() {
            this.api = new TestApi();
            this.rootGraph = { serialize: () => ({ nodes: [] }) };
          }
          async graphToPrompt() { return { workflow: { nodes: [] }, output: {} }; }
          async queuePrompt(...args) { events.push(["core-app", ...args]); return "core-app"; }
        }
        const app = new TestApp();
        const attempt = installPrivacyConnectionSerializationGate(app);
        const coordinator = {
          setSubmissionInvalidator() {},
          settle: async () => ({ packId: "helto.test", revision: 1, fields: [] }),
          activateTransaction() {},
          releaseTransaction() {},
          requireActiveTransaction() {},
          requireSettled() {},
          projectSerializedWorkflow: (workflow) => workflow,
          sanitizePromptExport: (promptData) => promptData,
          prepareSubmission: async (promptData) => ({ promptData, references: [] }),
          revokePreparedReferences: async () => {},
          onSessionChange: async () => {},
        };
        const barrier = installGraphSerializationBarrier(app, () => [coordinator]);
        await barrier.takeOwnership(attempt);

        const intercepted = [];
        const controller = barrier.installQueueInterceptor({
          appQueuePrompt(args) { intercepted.push(["app", ...args]); return "captured-app"; },
          apiQueuePrompt(args) { intercepted.push(["api", ...args]); return { prompt_id: "captured-api" }; },
        });
        assert.equal(await app.queuePrompt(0, 2), "captured-app");
        assert.deepEqual(await app.api.queuePrompt(0, { workflow: { nodes: [] }, output: {} }), {
          prompt_id: "captured-api",
        });
        assert.deepEqual(intercepted.map((item) => item[0]), ["app", "api"]);
        assert.equal(events.length, 0);
        assert.throws(
          () => barrier.installQueueInterceptor({ appQueuePrompt() {}, apiQueuePrompt() {} }),
          (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
        );

        const promptData = { workflow: { nodes: [] }, output: { "1": { inputs: {} } } };
        assert.deepEqual(await controller.submitPrompt(0, promptData), {
          prompt_id: "protected-core",
        });
        assert.equal(events[0][0], "fetch");
        assert.deepEqual(events[0][2].prompt, promptData.output);
        controller.dispose();
        assert.equal(await app.queuePrompt(1, 3), "core-app");
        assert.throws(
          () => controller.submitPrompt(0, promptData),
          (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
        );
        """,
    )


def test_queue_manager_settles_every_registered_pack_coordinator(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const events = [];
        const coordinatorA = {
          settle: async (reason) => {
            events.push(`a:settle:${reason}`);
            return { revision: 1, fields: [] };
          },
          activateTransaction: () => events.push("a:activate"),
          requireActiveTransaction: () => {},
          releaseTransaction: () => events.push("a:release"),
          requireSettled: () => {},
        };
        const coordinatorB = {
          settle: async (reason) => {
            events.push(`b:settle:${reason}`);
            return { revision: 2, fields: [] };
          },
          activateTransaction: () => events.push("b:activate"),
          requireActiveTransaction: () => {},
          releaseTransaction: () => events.push("b:release"),
          requireSettled: () => {},
        };
        const graph = { serialize: () => ({ nodes: [] }) };
        const app = {
          rootGraph: graph,
          graphToPrompt: async () => ({ workflow: graph.serialize(), output: {} }),
        };
        const barrier = installGraphSerializationBarrier(
          app,
          () => [coordinatorA, coordinatorB],
        );
        await barrier.runWithSnapshot(
          "queue-manager",
          ({ graphToPrompt }) => graphToPrompt(),
        );
        assert.deepEqual(events, [
          "a:settle:queue-manager",
          "b:settle:queue-manager",
          "a:activate",
          "b:activate",
          "b:release",
          "a:release",
        ]);
        """,
    )


def test_graph_transaction_injects_fresh_private_execution_reference(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const node = {
          id: 7,
          type: "SyntheticNode",
          live: { value: "private" },
          protected: "CURRENT_ENVELOPE",
          writes: [],
        };
        const prepared = [];
        const coordinator = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [{ ...field, execution: true }],
              executionProjections: [{
                id: "render",
                executionResourceId: "render-execution",
                workflowResourceId: "state",
                subjectModeBindingId: "render-mode",
                inputName: "private_execution",
              }],
              subjectModeBindings: [{
                id: "render-mode",
                scopeId: "global",
                inputName: "privacy_mode_reference",
                nodeTypes: ["SyntheticNode"],
              }],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({ disposition: ENVELOPE_DISPOSITION.VERIFIED_CURRENT }),
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
              prepareExecution: async (projection, owner, entries) => {
            const grant = `grant-${prepared.length + 1}`;
            prepared.push({ projection, owner, entries });
                return { reference: { grant } };
              },
              prepareSubjectMode: async () => ({
                effective: "private",
                reference: { grant: "mode-grant" },
              }),
        });
        await coordinator.registerNode(node);
        const graph = { serialize: () => ({ nodes: [] }) };
        const app = {
          rootGraph: graph,
          graphToPrompt: async () => ({
            workflow: graph.serialize(),
            output: { "7": { inputs: {} } },
          }),
        };
        installGraphSerializationBarrier(app, () => [coordinator]);

        const first = await app.graphToPrompt();
        const second = await app.graphToPrompt();

        assert.deepEqual(JSON.parse(first.output["7"].inputs.private_execution), {
          grant: "grant-1",
        });
        assert.deepEqual(JSON.parse(second.output["7"].inputs.private_execution), {
          grant: "grant-2",
        });
        assert.equal(prepared.length, 2);
        assert.equal(prepared[0].owner, node);
        assert.equal(prepared[0].entries[0].field.id, "private-state");
        """,
    )
