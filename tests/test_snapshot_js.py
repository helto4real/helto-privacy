import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "helto_privacy" / "web" / "privacy_snapshot.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module_path = tmp_path / "privacy_snapshot.js"
    module_path.write_text(SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8")
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


def test_legacy_replacement_is_current_and_unsupported_blocks_every_projection(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const legacyNode = {
          type: "SyntheticNode",
          live: {},
          protected: "LEGACY_EXACT",
          writes: [],
        };
        const legacy = createPrivacySnapshotCoordinator({
          packId: "helto.test",
          fields: [field],
          adapters: { "state-ui": adapter() },
          transport: {
            disposition: async () => ({
              disposition: ENVELOPE_DISPOSITION.READABLE_LEGACY,
              replacementEnvelope: "CURRENT_REPLACEMENT",
            }),
            protect: async () => { throw new Error("MUST_NOT_ENCRYPT"); },
          },
        });
        await legacy.registerNode(legacyNode);
        await legacy.settle("manual-save");
        assert.equal(legacy.workflowProjection(legacyNode, "private-state"), "CURRENT_REPLACEMENT");
        assert.deepEqual(legacyNode.writes, ["CURRENT_REPLACEMENT"]);

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
        assert(events.includes("queuePrompt"));
        assert(!events.includes("graphToPrompt"));
        release();
        await queued;

        assert(events.includes("settle:graph-to-prompt"));
        assert(events.includes("require:serialize"));
        assert(events.includes("serialize"));
        assert(events.includes("activate"));
        assert(events.includes("release"));
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
        await app.graphToPrompt();

        assert.deepEqual(observed, ["ENVELOPE_FIRST", "ENVELOPE_FIRST"]);
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
        await app.graphToPrompt();
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
        await barrier.runWithSnapshot("export", async () => {
          observed.push(coordinator.workflowProjection(node, "private-state"));
          node.live = { value: "second" };
          coordinator.markEdited(node, "private-state");
          await coordinator.settle("manual-save");
          observed.push(coordinator.workflowProjection(node, "private-state"));
        });

        assert.deepEqual(observed, ["ENVELOPE_FIRST", "ENVELOPE_FIRST"]);
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
            inputName: "private_execution",
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
