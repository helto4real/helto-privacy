from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
QUEUE = ROOT / "helto_privacy" / "web" / "privacy_queue.js"


def run_queue_test(tmp_path: Path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    script = tmp_path / "test.mjs"
    script.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import {{
              PrivacyQueueError,
              createPrivacyQueueCoordinator,
            }} from {QUEUE.as_uri()!r};
            {textwrap.dedent(body)}
            """
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        ["node", str(script)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_capture_settles_every_batch_and_preserves_callback_order(tmp_path):
    run_queue_test(
        tmp_path,
        """
        const events = [];
        let grant = 0;
        const workflow = {
          async runWithSnapshot(reason, operation) {
            events.push(`settle:${reason}`);
            return operation({ graphToPrompt: async () => ({ grant: ++grant }) });
          },
        };
        const coordinator = createPrivacyQueueCoordinator({
          workflow,
          capturePrompt: ({ graphToPrompt }) => graphToPrompt(),
          submitPrompt: async (prompt, options) => {
            events.push(`submit:${prompt.grant}:${options.batchIndex}`);
            return prompt.grant;
          },
          rebuildPrompt: async () => ({ grant: ++grant }),
        });
        const results = await coordinator.captureBatches({
          batchCount: 2,
          beforeSnapshot: ({ batchIndex }) => events.push(`before:${batchIndex}`),
          afterSubmit: ({ batchIndex }) => events.push(`after:${batchIndex}`),
        });
        assert.deepEqual(results, [1, 2]);
        assert.deepEqual(events, [
          "before:0", "settle:queue-manager", "submit:1:0", "after:0",
          "before:1", "settle:queue-manager", "submit:2:1", "after:1",
        ]);
        """,
    )


def test_replay_rebuilds_fresh_reference_and_never_submits_stored_payload(tmp_path):
    run_queue_test(
        tmp_path,
        """
        const reference = (grant) => ({
          schema: "helto.private-execution-reference",
          version: 2,
          subject: "a".repeat(64),
          grant,
        });
        const subjectReference = (grant) => ({
          schema: "helto.subject-mode-reference",
          version: 2,
          profileFingerprint: "b".repeat(64),
          subject: "c".repeat(64),
          bindingId: "render-mode",
          grant,
        });
        const stored = {
          workflow: { id: "synthetic" },
          execution: ` \n${JSON.stringify(reference("expired"))}\t `,
          subjectMode: `\t${JSON.stringify(subjectReference("expired-subject"))}\n`,
        };
        const submitted = [];
        let generation = 0;
        const coordinator = createPrivacyQueueCoordinator({
          workflow: {
            runWithSnapshot(reason, operation) {
              assert.equal(reason, "replay");
              return operation({ graphToPrompt: async () => ({}) });
            },
          },
          capturePrompt: async () => ({}),
          submitPrompt: async (prompt, options) => {
            submitted.push(prompt);
            assert.equal(options.replay, true);
            return prompt.grant;
          },
          rebuildPrompt: async (snapshot) => ({
            workflow: snapshot.workflow,
            grant: `fresh-${++generation}`,
            execution: ` \n${JSON.stringify(reference(`fresh-grant-${generation}`))}\t`,
            subjectMode: `\t${JSON.stringify(
              subjectReference(`fresh-subject-${generation}`),
            )}\n `,
          }),
        });
        assert.equal(await coordinator.replay(stored), "fresh-1");
        assert.equal(await coordinator.replay(stored), "fresh-2");
        assert.deepEqual(submitted.map((item) => item.grant), ["fresh-1", "fresh-2"]);
        assert(!submitted.includes(stored));
        """,
    )


def test_replay_fails_closed_for_missing_or_unrebuilt_snapshots(tmp_path):
    run_queue_test(
        tmp_path,
        """
        const workflow = { runWithSnapshot: (_reason, operation) => operation({}) };
        const base = {
          workflow,
          capturePrompt: async () => ({}),
          submitPrompt: async () => { throw new Error("must not submit"); },
        };
        const invalid = createPrivacyQueueCoordinator({
          ...base,
          rebuildPrompt: async () => null,
        });
        await assert.rejects(
          () => invalid.replay({ workflow: {} }),
          (error) => error.code === "PRIVACY_QUEUE_SNAPSHOT_INVALID"
            && !error.message.includes("workflow"),
        );
        const same = createPrivacyQueueCoordinator({
          ...base,
          rebuildPrompt: async (stored) => stored,
        });
        const stored = { workflow: {} };
        await assert.rejects(
          () => same.replay(stored),
          (error) => error.code === "PRIVACY_QUEUE_REPLAY_NOT_REBUILT",
        );
        """,
    )


def test_replay_rejects_cloned_stale_or_missing_execution_grants(tmp_path):
    run_queue_test(
        tmp_path,
        """
        const stored = {
          workflow: {},
          execution: ` \n${JSON.stringify({
            schema: "helto.private-execution-reference",
            version: 2,
            subject: "a".repeat(64),
            grant: "expired-grant",
          })}\t `,
          subjectMode: `\t${JSON.stringify({
            schema: "helto.subject-mode-reference",
            version: 2,
            profileFingerprint: "b".repeat(64),
            subject: "c".repeat(64),
            bindingId: "render-mode",
            grant: "expired-subject-grant",
          })}\n`,
        };
        const oversized = {
          workflow: {},
          reference: JSON.stringify({
            schema: "helto.private-execution-reference",
            grant: "oversized-grant",
            padding: "x".repeat(16384),
          }),
        };
        const subjectWithoutHash = {
          workflow: {},
          reference: JSON.stringify({
            schema: "helto.subject-mode-reference",
            version: 2,
            profileFingerprint: "b".repeat(64),
            bindingId: "render-mode",
            grant: "missing-subject-hash",
          }),
        };
        const ordinaryPromptText = {
          workflow: {},
          brace: "{ordinary prompt text",
          bracket: "[ordinary prompt text",
          largeJson: JSON.stringify({ padding: "x".repeat(20000) }),
          markerAsProductText: JSON.stringify({
            text: "helto.subject-mode-reference",
          }),
        };
        const disguisedMarker = {
          workflow: {},
          text: "prefix helto.private-execution-reference trailing junk",
        };
        const unicodeEscape = (value) => [...value].map(
          (character) => "\\\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"),
        ).join("");
        const executionMarker = "helto.private-execution-reference";
        const subjectMarker = "helto.subject-mode-reference";
        const escapedSchema = unicodeEscape("schema");
        const escapedExecution = unicodeEscape(executionMarker);
        const escapedReferences = [
          `{"schema":"${escapedExecution}","grant":"escaped-execution"}`,
          `{"${escapedSchema}":"${subjectMarker}","grant":"escaped-key"}`,
          `{"schema":"helto.subject-mode-${unicodeEscape("reference")}",`
            + `"grant":"mixed-marker"}`,
        ];
        const malformedEscaped = {
          workflow: {},
          reference: `{"schema":"${escapedExecution}","grant":"trailing"} trailing`,
        };
        const oversizedEscaped = {
          workflow: {},
          reference: `{"padding":"${"x".repeat(16384)}",`
            + `"schema":"${escapedExecution}","grant":"oversized"}`,
        };
        let submitted = false;
        const make = (rebuildPrompt) => createPrivacyQueueCoordinator({
          workflow: { runWithSnapshot: (_reason, operation) => operation({}) },
          capturePrompt: async () => ({}),
          submitPrompt: async () => { submitted = true; },
          rebuildPrompt,
        });
        await assert.rejects(
          () => make(async (value) => structuredClone(value)).replay(stored),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_GRANT_STALE",
        );
        await assert.rejects(
          () => make(async (value) => structuredClone(value)).replay(oversized),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID",
        );
        await assert.rejects(
          () => make(async (value) => structuredClone(value)).replay(subjectWithoutHash),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID",
        );
        let ordinarySubmitted = false;
        await createPrivacyQueueCoordinator({
          workflow: { runWithSnapshot: (_reason, operation) => operation({}) },
          capturePrompt: async () => ({}),
          submitPrompt: async () => { ordinarySubmitted = true; },
          rebuildPrompt: async (value) => structuredClone(value),
        }).replay(ordinaryPromptText);
        assert.equal(ordinarySubmitted, true);
        await assert.rejects(
          () => make(async (value) => structuredClone(value)).replay(disguisedMarker),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID",
        );
        for (const reference of escapedReferences) {
          await assert.rejects(
            () => make(async (value) => structuredClone(value)).replay({
              workflow: {}, reference,
            }),
            (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID",
          );
        }
        for (const candidate of [malformedEscaped, oversizedEscaped]) {
          await assert.rejects(
            () => make(async (value) => structuredClone(value)).replay(candidate),
            (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID",
          );
        }
        await assert.rejects(
          () => make(async () => ({ workflow: {} })).replay(stored),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING",
        );
        await assert.rejects(
          () => make(async () => ({
            workflow: {},
            execution: JSON.stringify({
              schema: "helto.subject-mode-reference",
              version: 2,
              profileFingerprint: "b".repeat(64),
              subject: "c".repeat(64),
              bindingId: "render-mode",
              grant: "fresh-subject",
            }),
            subjectMode: JSON.stringify({
              schema: "helto.private-execution-reference",
              version: 2,
              subject: "b".repeat(64),
              grant: "fresh-execution",
            }),
          })).replay(stored),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING",
        );
        await assert.rejects(
          () => make(async () => ({
            workflow: {},
            moved: {
              execution: JSON.stringify({
                schema: "helto.private-execution-reference",
                version: 2,
                subject: "b".repeat(64),
                grant: "fresh-execution",
              }),
              subjectMode: JSON.stringify({
                schema: "helto.subject-mode-reference",
                version: 2,
                profileFingerprint: "b".repeat(64),
                subject: "c".repeat(64),
                bindingId: "render-mode",
                grant: "fresh-subject",
              }),
            },
          })).replay(stored),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING",
        );
        const nestedStored = {
          workflow: {},
          a: { b: JSON.stringify({
            schema: "helto.subject-mode-reference",
            version: 2,
            profileFingerprint: "b".repeat(64),
            subject: "c".repeat(64),
            bindingId: "render-mode",
            grant: "expired-nested",
          }) },
        };
        await assert.rejects(
          () => make(async () => ({
            workflow: {},
            "a.b": JSON.stringify({
              schema: "helto.subject-mode-reference",
              version: 2,
              profileFingerprint: "b".repeat(64),
              subject: "c".repeat(64),
              bindingId: "render-mode",
              grant: "fresh-flat",
            }),
          })).replay(nestedStored),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING",
        );
        const numericObjectStored = {
          workflow: {},
          container: {
            "0": JSON.stringify({
              schema: "helto.private-execution-reference",
              version: 2,
              subject: "a".repeat(64),
              grant: "expired-object-index",
            }),
          },
        };
        await assert.rejects(
          () => make(async () => ({
            workflow: {},
            container: [JSON.stringify({
              schema: "helto.private-execution-reference",
              version: 2,
              subject: "b".repeat(64),
              grant: "fresh-array-index",
            })],
          })).replay(numericObjectStored),
          (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_MISSING",
        );
        assert.equal(submitted, false);
        """,
    )


def test_shared_reference_aliases_cannot_collapse_locations(tmp_path):
    run_queue_test(
        tmp_path,
        """
        const make = () => createPrivacyQueueCoordinator({
          workflow: { runWithSnapshot: (_reason, operation) => operation({}) },
          capturePrompt: async () => ({}),
          submitPrompt: async () => { throw new Error("must not submit"); },
          rebuildPrompt: async (stored) => ({ workflow: {}, a: { ...stored.a, grant: "fresh" } }),
        });
        for (const schema of [
          "helto.private-execution-reference",
          "helto.subject-mode-reference",
        ]) {
          const shared = { schema, grant: `expired-${schema}` };
          const stored = { workflow: {}, a: shared, b: shared };
          await assert.rejects(
            () => make().replay(stored),
            (error) => error.code === "PRIVACY_QUEUE_EXECUTION_REFERENCE_INVALID",
          );
        }
        """,
    )


def test_product_failures_are_sanitized_without_snapshot_details(tmp_path):
    run_queue_test(
        tmp_path,
        """
        const coordinator = createPrivacyQueueCoordinator({
          workflow: { runWithSnapshot: (_reason, operation) => operation({}) },
          capturePrompt: async () => {
            throw new Error("synthetic private prompt detail");
          },
          submitPrompt: async () => ({}),
          rebuildPrompt: async () => {
            throw new Error("synthetic private workflow detail");
          },
        });
        await assert.rejects(
          () => coordinator.captureOne(),
          (error) => error.code === "PRIVACY_QUEUE_CAPTURE_FAILED"
            && !error.message.includes("synthetic"),
        );
        await assert.rejects(
          () => coordinator.replay({ workflow: {} }),
          (error) => error.code === "PRIVACY_QUEUE_REPLAY_FAILED"
            && !error.message.includes("synthetic"),
        );
        """,
    )
