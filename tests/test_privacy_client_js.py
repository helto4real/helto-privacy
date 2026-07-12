import subprocess
import textwrap
from pathlib import Path

from privacy_js_test_support import write_privacy_client_dependencies


ROOT = Path(__file__).resolve().parents[1]
PRIVACY_UI = ROOT / "helto_privacy" / "web" / "privacy_ui.js"
PRIVACY_CLIENT = ROOT / "helto_privacy" / "web" / "privacy_client.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module_path = tmp_path / "privacy_ui.js"
    module_path.write_text(PRIVACY_UI.read_text(encoding="utf-8"), encoding="utf-8")
    client_path = tmp_path / "privacy_client.js"
    client_path.write_text(PRIVACY_CLIENT.read_text(encoding="utf-8"), encoding="utf-8")
    write_privacy_client_dependencies(tmp_path)
    script_path = tmp_path / "test.mjs"
    script_path.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import * as privacy from {module_path.as_uri()!r};
            import * as client from {client_path.as_uri()!r};

            function response(payload, status = 200) {{
              return {{
                ok: status >= 200 && status < 300,
                status,
                statusText: status < 400 ? "OK" : "Error",
                text: async () => JSON.stringify(payload),
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


def test_attested_client_retries_once_without_leaking_token_to_url_or_events(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const storage = new Map([["helto_privacy_token", "SYNTHETIC_TOKEN_CANARY"]]);
        assert.equal(typeof privacy.getStoredPrivacyToken, "undefined");
        assert.equal(typeof privacy.createAttestedPrivacyRequestClient, "undefined");
        assert.equal(typeof privacy.internalStorePrivacyToken, "undefined");
        assert.equal(typeof client.createAttestedPrivacyRequestClient, "undefined");
        assert.equal(typeof client.internalReadPrivacyToken, "undefined");
        assert.equal(typeof client.internalStorePrivacyToken, "undefined");
        globalThis.localStorage = {
          getItem: (key) => storage.get(key) || "",
          setItem: (key, value) => storage.set(key, String(value)),
          removeItem: (key) => storage.delete(key),
        };
        globalThis.document = { cookie: "" };
        const calls = [];
        let promptCount = 0;
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [{
              id: "record.use",
              resourceId: "library",
              route: "/helto-test/records/use",
              method: "POST",
              scopeId: null,
              sensitiveFields: [],
              safeProjection: [],
            }],
            modeScopes: [],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          if (target.endsWith("/unlock")) return response({
            ok: true,
            token: "REPLACEMENT_TOKEN_CANARY",
          });
          calls.push({ url: target, options });
          if (calls.length === 1) {
            return response({ ok: false, error: "PRIVACY_LOCKED" }, 401);
          }
          return response({ ok: true, value: "synthetic-result" });
        };
        const events = [];
        const unsubscribe = client.subscribePrivacySession((event) => events.push(event));
        const requestClient = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
          promptUnlock: async () => {
            promptCount += 1;
            return privacy.unlockPrivacyKeystore("synthetic password");
          },
        });

        const result = await requestClient.invoke(
          "library",
          "record.use",
          { recordId: "synthetic-record" },
        );

        assert.deepEqual(result, { ok: true, value: "synthetic-result" });
        assert.equal(promptCount, 1);
        assert.equal(calls.length, 2);
        assert.deepEqual(calls.map((call) => call.url), [
          "/helto-test/records/use",
          "/helto-test/records/use",
        ]);
        assert(!calls.some((call) => call.url.includes("TOKEN_CANARY")));
        assert.equal(
          calls[0].options.headers["X-Helto-Privacy-Token"],
          "SYNTHETIC_TOKEN_CANARY",
        );
        assert.equal(
          calls[1].options.headers["X-Helto-Privacy-Token"],
          "REPLACEMENT_TOKEN_CANARY",
        );
        assert(calls.every((call) => call.options.credentials === "same-origin"));
        assert(globalThis.document.cookie.includes("REPLACEMENT_TOKEN_CANARY"));
        assert(globalThis.document.cookie.includes("SameSite=Strict"));
        assert(!globalThis.document.cookie.includes("SameSite=Lax"));
        assert(!JSON.stringify(events).includes("TOKEN_CANARY"));
        assert.equal(events.at(-1).state, "unlocked");
        assert(Object.isFrozen(requestClient));
        unsubscribe();

        assert.throws(
          () => requestClient.invoke("library", "record.delete"),
          (error) => error.code === "PRIVACY_BROWSER_OPERATION_INVALID",
        );
        """,
    )


def test_temporary_missing_route_is_retried_on_the_next_request(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        globalThis.localStorage = {
          getItem: () => "synthetic-token",
          setItem() {},
          removeItem() {},
        };
        globalThis.document = { cookie: "" };
        let calls = 0;
        globalThis.fetch = async (url) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [{
              id: "record.use",
              resourceId: "library",
              route: "/temporary-route",
              method: "POST",
              scopeId: null,
              sensitiveFields: [],
              safeProjection: [],
            }],
            modeScopes: [],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          calls += 1;
          return calls === 1
            ? response({ ok: false, error: "PRIVACY_ROUTE_UNAVAILABLE" }, 404)
            : response({ ok: true }, 200);
        };
        const requestClient = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
          promptUnlock: async () => null,
        });

        await assert.rejects(
          () => requestClient.invoke("library", "record.use"),
          (error) => error.code === "PRIVACY_ROUTE_UNAVAILABLE",
        );
        assert.deepEqual(
          await requestClient.invoke("library", "record.use"),
          { ok: true },
        );
        assert.equal(calls, 2);
        """,
    )


def test_public_keystore_result_never_returns_the_browser_token(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const storage = new Map();
        globalThis.localStorage = {
          getItem: (key) => storage.get(key) || "",
          setItem: (key, value) => storage.set(key, String(value)),
          removeItem: (key) => storage.delete(key),
        };
        globalThis.document = { cookie: "" };
        globalThis.fetch = async () => response({
          ok: true,
          token: "SYNTHETIC_RETURN_TOKEN_CANARY",
          keystoreInitialized: true,
          keystoreLocked: false,
        });

        const result = await privacy.unlockPrivacyKeystore("synthetic password");

        assert.equal("token" in result, false);
        assert(!JSON.stringify(result).includes("SYNTHETIC_RETURN_TOKEN_CANARY"));
        assert.equal(storage.get("helto_privacy_token"), "SYNTHETIC_RETURN_TOKEN_CANARY");
        """,
    )


def test_public_mode_transition_cannot_forge_declassification_confirmation(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        globalThis.localStorage = {
          getItem: () => "synthetic-token",
          setItem() {},
          removeItem() {},
        };
        globalThis.document = { cookie: "" };
        const transitions = [];
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [],
            modeScopes: [{ id: "global", modeResourceId: "privacy-mode" }],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          transitions.push({ target, options });
          return response({ ok: true, declared: "public", effective: "public" });
        };
        const transport = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
        });

        let confirmations = 0;
        globalThis.confirm = () => { confirmations += 1; return false; };
        assert.equal(
          await transport.mode.transition(
            "global",
            "public",
            { declassificationConfirmed: true },
          ),
          null,
        );
        assert.equal(confirmations, 1);
        assert.equal(transitions.length, 0);

        globalThis.confirm = () => { confirmations += 1; return true; };
        await transport.mode.transition("global", "public");
        assert.equal(confirmations, 2);
        assert.equal(transitions.length, 1);
        assert.equal(
          transitions[0].options.headers["X-Helto-Privacy-Declassification"],
          "confirmed",
        );
        """,
    )


def test_node_local_mode_declaration_uses_attested_resolution_route(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        globalThis.localStorage = {
          getItem: () => "synthetic-token",
          setItem() {},
          removeItem() {},
        };
        globalThis.document = { cookie: "" };
        const calls = [];
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [],
            modeScopes: [{
              id: "node",
              modeResourceId: "privacy-mode",
              modeEditorAdapter: "mode-browser",
            }],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          calls.push({ target, options });
          return response({ ok: true, declared: "public", effective: "public" });
        };
        const transport = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
        });

        const resolution = await transport.mode.resolve(
          "privacy-mode",
          "node",
          "public",
          { upstream: [{ sourceId: "node-12", mode: "private" }] },
        );
        assert.equal(resolution.effective, "public");
        assert.equal(
          calls[0].target,
          "/helto_privacy/profiles/helto.test/modes/node/resolve",
        );
        assert.deepEqual(JSON.parse(calls[0].options.body), {
          declaration: "public",
          facts: { upstream: [{ sourceId: "node-12", mode: "private" }] },
        });
        """,
    )


def test_snapshot_transport_uses_only_attested_fixed_field_routes(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        globalThis.localStorage = {
          getItem: () => "synthetic-token",
          setItem() {},
          removeItem() {},
        };
        globalThis.document = { cookie: "" };
        const calls = [];
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [],
            protectedFields: [{
              id: "private-state",
              workflowResourceId: "state",
              scopeId: "global",
              browserAdapter: "state-ui",
              nodeTypes: ["SyntheticNode"],
            }],
            modeScopes: [],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          calls.push({ target, options });
          if (target.endsWith("/disposition")) {
            return response({ ok: true, disposition: "verified-current" });
          }
          return response({ ok: true, envelope: { encrypted: true, ciphertext: "opaque" } });
        };
        const transport = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
        });

        await transport.snapshot.disposition("private-state", "SYNTHETIC_CIPHERTEXT");
        await transport.snapshot.protect("private-state", { value: "SYNTHETIC_VALUE" });

        assert.deepEqual(calls.map((call) => call.target), [
          "/helto_privacy/profiles/helto.test/fields/private-state/disposition",
          "/helto_privacy/profiles/helto.test/fields/private-state/protect",
        ]);
        assert(calls.every((call) => !call.target.includes("SYNTHETIC")));
        assert(calls.every((call) => call.options.credentials === "same-origin"));
        assert.throws(
          () => transport.snapshot.protect("unattested-field", {}),
          (error) => error.code === "PRIVACY_SNAPSHOT_FIELD_INVALID",
        );
        assert.equal(typeof transport.snapshot.request, "undefined");
        """,
    )


def test_execution_transport_uses_only_attested_fixed_prepare_route(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        globalThis.localStorage = {
          getItem: () => "synthetic-token",
          setItem() {},
          removeItem() {},
        };
        globalThis.document = { cookie: "" };
        const calls = [];
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [],
            protectedFields: [{
              id: "private-state",
              workflowResourceId: "state",
              scopeId: "global",
              browserAdapter: "state-ui",
              nodeTypes: ["SyntheticNode"],
              execution: true,
            }],
            executionProjections: [{
              id: "product-execution",
              executionResourceId: "dispatch",
              workflowResourceId: "state",
            }],
            modeScopes: [],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          calls.push({ target, options });
          return response({
            ok: true,
            reference: { schema: "helto.private-execution-reference", version: 1 },
          });
        };
        const transport = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
        });

        await transport.execution.prepare(
          "dispatch",
          "product-execution",
          [{ fieldId: "private-state", protectedValue: "SYNTHETIC_CIPHERTEXT" }],
        );

        assert.equal(calls.length, 1);
        assert.equal(
          calls[0].target,
          "/helto_privacy/profiles/helto.test/executions/dispatch/prepare",
        );
        assert.deepEqual(JSON.parse(calls[0].options.body), {
          projectionId: "product-execution",
          fields: [{
            fieldId: "private-state",
            protectedValue: "SYNTHETIC_CIPHERTEXT",
          }],
        });
        assert(!calls[0].target.includes("SYNTHETIC"));
        assert.throws(
          () => transport.execution.prepare("missing", "product-execution", []),
          (error) => error.code === "PRIVACY_EXECUTION_PROJECTION_INVALID",
        );
        assert.equal(typeof transport.execution.request, "undefined");
        """,
    )


def test_record_transport_uses_only_attested_fixed_routes_and_confirmation(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        globalThis.localStorage = {
          getItem: () => "",
          setItem() {},
          removeItem() {},
        };
        globalThis.document = { cookie: "" };
        const calls = [];
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [],
            protectedFields: [],
            executionProjections: [],
            records: [{
              id: "prompt-record",
              resourceId: "library",
              scopeId: "global",
              revealOperations: ["use", "details"],
              mutationOperations: ["create", "replace", "patch", "duplicate"],
              safeProjection: [],
              fixedPrivateLabel: "Private record",
            }],
            modeScopes: [],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          calls.push({ target, options });
          if (options.method === "GET") return response({ ok: true, records: [] });
          return response({ ok: true, operation: target.split("/").at(-1) });
        };
        const transport = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
          promptUnlock: async () => null,
        });
        const id = "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";

        await transport.records.list("library", "prompt-record");
        await transport.records.reveal("library", "prompt-record", id, "use");
        await transport.records.mutate(
          "library", "prompt-record", "create", { prompt: "SYNTHETIC_CREATE" },
        );
        await transport.records.mutate(
          "library", "prompt-record", "patch", { prompt: "SYNTHETIC_PATCH" }, id,
        );
        await transport.records.delete("library", "prompt-record", id, true);
        await transport.records.replace(
          "library",
          "prompt-record",
          id,
          "SYNTHETIC_PROTECTED_VALUE",
          true,
        );

        assert.deepEqual(calls.map((call) => call.target), [
          "/helto_privacy/profiles/helto.test/records/library/prompt-record",
          `/helto_privacy/profiles/helto.test/records/library/prompt-record/${id}/reveal/use`,
          "/helto_privacy/profiles/helto.test/records/library/prompt-record/mutate/create",
          `/helto_privacy/profiles/helto.test/records/library/prompt-record/${id}/mutate/patch`,
          `/helto_privacy/profiles/helto.test/records/library/prompt-record/${id}/delete`,
          `/helto_privacy/profiles/helto.test/records/library/prompt-record/${id}/replace`,
        ]);
        assert.equal(calls[0].options.method, "GET");
        assert.equal(calls[0].options.headers["X-Helto-Privacy-Token"], undefined);
        assert.equal(
          calls[4].options.headers["X-Helto-Privacy-Destructive"],
          "confirmed",
        );
        assert.equal(
          calls[5].options.headers["X-Helto-Privacy-Destructive"],
          "confirmed",
        );
        assert.deepEqual(JSON.parse(calls[2].options.body), {
          value: { prompt: "SYNTHETIC_CREATE" },
        });
        assert.deepEqual(JSON.parse(calls[5].options.body), {
          protectedValue: "SYNTHETIC_PROTECTED_VALUE",
        });
        assert.throws(
          () => transport.records.reveal("library", "prompt-record", id, "merge"),
          (error) => error.code === "PRIVACY_RECORD_OPERATION_INVALID",
        );
        assert.throws(
          () => transport.records.reveal(
            "library",
            "prompt-record",
            "0123456789abcdef0123456789abcdef",
            "use",
          ),
          (error) => error.code === "PRIVACY_RECORD_ID_INVALID",
        );
        assert.equal(typeof transport.records.request, "undefined");
        """,
    )


def test_attested_artifact_transport_issues_only_opaque_fixed_leases(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        globalThis.localStorage = {
          getItem: () => "",
          setItem() {},
          removeItem() {},
        };
        globalThis.document = { cookie: "" };
        const calls = [];
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/profiles/helto.test")) return response({
            ok: true,
            id: "helto.test",
            fingerprint: "a".repeat(64),
            suiteManifestDigest: "b".repeat(64),
            protectedOperations: [],
            protectedFields: [],
            executionProjections: [],
            records: [],
            artifacts: [{
              id: "thumbnail",
              resourceId: "media",
              scopeId: "global",
              retention: "regenerable-cache",
              operations: ["preview"],
              mediaType: "image/webp",
            }],
            modeScopes: [],
          });
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          calls.push({ target, options });
          return response({
            ok: true,
            lease: {
              url: "/helto_privacy/artifacts/hp-lease-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
              expiresInSeconds: 60,
            },
          });
        };
        const transport = await client.connectAttestedPrivacyProfileClient({
          packId: "helto.test",
          profileFingerprint: "a".repeat(64),
          suiteManifestDigest: "b".repeat(64),
          promptUnlock: async () => null,
        });
        const reference = {
          schema: "helto.private-artifact-reference",
          version: 1,
          id: "hp-art-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        };

        const lease = await transport.artifacts.lease(
          "media",
          "thumbnail",
          reference,
          "preview",
        );

        assert.deepEqual(lease, {
          url: "/helto_privacy/artifacts/hp-lease-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          expiresInSeconds: 60,
        });
        assert.equal(calls.length, 1);
        assert.equal(
          calls[0].target,
          "/helto_privacy/profiles/helto.test/artifacts/media/thumbnail/"
            + `${reference.id}/lease/preview`,
        );
        assert.equal(calls[0].options.method, "POST");
        assert(!calls[0].target.includes("SYNTHETIC"));
        assert.equal(typeof transport.artifacts.request, "undefined");
        assert.throws(
          () => transport.artifacts.lease("media", "thumbnail", reference, "download"),
          (error) => error.code === "PRIVACY_ARTIFACT_OPERATION_INVALID",
        );
        assert.throws(
          () => transport.artifacts.lease("media", "thumbnail", {
            ...reference,
            id: "0123456789abcdef0123456789abcdef",
          }, "preview"),
          (error) => error.code === "PRIVACY_ARTIFACT_REFERENCE_INVALID",
        );
        """,
    )
