from tests.test_profile_runtime_js import run_node_module_test


def test_typed_operation_response_is_exact_and_backend_only_operation_attests(tmp_path):
    run_node_module_test(
        tmp_path,
        r"""
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [{
            id: "mode-editor", nodeTypes: ["HeltoTimeline"],
            methods: [
              "onPrivacySessionChange", "readDeclaredMode", "reconcileNode",
              "reconcileNodeDefinition", "writeDeclaredMode",
            ],
          }],
          resources: [
            { id: "privacy-mode", kind: "mode" },
            { id: "operations", kind: "operation" },
          ],
          modeScopes: [{
            id: "global", modeResourceId: "privacy-mode", modeEditorAdapter: "mode-editor",
          }],
          protectedFields: [], executionProjections: [], records: [], singletons: [], artifacts: [],
          subjectModeBindings: [],
          opaqueReferenceKinds: [{
            id: "result", resourceId: "operations", scopeId: "global",
          }],
          protectedOperations: [{
            id: "run", resourceId: "operations", route: "/consumer/run", method: "POST",
            scopeId: "global", subjectModeBindingId: null,
            sensitiveFields: [{ path: "*", class: "consumer-derived" }],
            safeProjection: [{ path: "items", kind: "count" }],
            referenceInputs: [], referenceOutputs: ["result"], returnsLease: false,
          }, {
            id: "diagnostic", resourceId: "operations", route: null, method: "POST",
            scopeId: "global", subjectModeBindingId: null,
            sensitiveFields: [{ path: "*", class: "consumer-derived" }],
            safeProjection: [{ path: "items", kind: "count" }],
          }],
        });
        const app = { graph: { serialize() { return { nodes: [] }; } }, registerExtension() {} };
        const baseFetch = globalThis.fetch;
        let operationPayload = {
          ok: true, payload: { items: 1 }, private: true,
          references: [{ id: `hp-ref-${"A".repeat(32)}`, kind: "result" }],
          correlationId: "hp-operation-abcdefghijklmnop",
        };
        globalThis.fetch = async (url, options = {}) => {
          if (!String(url).endsWith("/consumer/run")) return baseFetch(url, options);
          return {
            ok: true, status: 200,
            async json() { return operationPayload; },
            async text() { return JSON.stringify(operationPayload); },
          };
        };
        const pack = await privacy.connectPrivacyPack({
          app, packId: "helto.director", profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
        });
        assert.equal(pack.operations("operations") instanceof privacy.BrowserOperationHandle, true);
        const valid = await pack.operations("operations").invoke("run", { value: 1 });
        assert.deepEqual(Object.keys(valid).sort(), [
          "correlationId", "ok", "payload", "private", "references",
        ]);
        assert.deepEqual(Object.keys(valid.references[0]).sort(), ["id", "kind"]);
        for (const invalid of [
          { ...operationPayload, secret: "leak" },
          { ...operationPayload, locator: "/private/path" },
          { ...operationPayload, references: [{ ...operationPayload.references[0], extra: true }] },
          { ...operationPayload, references: [{ ...operationPayload.references[0], kind: "wrong" }] },
          { ...operationPayload, references: [] },
        ]) {
          operationPayload = invalid;
          await assert.rejects(
            pack.operations("operations").invoke("run", { value: 1 }),
            (error) => error.code === "invalid_browser_operation_response",
          );
        }
        assert.throws(
          () => pack.operations("operations").invoke("diagnostic", { value: 1 }),
          (error) => error.code === "unknown_browser_operation",
        );
        """,
    )


def test_typed_lease_operation_accepts_only_one_exact_shared_artifact_lease(tmp_path):
    run_node_module_test(
        tmp_path,
        r"""
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [{
            id: "mode-editor", nodeTypes: ["HeltoTimeline"],
            methods: [
              "onPrivacySessionChange", "readDeclaredMode", "reconcileNode",
              "reconcileNodeDefinition", "writeDeclaredMode",
            ],
          }],
          resources: [
            { id: "privacy-mode", kind: "mode" },
            { id: "operations", kind: "operation" },
          ],
          modeScopes: [{
            id: "global", modeResourceId: "privacy-mode", modeEditorAdapter: "mode-editor",
          }],
          protectedFields: [], executionProjections: [], records: [], singletons: [], artifacts: [],
          subjectModeBindings: [],
          opaqueReferenceKinds: [{
            id: "source", resourceId: "operations", scopeId: "global",
          }],
          protectedOperations: [{
            id: "view", resourceId: "operations", route: "/consumer/view", method: "POST",
            scopeId: "global", subjectModeBindingId: null,
            sensitiveFields: [{ path: "*", class: "consumer-derived" }],
            safeProjection: [{ path: "ready", kind: "boolean" }],
            referenceInputs: [{
              name: "source", referenceKindId: "source", revokeOnSuccess: false,
            }],
            referenceOutputs: [], returnsLease: true,
          }],
        });
        const app = { graph: { serialize() { return { nodes: [] }; } }, registerExtension() {} };
        const source = `hp-ref-${"S".repeat(32)}`;
        const validLease = {
          url: `/helto_privacy/artifacts/hp-lease-${"L".repeat(32)}`,
          expiresInSeconds: 30,
        };
        let operationPayload = {
          ok: true,
          data: { ready: true },
          safePayload: null,
          references: [],
          lease: validLease,
          association: null,
          private: true,
          correlationId: "hp-operation-abcdefghijklmnop",
        };
        const baseFetch = globalThis.fetch;
        globalThis.fetch = async (url, options = {}) => {
          if (!String(url).endsWith("/consumer/view")) return baseFetch(url, options);
          assert.deepEqual(JSON.parse(options.body), {
            input: {}, references: { source },
          });
          return {
            ok: true, status: 200,
            async json() { return operationPayload; },
            async text() { return JSON.stringify(operationPayload); },
          };
        };
        const pack = await privacy.connectPrivacyPack({
          app, packId: "helto.director", profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
        });
        const valid = await pack.operations("operations").invoke("view", {}, { source });
        assert.deepEqual(valid.lease, validLease);
        assert.equal(Object.isFrozen(valid.lease), true);
        for (const invalidLease of [
          null,
          { ...validLease, path: "/private/source.mp4" },
          { ...validLease, token: "secret" },
          { ...validLease, url: "/private/source.mp4" },
          { ...validLease, url: `${validLease.url}?token=secret` },
          { ...validLease, expiresInSeconds: 0 },
        ]) {
          operationPayload = { ...operationPayload, lease: invalidLease };
          await assert.rejects(
            pack.operations("operations").invoke("view", {}, { source }),
            (error) => error.code === "invalid_browser_operation_response",
          );
        }
        """,
    )


def test_deferred_association_claim_validates_fixed_safe_payload_wire(tmp_path):
    run_node_module_test(
        tmp_path,
        r"""
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [{
            id: "mode-editor", nodeTypes: ["HeltoDirector"],
            methods: [
              "onPrivacySessionChange", "readDeclaredMode", "reconcileNode",
              "reconcileNodeDefinition", "writeDeclaredMode",
            ],
          }],
          resources: [
            { id: "privacy-mode", kind: "mode" },
            { id: "operations", kind: "operation" },
          ],
          modeScopes: [{
            id: "global", modeResourceId: "privacy-mode", modeEditorAdapter: "mode-editor",
          }],
          protectedFields: [], executionProjections: [], records: [], singletons: [], artifacts: [],
          subjectModeBindings: [{
            id: "director-mode", scopeId: "global",
            inputName: "privacy_mode_reference", nodeTypes: ["HeltoDirector"],
          }],
          opaqueReferenceKinds: [{
            id: "folder", resourceId: "operations", scopeId: "global",
          }],
          safePayloadProjections: [{
            id: "folder-list-safe", operationId: "list-folders",
            schema: "director.folder-list.v1", purpose: "director.folder-list",
            safeLeaves: [
              { path: "count", kind: "count" },
              { path: "label", kind: "safe-text" },
            ],
          }],
          protectedOperations: [{
            id: "list-folders", resourceId: "operations", route: null, method: "POST",
            scopeId: "global", subjectModeBindingId: "director-mode",
            sensitiveFields: [], safeProjection: [], referenceInputs: [],
            referenceOutputs: [{ referenceKindId: "folder", minimum: 0, maximum: 2 }],
            returnsLease: false, safePayloadProjectionId: "folder-list-safe", deferredUi: true,
          }],
        });
        const app = { graph: { serialize() { return { nodes: [] }; } }, registerExtension() {} };
        const baseFetch = globalThis.fetch;
        let claimPayload = {
          ok: true, data: {}, safePayload: { count: 2, label: "Private folder 1" }, private: true,
          references: [
            { id: `hp-ref-${"A".repeat(32)}`, kind: "folder" },
            { id: `hp-ref-${"B".repeat(32)}`, kind: "folder" },
          ],
          lease: null, association: null,
          correlationId: "hp-operation-abcdefghijklmnop",
        };
        globalThis.fetch = async (url, options = {}) => {
          if (!String(url).includes("/associations/")) return baseFetch(url, options);
          assert.deepEqual(JSON.parse(options.body), {});
          return {
            ok: true, status: 200,
            async json() { return claimPayload; },
            async text() { return JSON.stringify(claimPayload); },
          };
        };
        const pack = await privacy.connectPrivacyPack({
          app, packId: "helto.director", profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
        });
        const association = `hp-assoc-${"C".repeat(32)}`;
        const valid = await pack.operations("operations").claim("list-folders", association);
        assert.deepEqual(Object.keys(valid).sort(), [
          "association", "correlationId", "data", "lease", "ok", "private",
          "references", "safePayload",
        ]);
        for (const invalid of [
          { ...claimPayload, locator: "/private/path" },
          { ...claimPayload, association },
          { ...claimPayload, references: [...claimPayload.references, claimPayload.references[0]] },
          { ...claimPayload, safePayload: [] },
          { ...claimPayload, safePayload: { count: "SYNTHETIC_PRIVATE_CANARY", label: "Private folder 1" } },
          { ...claimPayload, safePayload: { count: 2, label: "/private/path" } },
          { ...claimPayload, safePayload: { count: 2, label: "file://private/path" } },
        ]) {
          claimPayload = invalid;
          await assert.rejects(
            pack.operations("operations").claim("list-folders", association),
            (error) => error.code === "invalid_browser_operation_response",
          );
        }
        """,
    )
