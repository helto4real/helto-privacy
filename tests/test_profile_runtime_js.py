import subprocess
import textwrap
from pathlib import Path

from tests.privacy_js_test_support import write_privacy_client_dependencies


ROOT = Path(__file__).resolve().parents[1]
PRIVACY_PROFILE = ROOT / "helto_privacy" / "web" / "privacy_profile.js"
PRIVACY_UI = ROOT / "helto_privacy" / "web" / "privacy_ui.js"
PRIVACY_CLIENT = ROOT / "helto_privacy" / "web" / "privacy_client.js"
PRIVACY_SNAPSHOT = ROOT / "helto_privacy" / "web" / "privacy_snapshot.js"
PRIVACY_SUBMISSION = ROOT / "helto_privacy" / "web" / "privacy_submission.js"


def run_node_module_test(tmp_path, body: str) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    (tmp_path / "privacy.js").write_text(PRIVACY_UI.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "privacy_client.js").write_text(
        PRIVACY_CLIENT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "privacy_snapshot.js").write_text(
        PRIVACY_SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "privacy_submission.js").write_text(
        PRIVACY_SUBMISSION.read_text(encoding="utf-8"), encoding="utf-8"
    )
    write_privacy_client_dependencies(tmp_path)
    module_path = tmp_path / "privacy_profile" / "privacy_profile.js"
    module_path.parent.mkdir()
    module_path.write_text(PRIVACY_PROFILE.read_text(encoding="utf-8"), encoding="utf-8")
    script_path = tmp_path / "test.mjs"
    script_path.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import * as privacyRaw from {module_path.as_uri()!r};

            class HeltoPrivacyTestComfyApi {{
              async fetchApi(route, options = {{}}) {{
                return globalThis.fetch(route, options);
              }}

              async queuePrompt(number, data, options = undefined) {{
                const body = {{
                  client_id: this.clientId ?? "",
                  prompt: data.output,
                  ...(options?.partialExecutionTargets
                    ? {{ partial_execution_targets: options.partialExecutionTargets }}
                    : {{}}),
                  extra_data: {{
                    ...(this.authToken === undefined
                      ? {{}}
                      : {{ auth_token_comfy_org: this.authToken }}),
                    ...(this.apiKey === undefined
                      ? {{}}
                      : {{ api_key_comfy_org: this.apiKey }}),
                    extra_pnginfo: {{ workflow: data.workflow }},
                    ...(options?.previewMethod && options.previewMethod !== "default"
                      ? {{ preview_method: options.previewMethod }}
                      : {{}}),
                  }},
                  ...(number === -1 ? {{ front: true }} : {{}}),
                  ...(number !== 0 && number !== -1 ? {{ number }} : {{}}),
                }};
                const response = await this.fetchApi("/prompt", {{
                  method: "POST",
                  headers: {{ "Content-Type": "application/json" }},
                  body: JSON.stringify(body),
                }});
                return typeof response?.json === "function" ? response.json() : response;
              }}
            }}

            const preparedPrivacyCoreFixtures = new WeakSet();
            function preparePrivacyCoreFixture(app) {{
              if (preparedPrivacyCoreFixtures.has(app)) return app;
              app.api ??= new HeltoPrivacyTestComfyApi();
              const prototype = Object.create(Object.getPrototypeOf(app));
              for (const [name, fallback] of [
                ["graphToPrompt", async function graphToPrompt() {{
                  const graph = this.rootGraph || this.graph;
                  const workflow = graph?.serialize?.() || {{ nodes: [] }};
                  const output = Object.fromEntries(
                    (graph?._nodes || []).map((node) => [String(node.id), {{ inputs: {{}} }}]),
                  );
                  return {{ workflow, output }};
                }}],
                ["queuePrompt", async function queuePrompt() {{ return true; }}],
              ]) {{
                const value = typeof app[name] === "function" ? app[name] : fallback;
                Object.defineProperty(prototype, name, {{ value, configurable: true }});
                if (Object.hasOwn(app, name)) delete app[name];
              }}
              Object.setPrototypeOf(app, prototype);
              preparedPrivacyCoreFixtures.add(app);
              return app;
            }}

            const defaultModeAdapter = Object.freeze({{
              readDeclaredMode: () => "private",
              writeDeclaredMode() {{}},
              onPrivacySessionChange() {{}},
              reconcileNode() {{}},
              reconcileNodeDefinition() {{}},
            }});
            const privacy = Object.freeze({{
              ...privacyRaw,
              connectPrivacyPack(options) {{
                preparePrivacyCoreFixture(options.app);
                return privacyRaw.connectPrivacyPack({{
                  ...options,
                  adapters: {{
                    ...(!options.adapters?.["mode-editor"]
                      && !options.adapterFactories?.["mode-editor"]
                      ? {{ "mode-editor": defaultModeAdapter }}
                      : {{}}),
                    ...(options.adapters || {{}}),
                  }},
                }});
              }},
            }});

            const fingerprint = "a".repeat(64);
            const suiteDigest = "d".repeat(64);
            const attestation = (overrides = {{}}) => ({{
              id: "helto.director",
              contract: privacy.PRIVACY_CONTRACT_V3,
              modeTransitionProtocol: privacy.MODE_TRANSITION_PROTOCOL,
              serverBootEpoch: `hp-boot-${{"b".repeat(32)}}`,
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
              }}, {{
                id: "mode-editor",
                nodeTypes: ["HeltoTimeline"],
                methods: [
                  "onPrivacySessionChange",
                  "readDeclaredMode",
                  "reconcileNode",
                  "reconcileNodeDefinition",
                  "writeDeclaredMode",
                ],
              }}],
              resources: [
                {{ id: "privacy-mode", kind: "mode" }},
                {{ id: "timeline", kind: "workflow" }},
                {{ id: "library", kind: "record" }},
                {{ id: "pack-state", kind: "singleton" }},
                {{ id: "thumbnail", kind: "artifact" }},
                {{ id: "render", kind: "execution" }},
              ],
              modeScopes: [{{
                id: "global",
                modeResourceId: "privacy-mode",
                modeEditorAdapter: "mode-editor",
              }}],
              protectedFields: [{{
                id: "timeline-state",
                workflowResourceId: "timeline",
                scopeId: "global",
                browserAdapter: "timeline-editor",
                nodeTypes: ["HeltoTimeline"],
                legacyReaderIds: [],
                execution: true,
                stateAuthority: "server-durable",
                externalTransitionPolicy: null,
              }}],
              executionProjections: [{{
                id: "timeline-render",
                executionResourceId: "render",
                workflowResourceId: "timeline",
                subjectModeBindingId: "timeline-render-mode",
                inputName: "private_execution",
              }}],
              records: [{{
                id: "prompt-record",
                resourceId: "library",
                scopeId: "global",
                revealOperations: ["use", "details"],
                mutationOperations: ["create", "replace", "patch", "duplicate"],
                safeProjection: [],
                fixedPrivateLabel: "Private record",
              }}],
              singletons: [{{
                id: "provider-settings",
                resourceId: "pack-state",
                scopeId: "global",
                currentSchema: "helto.director.provider-settings.v1",
                purpose: "provider-settings",
                storeAdapter: "provider-settings-store",
                payloadKind: "field",
                legacyReaderIds: ["provider-settings-v1"],
              }}],
              artifacts: [{{
                id: "thumbnail",
                resourceId: "thumbnail",
                scopeId: "global",
                retention: "regenerable-cache",
                operations: ["preview"],
                mediaType: "image/webp",
                payloadMode: "bounded-bytes-v1",
                streamContract: null,
              }}],
              protectedOperations: [],
              subjectModeBindings: [{{
                id: "timeline-render-mode",
                scopeId: "global",
                inputName: "privacy_mode_reference",
                nodeTypes: ["HeltoTimeline"],
              }}],
              ...overrides,
            }});
            let serverAttestation = () => attestation();
            const executionBodies = [];
            const recordCalls = [];
            const artifactCalls = [];
            const modeResolutionCalls = [];
            const subjectModeCalls = [];
            let subjectModeSubject = "c".repeat(64);
            const promptBodies = [];
            const revokedSubmissionGrants = [];
            let externalOperationHandler = null;
            globalThis.fetch = async (url, options = {{}}) => {{
              const target = String(url);
              let payload = {{ ok: true }};
              if (target === "/prompt") {{
                promptBodies.push(JSON.parse(options.body));
              }} else if (target.endsWith("/disposition")) {{
                payload = {{ ok: true, disposition: "verified-current" }};
              }} else if (target.endsWith("/protect")) {{
                payload = {{ ok: true, envelope: "SYNTHETIC_CURRENT_ENVELOPE" }};
              }} else if (target.endsWith("/reveal")) {{
                payload = {{ ok: true, value: {{ value: "SYNTHETIC_REVEALED_STATE" }} }};
              }} else if (target.endsWith("/modes/global/resolve")) {{
                const body = JSON.parse(options.body);
                modeResolutionCalls.push({{ target, body }});
                payload = {{
                  id: "global",
                  modeResourceId: "privacy-mode",
                  declared: body.declaration,
                  effective: body.declaration === "public" ? "public" : "private",
                  inheritedFrom: "declared-" + body.declaration,
                  floors: [],
                  transitionStatus: "idle",
                }};
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
              }} else if (target.endsWith("/submission-grants/revoke")) {{
                revokedSubmissionGrants.push(JSON.parse(options.body));
                return {{
                  ok: true,
                  status: 204,
                  async json() {{ return {{}}; }},
                  async text() {{ return ""; }},
                }};
              }} else if (target.endsWith("/executions/render/prepare")) {{
                executionBodies.push(JSON.parse(options.body));
                payload = {{
                  ok: true,
                  reference: {{
                    schema: "helto.private-execution-reference",
                    version: 2,
                    packId: "helto.director",
                    executionResourceId: "render",
                    projectionId: "timeline-render",
                    workflowResourceId: "timeline",
                    subject: "a".repeat(64),
                    grant: "SYNTHETIC_OPAQUE_GRANT",
                    fields: [],
                  }},
                }};
              }} else if (target.endsWith("/subject-modes/timeline-render-mode/prepare")) {{
                const body = JSON.parse(options.body);
                subjectModeCalls.push(body);
                payload = {{
                  ok: true,
                  effective: body.declaration,
                  reference: {{
                    schema: "helto.subject-mode-reference",
                    version: 2,
                    packId: "helto.director",
                    profileFingerprint: fingerprint,
                    bindingId: "timeline-render-mode",
                    scopeId: "global",
                    subject: subjectModeSubject,
                    grant: `opaque-subject-grant-${{subjectModeCalls.length}}`,
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
                else if (target.includes("/mutate/")) payload = {{
                  ok: true,
                  recordId: "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
                  kind: "prompt-record",
                  operation: target.split("/").at(-1),
                  correlationId: "hp-record-bcdefghijklmnopq",
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
              }} else if (
                externalOperationHandler
                && target.includes("/operations/")
                && target.includes("/external")
              ) {{
                return externalOperationHandler(target, options);
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


def write_privacy_profile_module_tree(target: Path) -> Path:
    target.mkdir()
    (target / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    (target / "privacy.js").write_text(
        PRIVACY_UI.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (target / "privacy_client.js").write_text(
        PRIVACY_CLIENT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (target / "privacy_snapshot.js").write_text(
        PRIVACY_SNAPSHOT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (target / "privacy_submission.js").write_text(
        PRIVACY_SUBMISSION.read_text(encoding="utf-8"), encoding="utf-8"
    )
    write_privacy_client_dependencies(target)
    module_path = target / "privacy_profile" / "privacy_profile.js"
    module_path.parent.mkdir()
    module_path.write_text(PRIVACY_PROFILE.read_text(encoding="utf-8"), encoding="utf-8")
    return module_path


def test_snapshot_resolves_owner_local_mode_declaration_and_facts(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 12,
          type: "HeltoTimeline",
          live: { value: "initial" },
          protected: "SYNTHETIC_ENVELOPE",
        };
        const workflow = {
          apply() {},
          clear() {},
          normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {},
          reconcileNode() {},
          reconcileNodeDefinition() {},
        };
        const seenOwners = [];
        const mode = {
          readDeclaredMode(node) { seenOwners.push(node); return "public"; },
          readModeFacts(node) {
            assert.equal(node, owner);
            return { upstream: [{ sourceId: "node-11", mode: "public" }] };
          },
          writeDeclaredMode() {},
          onPrivacySessionChange() {},
          reconcileNode() {},
          reconcileNodeDefinition() {},
        };
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [
            {
              id: "mode-editor",
              nodeTypes: ["HeltoTimeline"],
              methods: [
                "onPrivacySessionChange",
                "readDeclaredMode",
                "reconcileNode",
                "reconcileNodeDefinition",
                "writeDeclaredMode",
              ],
            },
            attestation().requiredBrowserAdapters[0],
          ],
          modeScopes: [{
            id: "global",
            modeResourceId: "privacy-mode",
            modeEditorAdapter: "mode-editor",
          }],
        });
        const app = {
          rootGraph: { _nodes: [owner] },
          registeredNodeTypes: {},
          registerExtension(extension) { this.extension = extension; },
        };

        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "mode-editor": mode, "timeline-editor": workflow },
        });

        assert.deepEqual(seenOwners, [owner]);
        assert.equal(modeResolutionCalls.length, 1);
        assert.deepEqual(modeResolutionCalls[0].body, {
          declaration: "public",
          facts: { upstream: [{ sourceId: "node-11", mode: "public" }] },
        });
        const ownerResolution = await pack.mode("privacy-mode").resolve("global", owner);
        assert.equal(ownerResolution.effective, "public");
        assert.equal(modeResolutionCalls.length, 2);
        assert.deepEqual(modeResolutionCalls[1].body, {
          declaration: "public",
          facts: { upstream: [{ sourceId: "node-11", mode: "public" }] },
        });
        """,
    )


def test_workflow_reload_rereads_exact_protected_bytes_without_reencrypting(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 12,
          type: "HeltoTimeline",
          live: { value: "before" },
          protected: "SYNTHETIC_ORIGINAL_ENVELOPE",
        };
        const applied = [];
        const workflow = {
          apply(node, value) { applied.push([node, value]); },
          clear() {},
          normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {},
          reconcileNode() {},
          reconcileNodeDefinition() {},
        };
        const originalFetch = globalThis.fetch;
        let protectCalls = 0;
        globalThis.fetch = async (url, options = {}) => {
          if (String(url).endsWith("/protect")) protectCalls += 1;
          return originalFetch(url, options);
        };
        const app = {
          rootGraph: { _nodes: [owner] },
          registeredNodeTypes: {},
          registerExtension(extension) { this.extension = extension; },
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": workflow },
        });
        const beforeReloadProtectCalls = protectCalls;
        owner.protected = "SYNTHETIC_EXACT_ROLLBACK_ENVELOPE";
        const exact = await pack.workflow("timeline").reload(owner, "timeline-state");

        assert.equal(exact, "SYNTHETIC_EXACT_ROLLBACK_ENVELOPE");
        assert.equal(owner.protected, exact);
        assert.equal(protectCalls, beforeReloadProtectCalls);
        assert.equal(pack.workflow("timeline").workflowProjection(owner, "timeline-state"), exact);
        assert.equal(applied.at(-1)[0], owner);
        assert.deepEqual(applied.at(-1)[1], { value: "SYNTHETIC_REVEALED_STATE" });
        """,
    )


def test_owner_local_mode_adapter_failure_blocks_profile_connection(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 12,
          type: "HeltoTimeline",
          live: { value: "initial" },
          protected: "SYNTHETIC_ENVELOPE",
        };
        const workflow = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const mode = {
          readDeclaredMode() { throw new Error("SYNTHETIC_PRIVATE_MODE_FAILURE"); },
          writeDeclaredMode() {}, onPrivacySessionChange() {},
          reconcileNode() {}, reconcileNodeDefinition() {},
        };
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [
            {
              id: "mode-editor",
              nodeTypes: ["HeltoTimeline"],
              methods: [
                "onPrivacySessionChange", "readDeclaredMode", "reconcileNode",
                "reconcileNodeDefinition", "writeDeclaredMode",
              ],
            },
            attestation().requiredBrowserAdapters[0],
          ],
          modeScopes: [{
            id: "global",
            modeResourceId: "privacy-mode",
            modeEditorAdapter: "mode-editor",
          }],
        });
        const app = {
          rootGraph: { _nodes: [owner] },
          registeredNodeTypes: {},
          registerExtension() {},
        };

        await assert.rejects(
          () => privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: { "mode-editor": mode, "timeline-editor": workflow },
          }),
          (error) => error.code === "browser_lifecycle_registration_failed",
        );
        assert.equal(modeResolutionCalls.length, 0);
        """,
    )


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
        assert.equal(app.registerCount, 2);
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
        assert.equal(typeof pack.singletons, "undefined");
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
        assert.deepEqual(
          await records.create("prompt-record", { prompt: "SYNTHETIC_CREATE_VALUE" }),
          {
            ok: true,
            recordId: "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            kind: "prompt-record",
            operation: "create",
            correlationId: "hp-record-bcdefghijklmnopq",
          },
        );
        assert.equal((await records.mutate(
          "prompt-record",
          "hp-rec-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          "patch",
          { prompt: "SYNTHETIC_PATCH_VALUE" },
        )).operation, "patch");
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
          subjectId: "1",
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
        assert.equal(app.registerCount, 2);
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
        serverAttestation = () => attestation({ contract: "helto.privacy.v2" });
        await assert.rejects(
          () => privacy.connectPrivacyPack(base),
          (error) => error.code === "browser_server_attestation_drift",
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
        serverAttestation = () => attestation({
          subjectModeBindings: [{
            id: "timeline-render-mode",
            scopeId: "missing-scope",
            inputName: "privacy_mode_reference",
            nodeTypes: ["AIOImageGenerate"],
          }],
        });
        await assert.rejects(
          () => privacy.connectPrivacyPack(base),
          (error) => error.code === "server_attestation_unavailable",
        );

        serverAttestation = () => {
          const value = attestation();
          return {
            ...value,
            artifacts: [{
              ...value.artifacts[0],
              retention: "durable-adjunct",
              payloadMode: "stream-v1",
              streamContract: {
                codecSchema: "raw-segment-v1",
                codecVersion: 1,
                maxPlaintextBytes: 1024,
                maxOwnerPlaintextBytes: 4096,
                decodedOutput: "materialized",
                maxMaterializedOutputBytes: 1024,
              },
            }],
          };
        };
        await assert.rejects(
          () => privacy.connectPrivacyPack(base),
          (error) => error.code === "server_attestation_unavailable",
        );

        serverAttestation = () => attestation({ suiteStatus: "activation-required" });
        const verificationApp = { graph: { nodes: [] }, registerExtension() {} };
        const verificationPack = await privacy.connectPrivacyPack({
          ...base,
          app: verificationApp,
        });
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
        assert.equal(pack.readiness.state, "conflict");
        assert.throws(() => pack.readiness.requireReady(), /incomplete or conflicting/);
        assert.throws(
          () => app.graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
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


def test_browser_rejects_malformed_duplicate_and_drifted_singleton_attestation(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live || {}; },
          readProtected(node) { return node.protected || "SYNTHETIC_ENVELOPE"; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {},
          reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const connect = () => privacy.connectPrivacyPack({
          app: { graph: { nodes: [] }, registerExtension() {} },
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const singleton = attestation().singletons[0];
        const cases = [
          { singletons: undefined },
          { singletons: [singleton, { ...singleton }] },
          { singletons: [{ ...singleton, extra: true }] },
          { singletons: [{ ...singleton, currentSchema: "" }] },
          { singletons: [{ ...singleton, payloadKind: "opaque" }] },
          { singletons: [{ ...singleton, scopeId: "missing" }] },
          { singletons: [{
            ...singleton,
            legacyReaderIds: ["provider-settings-v1", "provider-settings-v1"],
          }] },
          {
            resources: attestation().resources.map((resource) => (
              resource.id === "pack-state" ? { ...resource, kind: "record" } : resource
            )),
          },
        ];
        for (const overrides of cases) {
          serverAttestation = () => attestation(overrides);
          await assert.rejects(
            connect,
            (error) => error.code === "invalid_singleton_declaration",
          );
        }
        """,
    )


def test_browser_validates_exact_protected_operation_dependencies(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live || {}; },
          readProtected(node) { return node.protected || "SYNTHETIC_ENVELOPE"; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {},
          reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const operation = {
          id: "timeline.consume",
          resourceId: "timeline",
          route: "/timeline/consume",
          method: "POST",
          scopeId: "global",
          sensitiveFields: [{ path: "*", class: "consumer-derived" }],
          safeProjection: [{ path: "items", kind: "count" }],
          recordDependencies: [{
            resourceId: "library", recordKind: "prompt-record", operation: "use",
          }],
          singletonDependencies: [{
            singletonId: "provider-settings", verbs: ["reveal", "status"],
          }],
          artifactDependencies: [{
            artifactKind: "thumbnail", verbs: ["lease.preview", "read"],
          }],
        };
        const connect = (packId) => privacy.connectPrivacyPack({
          app: { graph: { nodes: [] }, registerExtension() {} },
          packId,
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });

        serverAttestation = () => attestation({
          id: "helto.dependency-valid",
          protectedOperations: [operation],
        });
        const valid = await connect("helto.dependency-valid");
        assert.equal(valid.readiness.state, "ready");

        const malformed = [
          { ...operation, recordDependencies: [
            ...operation.recordDependencies,
            { ...operation.recordDependencies[0] },
          ] },
          { ...operation, recordDependencies: [{
            ...operation.recordDependencies[0], operation: "merge",
          }] },
          { ...operation, singletonDependencies: [{
            singletonId: "provider-settings", verbs: ["status", "reveal"],
          }] },
          { ...operation, singletonDependencies: [{
            singletonId: "provider-settings", verbs: ["export"],
          }] },
          { ...operation, artifactDependencies: [{
            artifactKind: "thumbnail", verbs: ["lease.inspect"],
          }] },
          { ...operation, artifactDependencies: [{
            artifactKind: "thumbnail", verbs: ["reconcile-owner"],
          }] },
          { ...operation, artifactDependencies: [{
            artifactKind: "thumbnail", verbs: ["read"], extra: true,
          }] },
          { ...operation, scopeId: null },
        ];
        for (const [index, candidate] of malformed.entries()) {
          const packId = `helto.dependency-invalid-${index}`;
          serverAttestation = () => attestation({
            id: packId,
            protectedOperations: [candidate],
          });
          await assert.rejects(
            () => connect(packId),
            (error) => [
              "PRIVACY_BROWSER_ATTESTATION_INVALID",
              "invalid_server_operation_declaration",
              "server_attestation_unavailable",
            ].includes(error.code),
          );
        }
        const spillPackId = "helto.dependency-invalid-spill-write";
        serverAttestation = () => attestation({
          id: spillPackId,
          artifacts: [{
            ...attestation().artifacts[0],
            retention: "run-scoped-spill",
            operations: [],
          }],
          protectedOperations: [{
            ...operation,
            artifactDependencies: [{ artifactKind: "thumbnail", verbs: ["write"] }],
          }],
        });
        await assert.rejects(
          () => connect(spillPackId),
          (error) => [
            "PRIVACY_BROWSER_ATTESTATION_INVALID",
            "invalid_server_operation_declaration",
            "server_attestation_unavailable",
          ].includes(error.code),
        );
        """,
    )


def test_connection_gate_is_installed_before_attestation_and_hands_off_to_snapshot(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 41,
          type: "HeltoTimeline",
          live: { value: "initial" },
          protected: "SYNTHETIC_ENVELOPE",
        };
        const graph = {
          _nodes: [owner],
          serialize() { return { nodes: [owner.live] }; },
        };
        const app = {
          graph,
          async graphToPrompt() {
            return { workflow: graph.serialize(), output: {} };
          },
          async queuePrompt() { return this.graphToPrompt(); },
          registeredNodeTypes: {},
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const fetchBeforeGate = globalThis.fetch;
        let attestationObserved = false;
        globalThis.fetch = async (...args) => {
          if (!attestationObserved && String(args[0]).includes("/profiles/")) {
            attestationObserved = true;
            assert.throws(
              () => graph.serialize(),
              (error) => error.code === "PRIVACY_PROFILE_CONNECTING"
                && !error.message.includes("HeltoTimeline"),
            );
            await assert.rejects(
              app.graphToPrompt(),
              (error) => error.code === "PRIVACY_PROFILE_CONNECTING",
            );
            await assert.rejects(
              app.queuePrompt(),
              (error) => error.code === "PRIVACY_PROFILE_CONNECTING",
            );
            const status = await app.api.fetchApi("/status");
            assert.equal(status.ok, true);
            await assert.rejects(
              app.api.fetchApi("/prompt", { method: "POST" }),
              (error) => error.code === "PRIVACY_PROFILE_CONNECTING",
            );
          }
          return fetchBeforeGate(...args);
        };

        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        assert(attestationObserved);
        assert.equal(pack.readiness.state, "ready");
        assert.deepEqual(await app.graphToPrompt(), {
          workflow: { nodes: [{ value: "initial" }] },
          output: {},
        });
        assert.deepEqual(await Promise.race([
          app.queuePrompt(),
          new Promise((_, reject) => setTimeout(
            () => reject(new Error("SYNTHETIC_QUEUE_DEADLOCK")),
            250,
          )),
        ]), {
          workflow: { nodes: [{ value: "initial" }] },
          output: {},
        });

        owner.live = { value: "edited" };
        pack.workflow("timeline").markEdited(owner, "timeline-state");
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_SNAPSHOT_UNSETTLED",
        );
        """,
    )


def test_connection_failures_leave_serialization_permanently_blocked(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = { serialize() { return { nodes: [] }; } };
        const app = {
          graph,
          async graphToPrompt() { return { workflow: graph.serialize(), output: {} }; },
          async queuePrompt() { return this.graphToPrompt(); },
          registerExtension() {},
        };
        serverAttestation = () => attestation({ fingerprint: "b".repeat(64) });
        await assert.rejects(
          privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: { "timeline-editor": {} },
          }),
          (error) => error.code === "browser_server_attestation_drift",
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        await assert.rejects(
          app.graphToPrompt(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        await assert.rejects(
          app.queuePrompt(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_factory_and_reconciliation_failures_keep_connection_gate_closed(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = {
          _nodes: [{ id: 2, type: "HeltoTimeline" }],
          serialize() { return { nodes: [] }; },
        };
        const app = { graph, registerExtension() {} };
        await assert.rejects(
          privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapterFactories: {
              "timeline-editor": () => ({
                apply() {}, clear() {}, normalize() { return {}; },
                readProtected() { return "SYNTHETIC_ENVELOPE"; },
                writeProtected() {}, onPrivacySessionChange() {},
                reconcileNode() { throw new Error("SYNTHETIC_PRIVATE_RECONCILE"); },
                reconcileNodeDefinition() {},
              }),
            },
          }),
          (error) => error.code === "browser_lifecycle_registration_failed",
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_late_serialization_methods_remain_guarded(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = { _nodes: [], subgraphs: new Map() };
        const nested = { serialize() { return { nested: true }; } };
        graph.subgraphs.set("nested", nested);
        const app = { graph, registerExtension() {} };
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pending = privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        assert.throws(
          () => { app.graphToPrompt = async () => ({ workflow: {}, output: {} }); },
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        assert.throws(
          () => nested.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        const dynamicNested = { serialize() { return { dynamic: true }; } };
        graph.subgraphs.set("dynamic", dynamicNested);
        assert.throws(
          () => dynamicNested.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        graph.subgraphs = [];
        const indexedNested = { serialize() { return { indexed: true }; } };
        graph.subgraphs[0] = indexedNested;
        assert.throws(
          () => indexedNested.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        await assert.rejects(pending);
        """,
    )


def test_pre_gate_array_alias_cannot_add_a_live_subgraph(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const retainedSubgraphs = [];
        const graph = {
          _nodes: [],
          subgraphs: retainedSubgraphs,
          serialize() { return { nodes: [] }; },
        };
        const app = { graph, registerExtension() {} };
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pending = privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const aliasCandidate = { serialize() { return { alias: true }; } };
        assert.throws(() => { retainedSubgraphs[0] = aliasCandidate; }, TypeError);
        assert.equal(graph.subgraphs.length, 0);
        const liveCandidate = { serialize() { return { live: true }; } };
        graph.subgraphs[0] = liveCandidate;
        assert.throws(
          () => liveCandidate.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_CONNECTING",
        );
        await pending;
        assert.deepEqual(liveCandidate.serialize(), { live: true });
        """,
    )


def test_same_identity_concurrent_connections_share_one_installation(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = { serialize() { return { nodes: [] }; } };
        const app = {
          graph,
          registerExtension() { this.registerCount = (this.registerCount || 0) + 1; },
        };
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const baseFetch = globalThis.fetch;
        let releaseAttestation;
        let profileFetches = 0;
        const blocked = new Promise((resolve) => { releaseAttestation = resolve; });
        globalThis.fetch = async (...args) => {
          if (String(args[0]).includes("/profiles/helto.director")) {
            profileFetches += 1;
            await blocked;
          }
          return baseFetch(...args);
        };
        const options = {
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        };
        const first = privacy.connectPrivacyPack(options);
        const second = privacy.connectPrivacyPack(options);
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_CONNECTING",
        );
        releaseAttestation();
        const [firstPack, secondPack] = await Promise.all([first, second]);
        assert.equal(firstPack, secondPack);
        assert.equal(profileFetches, 1);
        assert.equal(app.registerCount, 2);
        assert.deepEqual(graph.serialize(), { nodes: [] });
        """,
    )


def test_multiple_packs_share_gate_readiness_and_failure_state(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = { serialize() { return { nodes: [] }; } };
        const app = { graph, registerExtension() {} };
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const baseFetch = globalThis.fetch;
        let releaseSecond;
        let releaseThird;
        const secondBlocked = new Promise((resolve) => { releaseSecond = resolve; });
        const thirdBlocked = new Promise((resolve) => { releaseThird = resolve; });
        const response = (payload) => ({
          ok: true,
          status: 200,
          async json() { return payload; },
          async text() { return JSON.stringify(payload); },
        });
        globalThis.fetch = async (...args) => {
          const target = String(args[0]);
          if (target.endsWith("/profiles/helto.secondary")) {
            await secondBlocked;
            return response(attestation({ id: "helto.secondary" }));
          }
          if (target.endsWith("/profiles/helto.tertiary")) {
            await thirdBlocked;
            return response(attestation({ id: "helto.tertiary" }));
          }
          return baseFetch(...args);
        };
        const primary = privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const secondary = privacy.connectPrivacyPack({
          app,
          packId: "helto.secondary",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        let primaryResolved = false;
        primary.then(() => { primaryResolved = true; });
        await new Promise((resolve) => setTimeout(resolve, 0));
        assert.equal(primaryResolved, false);
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_CONNECTING",
        );
        releaseSecond();
        const [primaryPack, secondaryPack] = await Promise.all([primary, secondary]);
        assert.equal(primaryPack.readiness.state, "ready");
        assert.equal(secondaryPack.readiness.state, "ready");
        assert.deepEqual(graph.serialize(), { nodes: [] });

        const tertiary = privacy.connectPrivacyPack({
          app,
          packId: "helto.tertiary",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        assert.equal(primaryPack.readiness.state, "connecting");
        assert.equal(secondaryPack.readiness.state, "connecting");
        releaseThird();
        const tertiaryPack = await tertiary;
        assert.equal(primaryPack.readiness.state, "ready");
        assert.equal(secondaryPack.readiness.state, "ready");
        assert.equal(tertiaryPack.readiness.state, "ready");

        await assert.rejects(
          privacy.connectPrivacyPack({
            app,
            packId: "helto.secondary",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: {},
          }),
          (error) => error.code === "browser_adapter_mismatch",
        );
        assert.equal(primaryPack.readiness.state, "conflict");
        assert.equal(secondaryPack.readiness.state, "conflict");
        assert.equal(tertiaryPack.readiness.state, "conflict");
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_pending_connection_rejects_different_adapter_declaration(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = { serialize() { return { nodes: [] }; } };
        const app = { graph, registerExtension() {} };
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const baseFetch = globalThis.fetch;
        let releaseAttestation;
        const blocked = new Promise((resolve) => { releaseAttestation = resolve; });
        globalThis.fetch = async (...args) => {
          if (String(args[0]).includes("/profiles/helto.director")) await blocked;
          return baseFetch(...args);
        };
        const first = privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        await assert.rejects(
          privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapterFactories: { "timeline-editor": () => adapter },
          }),
          (error) => error.code === "browser_profile_conflict",
        );
        releaseAttestation();
        await assert.rejects(first);
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_conflicting_pending_connection_cannot_open_gate(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = { serialize() { return { nodes: [] }; } };
        const app = { graph, registerExtension() {} };
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const baseFetch = globalThis.fetch;
        let releaseAttestation;
        const blocked = new Promise((resolve) => { releaseAttestation = resolve; });
        globalThis.fetch = async (...args) => {
          if (String(args[0]).includes("/profiles/helto.director")) await blocked;
          return baseFetch(...args);
        };
        const first = privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        await assert.rejects(
          privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: "b".repeat(64),
            suiteManifestDigest: suiteDigest,
            adapters: { "timeline-editor": adapter },
          }),
          (error) => error.code === "browser_profile_conflict",
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        releaseAttestation();
        await assert.rejects(
          first,
          (error) => error.code === "browser_lifecycle_registration_failed",
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_app_queue_calls_through_and_api_sink_owns_execution_transaction(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 19,
          type: "HeltoTimeline",
          live: { value: "initial" },
          protected: "SYNTHETIC_ENVELOPE",
        };
        const graph = {
          _nodes: [owner],
          serialize() { return { nodes: [owner.live] }; },
        };
        const app = {
          graph,
          async queuePrompt() {
            const promptData = await this.graphToPrompt();
            return this.api.queuePrompt(0, promptData);
          },
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        owner.live = { value: "edited" };
        pack.workflow("timeline").markEdited(owner, "timeline-state");
        const result = await app.queuePrompt();
        assert.equal(result.ok, true);
        assert.equal(executionBodies.length, 1);
        assert.equal(owner.protected, "SYNTHETIC_CURRENT_ENVELOPE");
        """,
    )


def test_lexical_queue_graph_to_prompt_preserves_receiver_without_deadlock(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const events = [];
        const graph = { serialize() { events.push("serialize"); return { nodes: [] }; } };
        let releaseQueue;
        let queueEntered;
        const queueBlocked = new Promise((resolve) => { releaseQueue = resolve; });
        const entered = new Promise((resolve) => { queueEntered = resolve; });
        const app = {
          graph,
          async graphToPrompt() {
            events.push("graphToPrompt");
            return { workflow: graph.serialize(), output: {} };
          },
          async queuePrompt() {
            assert.equal(this, app);
            events.push("queue:start");
            queueEntered();
            await queueBlocked;
            const result = await app.graphToPrompt();
            events.push("queue:end");
            return result;
          },
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const queued = app.queuePrompt();
        await entered;
        assert.deepEqual(events, ["queue:start"]);
        releaseQueue();
        await Promise.race([
          queued,
          new Promise((_, reject) => setTimeout(
            () => reject(new Error("SYNTHETIC_QUEUE_DEADLOCK")),
            250,
          )),
        ]);
        assert.deepEqual(events, [
          "queue:start",
          "graphToPrompt",
          "serialize",
          "queue:end",
        ]);
        """,
    )


def test_app_queue_does_not_borrow_an_ambient_snapshot_for_generation_changes(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 27, type: "HeltoTimeline", live: {}, protected: "SYNTHETIC_ENVELOPE",
        };
        let rawGraphCalls = 0;
        let releaseQueue;
        let queueEntered;
        const blocked = new Promise((resolve) => { releaseQueue = resolve; });
        const entered = new Promise((resolve) => { queueEntered = resolve; });
        const graph = { _nodes: [owner], serialize() { return { nodes: [] }; } };
        const app = {
          graph,
          async graphToPrompt() {
            rawGraphCalls += 1;
            return { workflow: graph.serialize(), output: {} };
          },
          async queuePrompt() {
            queueEntered();
            await blocked;
            return app.graphToPrompt();
          },
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const queued = app.queuePrompt();
        await entered;
        pack.workflow("timeline").markEdited(owner, "timeline-state");
        await app.graphToPrompt();
        assert.equal(rawGraphCalls, 1);
        releaseQueue();
        await queued;
        assert.equal(rawGraphCalls, 2);
        """,
    )


def test_app_queue_does_not_borrow_an_ambient_snapshot_across_session_changes(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 28, type: "HeltoTimeline", live: {}, protected: "SYNTHETIC_ENVELOPE",
        };
        let rawGraphCalls = 0;
        let releaseQueue;
        let queueEntered;
        const blocked = new Promise((resolve) => { releaseQueue = resolve; });
        const entered = new Promise((resolve) => { queueEntered = resolve; });
        const graph = { _nodes: [owner], serialize() { return { nodes: [] }; } };
        const app = {
          graph,
          async graphToPrompt() {
            rawGraphCalls += 1;
            return { workflow: graph.serialize(), output: {} };
          },
          async queuePrompt() {
            queueEntered();
            await blocked;
            return app.graphToPrompt();
          },
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const queued = app.queuePrompt();
        await entered;
        globalThis.localStorage = {
          getItem: () => "",
          setItem() {},
          removeItem() {},
        };
        const shared = await import(new URL("./privacy.js", import.meta.url));
        await shared.unlockPrivacyKeystore("synthetic password");
        await app.graphToPrompt();
        assert.equal(rawGraphCalls, 1);
        releaseQueue();
        await queued;
        assert.equal(rawGraphCalls, 2);
        """,
    )


def test_raw_graph_to_prompt_rechecks_generation_after_await(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 31, type: "HeltoTimeline", live: {}, protected: "SYNTHETIC_ENVELOPE",
        };
        let releaseRaw;
        let rawEntered;
        const blocked = new Promise((resolve) => { releaseRaw = resolve; });
        const entered = new Promise((resolve) => { rawEntered = resolve; });
        const graph = { _nodes: [owner], serialize() { return { nodes: [] }; } };
        const app = {
          graph,
          async graphToPrompt() {
            rawEntered();
            await blocked;
            return { workflow: { nodes: [] }, output: {} };
          },
          async queuePrompt() {
            return app.api.queuePrompt(0, await app.graphToPrompt());
          },
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const queued = app.queuePrompt();
        await entered;
        pack.workflow("timeline").markEdited(owner, "timeline-state");
        releaseRaw();
        await assert.rejects(
          queued,
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );
        """,
    )


def test_reference_preparation_rechecks_session_before_output_mutation(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 32, type: "HeltoTimeline", live: {}, protected: "SYNTHETIC_ENVELOPE",
        };
        const promptData = {
          workflow: { nodes: [] },
          output: { "32": { inputs: { stable: "SYNTHETIC_UNCHANGED" } } },
        };
        const graph = { _nodes: [owner], serialize() { return { nodes: [] }; } };
        const app = {
          graph,
          async graphToPrompt() { return promptData; },
          async queuePrompt() {
            return app.api.queuePrompt(0, await app.graphToPrompt());
          },
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const baseFetch = globalThis.fetch;
        let releasePreparation;
        let preparationEntered;
        const blocked = new Promise((resolve) => { releasePreparation = resolve; });
        const entered = new Promise((resolve) => { preparationEntered = resolve; });
        globalThis.fetch = async (...args) => {
          if (String(args[0]).endsWith("/executions/render/prepare")) {
            preparationEntered();
            await blocked;
          }
          return baseFetch(...args);
        };
        await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const queued = app.queuePrompt();
        await entered;
        globalThis.localStorage = {
          getItem: () => "",
          setItem() {},
          removeItem() {},
        };
        const shared = await import(new URL("./privacy.js", import.meta.url));
        await shared.unlockPrivacyKeystore("synthetic password");
        releasePreparation();
        await assert.rejects(
          queued,
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );
        assert.deepEqual(promptData.output["32"].inputs, {
          stable: "SYNTHETIC_UNCHANGED",
        });
        """,
    )


def test_multiple_reference_preparations_are_atomic_on_late_staleness(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const firstOwner = {
          id: 41, type: "HeltoTimeline", live: {}, protected: "SYNTHETIC_ENVELOPE_ONE",
        };
        const secondOwner = {
          id: 42, type: "HeltoTimeline", live: {}, protected: "SYNTHETIC_ENVELOPE_TWO",
        };
        const promptData = {
          workflow: { nodes: [] },
          output: {
            "41": { inputs: { stable: "SYNTHETIC_FIRST_UNCHANGED" } },
            "42": { inputs: { stable: "SYNTHETIC_SECOND_UNCHANGED" } },
          },
        };
        const graph = {
          _nodes: [firstOwner, secondOwner],
          serialize() { return { nodes: [] }; },
        };
        const app = {
          graph,
          async graphToPrompt() { return promptData; },
          async queuePrompt() {
            return app.api.queuePrompt(0, await app.graphToPrompt());
          },
          registerExtension() {},
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const baseFetch = globalThis.fetch;
        let prepareCount = 0;
        let releaseSecond;
        let secondEntered;
        const blocked = new Promise((resolve) => { releaseSecond = resolve; });
        const entered = new Promise((resolve) => { secondEntered = resolve; });
        globalThis.fetch = async (...args) => {
          if (String(args[0]).endsWith("/executions/render/prepare")) {
            prepareCount += 1;
            if (prepareCount === 2) {
              secondEntered();
              await blocked;
            }
          }
          return baseFetch(...args);
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const queued = app.queuePrompt();
        await entered;
        pack.workflow("timeline").markEdited(secondOwner, "timeline-state");
        releaseSecond();
        await assert.rejects(
          queued,
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );
        assert.equal(prepareCount, 2);
        assert.deepEqual(promptData.output["41"].inputs, {
          stable: "SYNTHETIC_FIRST_UNCHANGED",
        });
        assert.deepEqual(promptData.output["42"].inputs, {
          stable: "SYNTHETIC_SECOND_UNCHANGED",
        });
        assert.equal("private_execution" in promptData.output["41"].inputs, false);
        assert.equal("private_execution" in promptData.output["42"].inputs, false);
        """,
    )


def test_subject_mode_references_are_injected_only_into_execution_output(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = { id: 61, type: "AIOImageGenerate", declared: "private" };
        const graph = {
          _nodes: [owner],
          serialize() { return { nodes: [{ id: 61, inputs: {} }] }; },
        };
        const rawOutput = { "61": { inputs: {
          private_execution: JSON.stringify({
            schema: "helto.private-execution-reference", grant: "stale-execution",
          }),
          privacy_mode_reference: JSON.stringify({
            schema: "helto.subject-mode-reference", grant: "stale-subject",
          }),
        } } };
        const app = {
          graph,
          async graphToPrompt() {
            return { workflow: graph.serialize(), output: rawOutput };
          },
          async queuePrompt() {
            return app.api.queuePrompt(0, await app.graphToPrompt());
          },
          registerExtension() {},
        };
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [
            {
              id: "mode-editor",
              nodeTypes: ["AIOImageGenerate"],
              methods: [
                "onPrivacySessionChange", "readDeclaredMode", "reconcileNode",
                "reconcileNodeDefinition", "writeDeclaredMode",
              ],
            },
            attestation().requiredBrowserAdapters[0],
          ],
          modeScopes: [{
            id: "global", modeResourceId: "privacy-mode", modeEditorAdapter: "mode-editor",
          }],
          protectedFields: [{
            ...attestation().protectedFields[0],
            nodeTypes: ["AIOImageGenerate"],
          }],
          subjectModeBindings: [{
            id: "timeline-render-mode",
            scopeId: "global",
            inputName: "privacy_mode_reference",
            nodeTypes: ["AIOImageGenerate"],
          }],
        });
        const mode = {
          readDeclaredMode(node) { return node.declared; },
          writeDeclaredMode() {}, onPrivacySessionChange() {},
          reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const workflow = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "mode-editor": mode, "timeline-editor": workflow },
        });
        const preview = await app.graphToPrompt();
        assert.deepEqual(preview.output["61"].inputs, {});
        assert.equal("private_execution" in rawOutput["61"].inputs, true);
        assert.equal("privacy_mode_reference" in rawOutput["61"].inputs, true);
        rawOutput["61"].inputs.moved = JSON.stringify({
          schema: "helto.private-execution-reference", grant: "moved-execution",
        });
        await assert.rejects(
          app.graphToPrompt(),
          (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
        );
        delete rawOutput["61"].inputs.moved;
        await app.queuePrompt();
        const privatePrompt = {
          output: promptBodies.at(-1).prompt,
          workflow: promptBodies.at(-1).extra_data.extra_pnginfo.workflow,
        };
        assert.equal(subjectModeCalls[0].subjectId, "61");
        assert.equal(subjectModeCalls[0].declaration, "private");
        assert.equal(
          JSON.parse(privatePrompt.output["61"].inputs.privacy_mode_reference).schema,
          "helto.subject-mode-reference",
        );
        assert.equal(
          JSON.parse(privatePrompt.output["61"].inputs.private_execution).schema,
          "helto.private-execution-reference",
        );
        assert.equal(
          "privacy_mode_reference" in privatePrompt.workflow.nodes[0].inputs,
          false,
        );
        owner.declared = "public";
        await app.queuePrompt();
        const publicPrompt = { output: promptBodies.at(-1).prompt };
        assert.equal(subjectModeCalls[1].declaration, "public");
        assert.equal(
          JSON.parse(publicPrompt.output["61"].inputs.privacy_mode_reference).grant,
          "opaque-subject-grant-2",
        );
        subjectModeSubject = "malformed-subject-hash";
        await assert.rejects(
          app.queuePrompt(),
          (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
        );
        """,
    )


def test_api_submission_projects_cached_legacy_without_mutating_sources(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 71,
          type: "HeltoTimeline",
          live: {},
          protected: "LEGACY_NETWORK_CANARY",
          writes: [],
        };
        const graph = { _nodes: [owner], serialize() { return { nodes: [] }; } };
        const app = { graph, registerExtension() {} };
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [{
            ...attestation().requiredBrowserAdapters[0],
            methods: [
              ...attestation().requiredBrowserAdapters[0].methods,
              "writeWorkflowProjection",
            ],
          }, attestation().requiredBrowserAdapters[1]],
          protectedFields: [{
            ...attestation().protectedFields[0],
            legacyReaderIds: ["timeline-v0"],
          }],
        });
        const baseFetch = globalThis.fetch;
        globalThis.fetch = async (url, options = {}) => {
          if (String(url).endsWith("/disposition")) return {
            ok: true,
            status: 200,
            async json() { return {
              ok: true,
              disposition: "readable-legacy",
              replacementEnvelope: "CURRENT_NETWORK_ENVELOPE",
              migrationObligationId: "hp-obligation-network",
            }; },
            async text() { return JSON.stringify({
              ok: true,
              disposition: "readable-legacy",
              replacementEnvelope: "CURRENT_NETWORK_ENVELOPE",
              migrationObligationId: "hp-obligation-network",
            }); },
          };
          return baseFetch(url, options);
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; node.writes.push(value); },
          writeWorkflowProjection(_owner, serializedNode, value) {
            serializedNode.protected = value;
          },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: {
            "mode-editor": defaultModeAdapter,
            "timeline-editor": adapter,
          },
        });
        const cached = {
          workflow: { nodes: [{
            id: 71,
            type: "HeltoTimeline",
            protected: "LEGACY_NETWORK_CANARY",
          }] },
          output: { "71": { inputs: {
            private_execution: JSON.stringify({
              schema: "helto.private-execution-reference",
              version: 1,
              grant: "STALE_PREEXISTING_GRANT",
            }),
          } } },
        };
        await app.api.queuePrompt(0, cached);
        const sent = promptBodies.at(-1);
        assert.equal(
          sent.extra_data.extra_pnginfo.workflow.nodes[0].protected,
          "CURRENT_NETWORK_ENVELOPE",
        );
        assert(!JSON.stringify(sent).includes("LEGACY_NETWORK_CANARY"));
        assert.equal(cached.workflow.nodes[0].protected, "LEGACY_NETWORK_CANARY");
        assert.equal(owner.protected, "LEGACY_NETWORK_CANARY");
        assert.deepEqual(owner.writes, []);
        assert.equal(
          JSON.parse(sent.prompt["71"].inputs.private_execution).schema,
          "helto.private-execution-reference",
        );
        """,
    )


def test_api_prompt_transport_permit_rejects_bypass_replay_mismatch_and_staleness(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let releaseFetch;
        let fetchEntered;
        let releaseAuthorization;
        let authorizationEntered;
        let forwardedSignal;
        let authorizedNetworkCalls = 0;
        let headerGetterCalls = 0;
        let releaseFireFetch;
        let fireFetchEntered;
        let releaseFireCore;
        const retainedHeaderValues = [];
        class AttackApi extends HeltoPrivacyTestComfyApi {
          mode = "normal";

          body(number, data) {
            return {
              client_id: this.clientId ?? "",
              prompt: data.output,
              extra_data: { extra_pnginfo: { workflow: data.workflow } },
              ...(number === -1 ? { front: true } : {}),
            };
          }

          async fetchApi(route, options = {}) {
            if (route === "/prompt" && this.mode.startsWith("retained-")) {
              retainedHeaderValues.push(options.headers.get("content-type"));
            }
            if (route === "/prompt" && this.mode === "auth-wait") {
              forwardedSignal = options.signal;
              authorizationEntered();
              await new Promise((resolve) => { releaseAuthorization = resolve; });
              if (options.signal?.aborted) {
                throw new DOMException("aborted", "AbortError");
              }
              authorizedNetworkCalls += 1;
            }
            if (route === "/prompt" && this.mode.startsWith("fire-")) {
              forwardedSignal = options.signal;
              fireFetchEntered();
              await new Promise((resolve) => { releaseFireFetch = resolve; });
              if (this.mode.endsWith("failure")) {
                throw new Error("SYNTHETIC_LATE_FETCH_FAILURE");
              }
              if (options.signal?.aborted) {
                throw new DOMException("aborted", "AbortError");
              }
              authorizedNetworkCalls += 1;
            }
            return super.fetchApi(route, options);
          }

          async queuePrompt(number, data, options = undefined) {
            const request = () => this.fetchApi("/prompt", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(this.body(number, data)),
            });
            if (this.mode === "no-submit") return { skipped: true };
            if (this.mode === "fail") throw new Error("SYNTHETIC_ORIGINAL_FAILURE");
            if (this.mode === "nested") return this.queuePrompt(number, data, options);
            if (this.mode === "delayed-nested") {
              await Promise.resolve();
              return this.queuePrompt(number, data, options);
            }
            if (this.mode === "swap") {
              const body = this.body(number, data);
              body.prompt = { swapped: true };
              return this.fetchApi("/prompt", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
              });
            }
            if (this.mode === "extra-body-key" || this.mode === "proto-body-key") {
              const body = this.body(number, data);
              if (this.mode === "extra-body-key") body.unexpected = true;
              else Object.defineProperty(body, "__proto__", {
                enumerable: true,
                value: { hidden: "must-bind" },
              });
              return this.fetchApi("/prompt", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
              });
            }
            if (this.mode === "wrong-content-type" || this.mode === "extra-init-key") {
              return this.fetchApi("/prompt", {
                method: "POST",
                headers: {
                  "Content-Type": this.mode === "wrong-content-type"
                    ? "text/plain"
                    : "application/json",
                },
                body: JSON.stringify(this.body(number, data)),
                ...(this.mode === "extra-init-key" ? { cache: "no-store" } : {}),
              });
            }
            if (this.mode === "header-getter") {
              const headers = {};
              Object.defineProperty(headers, "Content-Type", {
                enumerable: true,
                get() {
                  headerGetterCalls += 1;
                  return "application/json";
                },
              });
              return this.fetchApi("/prompt", {
                method: "POST", headers, body: JSON.stringify(this.body(number, data)),
              });
            }
            if (this.mode === "retained-plain" || this.mode === "retained-headers") {
              const headers = this.mode === "retained-headers"
                ? new Headers({ "Content-Type": "application/json" })
                : { "Content-Type": "application/json" };
              const pending = this.fetchApi("/prompt", {
                method: "POST", headers, body: JSON.stringify(this.body(number, data)),
              });
              if (headers instanceof Headers) headers.set("Content-Type", "text/plain");
              else headers["Content-Type"] = "text/plain";
              return await pending;
            }
            if (this.mode.startsWith("fire-")) {
              this.fetchApi("/prompt", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(this.body(number, data)),
              }).catch(() => {});
              if (this.mode.startsWith("fire-late-")) {
                await new Promise((resolve) => { releaseFireCore = resolve; });
              }
              return { returnedEarly: true };
            }
            if (this.mode === "parallel") {
              return Promise.all([request(), request()]);
            }
            if (this.mode === "hold") {
              fetchEntered();
              await new Promise((resolve) => { releaseFetch = resolve; });
              return { held: true };
            }
            if (this.mode === "wait") {
              fetchEntered();
              await new Promise((resolve) => { releaseFetch = resolve; });
            }
            const response = await request();
            return response.json();
          }
        }
        const owner = {
          id: 72, type: "HeltoTimeline", live: {}, protected: "CURRENT_SOURCE",
        };
        const graph = { _nodes: [owner], serialize() { return { nodes: [] }; } };
        const api = new AttackApi();
        const app = { api, graph, registerExtension() {} };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const promptData = {
          workflow: { nodes: [] },
          output: { "72": { inputs: {} } },
        };
        const promptCount = () => promptBodies.length;
        const directBody = JSON.stringify({
          client_id: "",
          prompt: promptData.output,
          extra_data: { extra_pnginfo: { workflow: promptData.workflow } },
        });

        let routeCanaryCalls = 0;
        const mutableRoute = {
          toString() { routeCanaryCalls += 1; return "/prompt"; },
          get startsWith() { routeCanaryCalls += 1; return () => true; },
        };
        await assert.rejects(
          api.fetchApi(mutableRoute, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: directBody,
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
        );
        assert.equal(routeCanaryCalls, 0);

        let rejectedRouteNetworkCalls = 0;
        const routeTestFetch = globalThis.fetch;
        globalThis.fetch = async (...args) => {
          rejectedRouteNetworkCalls += 1;
          return routeTestFetch(...args);
        };
        await assert.rejects(
          api.fetchApi("/prompt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: directBody,
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
        );
        for (const route of [
          "/%70rompt",
          "/%2570rompt",
          "/prompt?client=1",
          "/prompt#fragment",
          "/api/prompt",
          "/api%2Fprompt",
          "/safe/%2e%2e/prompt",
          "http://helto-privacy.invalid/prompt",
          "https://other.invalid/prompt",
        ]) {
          await assert.rejects(
            api.fetchApi(route, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: directBody,
            }),
            (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
          );
        }
        assert.equal(rejectedRouteNetworkCalls, 0);
        globalThis.fetch = routeTestFetch;
        assert.equal(promptCount(), 0);
        const nonPrompt = await api.fetchApi("/status");
        assert.equal(nonPrompt.ok, true);

        api.mode = "normal";
        await api.queuePrompt(0, promptData);
        assert.equal(promptCount(), 1);
        const movedReference = {
          workflow: { nodes: [] },
          output: { "72": { inputs: {
            moved: JSON.stringify({
              schema: "helto.private-execution-reference",
              version: 1,
              grant: "MOVED_STALE_GRANT",
            }),
          } } },
        };
        await assert.rejects(
          api.queuePrompt(0, movedReference),
          (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
        );
        const oversizedReference = {
          workflow: { nodes: [] },
          output: { "72": { inputs: {
            moved: JSON.stringify({
              schema: "helto.private-execution-reference",
              grant: "OVERSIZED_STALE_GRANT",
              padding: "x".repeat(1024 * 1024),
            }),
          } } },
        };
        await assert.rejects(
          api.queuePrompt(0, oversizedReference),
          (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
        );
        assert.equal(promptCount(), 1);
        await assert.rejects(
          api.fetchApi("/prompt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: directBody,
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
        );
        assert.equal(promptCount(), 1);

        const failedModes = [
          "swap", "extra-body-key", "proto-body-key", "parallel",
          "wrong-content-type", "extra-init-key", "header-getter",
          "nested", "delayed-nested", "fail",
        ];
        const revokesBeforeFailures = revokedSubmissionGrants.length;
        for (const mode of failedModes) {
          api.mode = mode;
          await assert.rejects(Promise.race([
            api.queuePrompt(0, promptData),
            new Promise((_, reject) => setTimeout(
              () => reject(new Error("SYNTHETIC_SUBMISSION_DEADLOCK")),
              100,
            )),
          ]));
          assert.equal(promptCount(), 1);
        }
        api.mode = "no-submit";
        assert.deepEqual(await api.queuePrompt(0, promptData), { skipped: true });
        await assert.rejects(
          api.fetchApi("/prompt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: directBody,
          }),
          (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
        );
        assert.equal(promptCount(), 1);
        assert.equal(
          revokedSubmissionGrants.length - revokesBeforeFailures,
          failedModes.length + 1,
        );
        assert.equal(headerGetterCalls, 0);

        const holdEntered = new Promise((resolve) => { fetchEntered = resolve; });
        api.mode = "hold";
        const held = api.queuePrompt(0, promptData);
        await holdEntered;
        await assert.rejects(Promise.race([
          api.queuePrompt(0, promptData),
          new Promise((_, reject) => setTimeout(
            () => reject(new Error("SYNTHETIC_CONCURRENT_SUBMISSION_WAITED")),
            100,
          )),
        ]), (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID");
        releaseFetch();
        assert.deepEqual(await held, { held: true });
        assert.equal(promptCount(), 1);

        const authEntered = new Promise((resolve) => { authorizationEntered = resolve; });
        api.mode = "auth-wait";
        const authStale = api.queuePrompt(0, promptData);
        await authEntered;
        assert.equal(typeof forwardedSignal?.aborted, "boolean");
        owner.live = { value: "edited-during-auth" };
        pack.workflow("timeline").markEdited(owner, "timeline-state");
        assert.equal(forwardedSignal.aborted, true);
        releaseAuthorization();
        await assert.rejects(authStale, (error) => error.name === "AbortError");
        assert.equal(authorizedNetworkCalls, 0);
        assert.equal(promptCount(), 1);

        for (const mode of ["retained-plain", "retained-headers"]) {
          api.mode = mode;
          await api.queuePrompt(0, promptData);
        }
        assert.equal(promptCount(), 3);
        assert.deepEqual(retainedHeaderValues, ["application/json", "application/json"]);

        const revokesBeforeFireAndForget = revokedSubmissionGrants.length;
        api.mode = "fire-success";
        await assert.rejects(api.queuePrompt(0, promptData));
        for (const mode of ["fire-late-success", "fire-late-failure"]) {
          const entered = new Promise((resolve) => { fireFetchEntered = resolve; });
          api.mode = mode;
          const early = api.queuePrompt(0, promptData);
          await entered;
          releaseFireCore();
          await Promise.resolve();
          releaseFireFetch();
          await assert.rejects(early);
        }
        assert.equal(authorizedNetworkCalls, 0);
        assert.equal(promptCount(), 3);
        assert.equal(
          revokedSubmissionGrants.length - revokesBeforeFireAndForget,
          3,
        );
        assert.equal(revokedSubmissionGrants.length > 0, true);

        const waitEntered = new Promise((resolve) => { fetchEntered = resolve; });
        api.mode = "wait";
        const stale = api.queuePrompt(0, promptData);
        await waitEntered;
        owner.live = { value: "edited-between-preparation-and-fetch" };
        pack.workflow("timeline").markEdited(owner, "timeline-state");
        releaseFetch();
        await assert.rejects(
          stale,
          (error) => error.code === "PRIVACY_SNAPSHOT_TRANSACTION_STALE",
        );
        assert.equal(promptCount(), 3);

        const sessionWaitEntered = new Promise(
          (resolve) => { authorizationEntered = resolve; },
        );
        api.mode = "auth-wait";
        const sessionStale = api.queuePrompt(0, promptData);
        await sessionWaitEntered;
        const sessionSignal = forwardedSignal;
        globalThis.localStorage = {
          getItem: () => "",
          setItem() {},
          removeItem() {},
        };
        const shared = await import(new URL("./privacy.js", import.meta.url));
        await shared.unlockPrivacyKeystore("rotated synthetic password");
        assert.equal(sessionSignal.aborted, true);
        releaseAuthorization();
        await assert.rejects(
          sessionStale,
          (error) => error.name === "AbortError",
        );
        assert.equal(authorizedNetworkCalls, 0);
        assert.equal(promptCount(), 3);
        """,
    )


def test_submission_gate_rejects_preexisting_and_late_core_replacements(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        let coreCalls = 0;
        class CoreApp {
          constructor() {
            this.api = new HeltoPrivacyTestComfyApi();
            this.graph = { _nodes: [], serialize() { return { nodes: [] }; } };
          }
          async graphToPrompt() {
            coreCalls += 1;
            return { workflow: { nodes: [] }, output: {} };
          }
          async queuePrompt() { coreCalls += 1; return true; }
          registerExtension() {}
        }
        const apiAccessor = new CoreApp();
        delete apiAccessor.api;
        let apiAccessorCalls = 0;
        Object.defineProperty(apiAccessor, "api", {
          configurable: true,
          get() {
            apiAccessorCalls += 1;
            return new HeltoPrivacyTestComfyApi();
          },
        });
        let apiAccessorNetworkCalls = 0;
        const apiAccessorFetch = globalThis.fetch;
        globalThis.fetch = async (...args) => {
          apiAccessorNetworkCalls += 1;
          return apiAccessorFetch(...args);
        };
        await assert.rejects(
          privacyRaw.connectPrivacyPack({
            app: apiAccessor,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: {},
          }),
          (error) => error.code === "browser_serialization_gate_failed",
        );
        assert.equal(apiAccessorCalls, 0);
        assert.equal(apiAccessorNetworkCalls, 0);
        globalThis.fetch = apiAccessorFetch;

        let opaqueRan = false;
        const opaque = new CoreApp();
        opaque.queuePrompt = async () => { opaqueRan = true; };
        await assert.rejects(
          privacyRaw.connectPrivacyPack({
            app: opaque,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: {},
          }),
          (error) => error.code === "browser_serialization_gate_failed",
        );
        assert.equal(opaqueRan, false);

        let accessorRan = false;
        const opaqueAccessor = new CoreApp();
        Object.defineProperty(opaqueAccessor, "queuePrompt", {
          configurable: true,
          get() {
            accessorRan = true;
            return CoreApp.prototype.queuePrompt;
          },
        });
        await assert.rejects(
          privacyRaw.connectPrivacyPack({
            app: opaqueAccessor,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapters: {},
          }),
          (error) => error.code === "browser_serialization_gate_failed",
        );
        assert.equal(accessorRan, false);

        const app = new CoreApp();
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "CURRENT"; }, writeProtected() {},
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pack = await privacyRaw.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: {
            "mode-editor": defaultModeAdapter,
            "timeline-editor": adapter,
          },
        });
        const apiDescriptor = Object.getOwnPropertyDescriptor(app, "api");
        assert.equal(apiDescriptor.configurable, false);
        assert.equal(apiDescriptor.get(), app.api);
        const coreCallsBeforeReceiverAttacks = coreCalls;
        await assert.rejects(app.graphToPrompt.call({}));
        await assert.rejects(app.queuePrompt.call({}));
        await assert.rejects(app.api.queuePrompt.call({}, 0, {
          workflow: { nodes: [] }, output: {},
        }));
        await assert.rejects(app.api.fetchApi.call({}, "/status"));
        assert.equal(coreCalls, coreCallsBeforeReceiverAttacks);
        const attempts = [
          () => { app.api = new HeltoPrivacyTestComfyApi(); },
          () => { app.queuePrompt = async () => { opaqueRan = true; }; },
          () => { app.graphToPrompt = async () => { opaqueRan = true; }; },
          () => { app.api.queuePrompt = async () => { opaqueRan = true; }; },
          () => { app.api.fetchApi = async () => { opaqueRan = true; }; },
        ];
        for (const attempt of attempts) {
          assert.throws(
            attempt,
            (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
          );
        }
        assert.equal(pack.readiness.state, "conflict");
        assert.equal(opaqueRan, false);
        await assert.rejects(
          app.api.queuePrompt(0, { workflow: { nodes: [] }, output: {} }),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_reference_probe_keeps_ordinary_prompt_text_opaque(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const app = {
          graph: { _nodes: [], serialize() { return { nodes: [] }; } },
          registerExtension() {},
        };
        await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": {
            apply() {}, clear() {}, normalize() { return {}; },
            readProtected() { return "CURRENT"; }, writeProtected() {},
            onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
          } },
        });
        const ordinary = {
          workflow: { nodes: [] },
          output: { "1": { inputs: {
            brace: "{ordinary prompt text",
            bracket: "[ordinary prompt text",
            largeJson: JSON.stringify({ padding: "x".repeat(1024 * 1024 + 16) }),
            markerAsProductText: JSON.stringify({
              text: "helto.private-execution-reference",
            }),
          } } },
        };
        await app.api.queuePrompt(0, ordinary);
        assert.equal(promptBodies.length, 1);
        const unicodeEscape = (value) => [...value].map(
          (character) => "\\\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"),
        ).join("");
        const executionMarker = "helto.private-execution-reference";
        const subjectMarker = "helto.subject-mode-reference";
        const escapedSchema = unicodeEscape("schema");
        const escapedExecution = unicodeEscape(executionMarker);
        const mixedSubject = "helto.subject-mode-" + unicodeEscape("reference");
        for (const attack of [
          "prefix helto.private-execution-reference trailing junk",
          JSON.stringify({
            schema: "helto.subject-mode-reference",
            grant: "oversized",
            padding: "x".repeat(1024 * 1024),
          }),
          `{"schema":"${escapedExecution}","grant":"escaped-execution"}`,
          `{"${escapedSchema}":"${subjectMarker}","grant":"escaped-key"}`,
          `{"schema":"${mixedSubject}","grant":"mixed-marker"}`,
          `{"schema":"${escapedExecution}","grant":"trailing"} trailing`,
          `{"padding":"${"x".repeat(1024 * 1024)}",`
            + `"schema":"${escapedExecution}","grant":"oversized-escaped"}`,
        ]) {
          await assert.rejects(
            app.api.queuePrompt(0, {
              workflow: { nodes: [] },
              output: { "1": { inputs: { disguised: attack } } },
            }),
            (error) => error.code === "PRIVACY_SNAPSHOT_EXECUTION_BLOCKED",
          );
        }
        assert.equal(promptBodies.length, 1);
        """,
    )


def test_prompt_permit_binds_complete_installed_comfy_body(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const api = new HeltoPrivacyTestComfyApi();
        api.clientId = "client-7";
        api.authToken = "auth-token";
        api.apiKey = "api-key";
        const app = {
          api,
          graph: { _nodes: [], serialize() { return { nodes: [] }; } },
          registerExtension() {},
        };
        await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": {
            apply() {}, clear() {}, normalize() { return {}; },
            readProtected() { return "CURRENT"; }, writeProtected() {},
            onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
          } },
        });
        const options = {
          partialExecutionTargets: ["node-1"],
          previewMethod: "taesd",
        };
        await api.queuePrompt(-1, {
          output: { "1": { inputs: { seed: 7 } } },
          workflow: { nodes: [{ id: 1 }] },
        }, options);
        assert.deepEqual(promptBodies.at(-1), {
          client_id: "client-7",
          prompt: { "1": { inputs: { seed: 7 } } },
          partial_execution_targets: ["node-1"],
          extra_data: {
            auth_token_comfy_org: "auth-token",
            api_key_comfy_org: "api-key",
            extra_pnginfo: { workflow: { nodes: [{ id: 1 }] } },
            preview_method: "taesd",
          },
          front: true,
        });
        assert.deepEqual(options, {
          partialExecutionTargets: ["node-1"],
          previewMethod: "taesd",
        });
        """,
    )


def test_app_batch_iterations_get_independent_api_snapshots_and_references(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const owner = {
          id: 81, type: "HeltoTimeline", live: {}, protected: "CURRENT_INITIAL",
        };
        const graph = {
          _nodes: [owner],
          serialize() { return { nodes: [{ id: 81, type: "HeltoTimeline" }] }; },
        };
        let workflowHandle;
        const app = {
          graph,
          async graphToPrompt() {
            return { workflow: graph.serialize(), output: { "81": { inputs: {} } } };
          },
          async queuePrompt(number, batchCount = 1) {
            const results = [];
            for (let index = 0; index < batchCount; index += 1) {
              owner.live = { iteration: index + 1 };
              workflowHandle.markEdited(owner, "timeline-state");
              results.push(await this.api.queuePrompt(
                number,
                await this.graphToPrompt(),
              ));
            }
            return results;
          },
          registerExtension() {},
        };
        let protectCount = 0;
        let grantCount = 0;
        const baseFetch = globalThis.fetch;
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/protect")) {
            protectCount += 1;
            const payload = { ok: true, envelope: `CURRENT_BATCH_${protectCount}` };
            return {
              ok: true, status: 200,
              async text() { return JSON.stringify(payload); },
              async json() { return payload; },
            };
          }
          if (target.endsWith("/executions/render/prepare")) {
            grantCount += 1;
            const payload = { ok: true, reference: {
              schema: "helto.private-execution-reference",
              version: 2,
              subject: "a".repeat(64),
              grant: `BATCH_GRANT_${grantCount}`,
            } };
            executionBodies.push(JSON.parse(options.body));
            return {
              ok: true, status: 200,
              async text() { return JSON.stringify(payload); },
              async json() { return payload; },
            };
          }
          return baseFetch(url, options);
        };
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        workflowHandle = pack.workflow("timeline");
        const results = await app.queuePrompt(0, 2);
        assert.equal(results.length, 2);
        assert.equal(promptBodies.length, 2);
        const references = promptBodies.map(
          (body) => JSON.parse(body.prompt["81"].inputs.private_execution),
        );
        assert.deepEqual(references.map((item) => item.grant), [
          "BATCH_GRANT_1",
          "BATCH_GRANT_2",
        ]);
        assert.deepEqual(executionBodies.map((body) => (
          body.fields[0].protectedValue
        )), ["CURRENT_BATCH_1", "CURRENT_BATCH_2"]);
        """,
    )


def test_adapter_factories_receive_bound_typed_handles_before_reconciliation(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [
            {
              id: "mode-editor",
              nodeTypes: ["HeltoTimeline"],
              methods: [
                "onPrivacySessionChange", "readDeclaredMode", "reconcileNode",
                "reconcileNodeDefinition", "writeDeclaredMode",
              ],
            },
            attestation().requiredBrowserAdapters[0],
          ],
          modeScopes: [{
            id: "global",
            modeResourceId: "privacy-mode",
            modeEditorAdapter: "mode-editor",
          }],
        });
        const events = [];
        const owner = {
          id: 7, type: "HeltoTimeline", live: {}, protected: "SYNTHETIC_ENVELOPE",
        };
        const app = {
          graph: { _nodes: [owner], serialize() { return { nodes: [] }; } },
          registeredNodeTypes: {}, registerExtension() {},
        };
        const checkContext = (context, HandleType, adapterId) => {
          events.push(`factory:${adapterId}`);
          assert(Object.isFrozen(context));
          assert(Object.isFrozen(context.requirement));
          assert(context.handle instanceof HandleType);
          assert.equal(context.handle.packId, "helto.director");
          assert.deepEqual(Object.keys(context).sort(), ["handle", "requirement"]);
          assert.equal("transport" in context, false);
          assert.equal("token" in context, false);
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapterFactories: {
            "mode-editor": (context) => {
              checkContext(context, privacy.BrowserModeHandle, "mode-editor");
              return {
                readDeclaredMode() { return "private"; }, writeDeclaredMode() {},
                onPrivacySessionChange() {},
                reconcileNode() { events.push("reconcile:mode"); },
                reconcileNodeDefinition() {},
              };
            },
            "timeline-editor": (context) => {
              checkContext(context, privacy.BrowserWorkflowHandle, "timeline-editor");
              return {
                apply() {}, clear() {}, normalize(node) { return node.live; },
                readProtected(node) { return node.protected; },
                writeProtected(node, value) { node.protected = value; },
                onPrivacySessionChange() {},
                reconcileNode() { events.push("reconcile:workflow"); },
                reconcileNodeDefinition() {},
              };
            },
          },
        });
        assert.equal(pack.readiness.state, "ready");
        assert.deepEqual(events.slice(0, 2), ["factory:mode-editor", "factory:timeline-editor"]);
        assert.deepEqual(events.slice(2), ["reconcile:mode", "reconcile:workflow"]);
        """,
    )


def test_incomplete_adapter_factory_fails_closed(tmp_path):
    run_node_module_test(
        tmp_path,
        """
        const graph = { serialize() { return { nodes: [] }; } };
        const app = { graph, registerExtension() {} };
        await assert.rejects(
          privacy.connectPrivacyPack({
            app,
            packId: "helto.director",
            profileFingerprint: fingerprint,
            suiteManifestDigest: suiteDigest,
            adapterFactories: {
              "timeline-editor": ({ handle }) => ({ handle, normalize() {} }),
            },
          }),
          (error) => error.code === "browser_adapter_mismatch",
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "PRIVACY_PROFILE_UNAVAILABLE",
        );
        """,
    )


def test_external_browser_mode_transition_rewrites_exact_owners_and_keeps_capability_product_free(
    tmp_path,
):
    run_node_module_test(
        tmp_path,
        """
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        const bootEpoch = `hp-boot-${"c".repeat(32)}`;
        const transitionId = "1".repeat(32);
        const lease = `hp-mode-client-${"l".repeat(43)}`;
        const originalExact = encoder.encode("private:SYNTHETIC_EXACT_CANARY");
        const targetExact = encoder.encode("public:SYNTHETIC_EXACT_CANARY");
        const privateTargetExact = encoder.encode("private:SYNTHETIC_EXACT_CANARY");
        const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
        const sessionValues = new Map();
        const sessionWrites = [];
        const localValues = new Map();
        globalThis.localStorage = {
          getItem(key) { return localValues.has(key) ? localValues.get(key) : null; },
          setItem(key, value) { localValues.set(String(key), String(value)); },
          removeItem(key) { localValues.delete(String(key)); },
        };
        globalThis.sessionStorage = {
          getItem(key) { return sessionValues.has(key) ? sessionValues.get(key) : null; },
          setItem(key, value) {
            sessionValues.set(String(key), String(value));
            sessionWrites.push(String(value));
          },
          removeItem(key) { sessionValues.delete(String(key)); },
        };
        globalThis.confirm = () => true;

        const externalMethods = [
          ...attestation().requiredBrowserAdapters[0].methods,
          "settleModeTransition",
          "inventoryModeTransitionOwners",
          "readModeTransitionOwnerExact",
          "applyModeTransitionOwnerExact",
          "extractDetachedModeTransitionOwnerExact",
          "restoreModeTransitionOwnerExact",
          "reloadModeTransitionRuntime",
          "reconcileModeTransitionRuntime",
        ].sort();
        serverAttestation = () => attestation({
          serverBootEpoch: bootEpoch,
          requiredBrowserAdapters: [{
            ...attestation().requiredBrowserAdapters[0],
            methods: externalMethods,
          }, attestation().requiredBrowserAdapters[1]],
          protectedFields: [{
            ...attestation().protectedFields[0],
            stateAuthority: "external-browser-workflow",
            externalTransitionPolicy: {
              ownerIdentity: "graph-node-field-v1",
              maxOwners: 4,
              maxOriginalBytesPerOwner: 1024,
              maxTargetBytesPerOwner: 1024,
              maxTotalBytes: 4096,
              leaseSeconds: 60,
            },
          }],
        });

        const owner = {
          id: 12,
          type: "HeltoTimeline",
          live: { value: "initial" },
          protected: "SYNTHETIC_ENVELOPE",
          exact: originalExact,
        };
        const calls = [];
        let failNextExternalApply = false;
        let failNextReconcile = false;
        let failNextRelease = false;
        let rejectSettlement = false;
        let invalidInventory = false;
        let frozen = false;
        const adapter = {
          apply() {}, clear() {}, normalize(node) { return node.live; },
          readProtected(node) { return node.protected; },
          writeProtected(node, value) { node.protected = value; },
          onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
          settleModeTransition() {
            calls.push("settle");
            assert.equal(frozen, false);
            frozen = true;
            return {
              settled: rejectSettlement
                ? Promise.reject(new Error("synthetic settlement failure"))
                : Promise.resolve({ offlineRepresentationCount: 0 }),
              async release() {
                calls.push("release");
                frozen = false;
                if (failNextRelease) {
                  failNextRelease = false;
                  throw new Error("synthetic release failure");
                }
              },
            };
          },
          async inventoryModeTransitionOwners() {
            assert.equal(frozen, true);
            calls.push("inventory");
            if (invalidInventory) {
              return Array.from({ length: 5 }, (_value, index) => ({
                owner, rootGraphId: "root", graphId: "root", nodeId: String(20 + index),
              }));
            }
            return [{ owner, rootGraphId: "root", graphId: "root", nodeId: "12" }];
          },
          async readModeTransitionOwnerExact(value) { return value.exact; },
          async applyModeTransitionOwnerExact(value, exact) {
            assert.equal(frozen, true);
            calls.push("apply");
            if (failNextExternalApply) {
              failNextExternalApply = false;
              throw new Error("synthetic external apply failure");
            }
            value.exact = new Uint8Array(exact);
          },
          async extractDetachedModeTransitionOwnerExact(_value, serialized) {
            assert.equal(frozen, true);
            calls.push("detached");
            return new Uint8Array(serialized.nodes[0].exact);
          },
          async restoreModeTransitionOwnerExact(value, exact) {
            assert.equal(frozen, true);
            calls.push("restore");
            value.exact = new Uint8Array(exact);
          },
          async reloadModeTransitionRuntime() { calls.push("reload"); },
          async reconcileModeTransitionRuntime() {
            calls.push("reconcile");
            if (failNextReconcile) {
              failNextReconcile = false;
              throw new Error("synthetic reconcile failure");
            }
          },
        };
        const graph = {
          _nodes: [owner],
          serialize() { return { nodes: [{ id: 12, exact: [...owner.exact] }] }; },
        };
        const app = {
          rootGraph: graph,
          registeredNodeTypes: {},
          registerExtension(extension) { this.extension = extension; },
          async queuePrompt(...args) { return this.api.queuePrompt(...args); },
        };

        let currentEpoch = 0;
        let opaqueOwnerId = null;
        let desiredTarget = "public";
        let originalAtReserve = originalExact;
        let loseFinalizeResponse = true;
        let finalized = false;
        let loseRollbackCompletionResponse = true;
        let rollbackCompleted = false;
        let failPrepare = false;
        let failRollbackRequests = 0;
        let resumeRollback = false;
        const transportCalls = [];
        const originalFetch = globalThis.fetch;
        const response = (payload) => ({
          ok: true,
          status: 200,
          async json() { return payload; },
          async text() { return JSON.stringify(payload); },
        });
        const makeOwnerId = async (resumeSecret) => {
          const key = await crypto.subtle.importKey(
            "raw", encoder.encode(resumeSecret),
            { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
          );
          const message = [
            "graph-node-field-v1", "helto.director", fingerprint, "global",
            "root", "root", "12", "timeline-state",
          ].join("\\0");
          return `hp-owner-${b64(new Uint8Array(await crypto.subtle.sign(
            "HMAC", key, encoder.encode(message),
          )))}`;
        };
        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/modes")) {
            return response({ ok: true, serverBootEpoch: bootEpoch, scopes: [{
              id: "global", modeResourceId: "privacy-mode",
              declared: currentEpoch ? "public" : "private",
              effective: currentEpoch ? "public" : "private",
              inheritedFrom: currentEpoch ? "declared-public" : "declared-private",
              floors: [], transitionStatus: "idle", modeEpoch: currentEpoch,
            }] });
          }
          if (!target.includes("/transition")) return originalFetch(url, options);
          const body = options.body === undefined ? {} : JSON.parse(options.body);
          transportCalls.push({ target, body, headers: { ...options.headers } });
          const resumeSecret = options.headers["X-Helto-Privacy-Resume-Capability"];
          if (target.endsWith("/client-heartbeat")) {
            return response({ ok: true });
          }
          if (target.endsWith("/reserve")) {
            desiredTarget = body.target;
            originalAtReserve = new Uint8Array(owner.exact);
            opaqueOwnerId = null;
            rollbackCompleted = false;
            finalized = false;
            return response({
              ok: true, transitionId, requestId: body.requestId,
              clientLease: lease, clientLeaseEpoch: 1, modeEpoch: currentEpoch,
              targetModeEpoch: currentEpoch + 1,
              priorDeclared: currentEpoch ? "public" : "private",
            });
          }
          opaqueOwnerId ||= await makeOwnerId(resumeSecret);
          if (target.endsWith("/resume") && resumeRollback) {
            return response({
              ok: true, externalPhase: "rollback-restoring",
              clientLease: lease, clientLeaseEpoch: 2,
              pendingOwners: [{
                ownerId: opaqueOwnerId,
                fieldId: "timeline-state",
                exact: b64(originalAtReserve),
              }],
            });
          }
          if (target.endsWith("/rebase")) {
            return response({
              ok: true,
              scopeId: "global",
              fieldId: body.fieldId,
              exact: body.exact,
              modeEpoch: body.modeEpoch,
              serverBootEpoch: bootEpoch,
            });
          }
          if (target.endsWith("/prepare")) {
            if (failPrepare) {
              failPrepare = false;
              throw new Error("synthetic prepare failure");
            }
            return response({
              ok: true, externalPhase: "prepared",
              pendingOwners: [{
                ownerId: opaqueOwnerId,
                fieldId: "timeline-state",
                exact: b64(desiredTarget === "public" ? targetExact : privateTargetExact),
              }],
            });
          }
          if (target.endsWith("/apply-ack")) {
            return response({ ok: true, externalPhase: "applied", pendingOwners: [] });
          }
          if (target.endsWith("/verify")) {
            return response({ ok: true, externalPhase: "verified", pendingOwners: [] });
          }
          if (target.endsWith("/finalize")) {
            if (!finalized) {
              currentEpoch += 1;
              finalized = true;
            }
            if (loseFinalizeResponse) {
              loseFinalizeResponse = false;
              throw new Error("synthetic lost finalize response");
            }
            return response({
              ok: true, scopeId: "global", declared: "public", effective: "public",
              transitionStatus: "idle", modeEpoch: currentEpoch,
            });
          }
          if (target.endsWith("/rollback")) {
            if (failRollbackRequests > 0) {
              failRollbackRequests -= 1;
              throw new Error("synthetic rollback failure");
            }
            if (body.acknowledgements === null) {
              return response({
                ok: true, externalPhase: "rollback-restoring",
                pendingOwners: [{
                  ownerId: opaqueOwnerId,
                  fieldId: "timeline-state",
                  exact: b64(originalAtReserve),
                }],
              });
            }
            if (!rollbackCompleted) {
              rollbackCompleted = true;
              currentEpoch += 1;
            }
            if (loseRollbackCompletionResponse) {
              loseRollbackCompletionResponse = false;
              throw new Error("synthetic lost rollback response");
            }
            return response({
              ok: true, scopeId: "global", declared: "public", effective: "public",
              transitionStatus: "idle", modeEpoch: currentEpoch,
            });
          }
          assert.fail(`unexpected external route ${target}`);
        };

        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });
        const completed = await pack.mode("privacy-mode").transition("global", "public");

        assert.equal(completed.effective, "public");
        assert.equal(decoder.decode(owner.exact), "public:SYNTHETIC_EXACT_CANARY");
        assert.deepEqual(calls, [
          "settle", "inventory", "apply", "detached", "reload", "reconcile", "release",
        ]);
        assert.deepEqual(
          transportCalls.map((item) => item.target.split("/").at(-1)),
          [
            "client-heartbeat", "reserve", "prepare", "apply-ack", "verify",
            "finalize", "finalize",
          ],
        );
        for (const call of transportCalls) {
          assert.equal("resumeSecret" in call.body, false);
          assert.equal("serverBootEpoch" in call.body, false);
          assert.equal(call.headers["X-Helto-Privacy-Boot-Epoch"], bootEpoch);
          assert.match(call.headers["X-Helto-Privacy-Resume-Capability"], /^hp-mode-resume-/);
        }
        const prepareCall = transportCalls.find((item) => item.target.endsWith("/prepare"));
        assert.equal(decoder.decode(Buffer.from(
          prepareCall.body.owners[0].originalExact, "base64url",
        )), "private:SYNTHETIC_EXACT_CANARY");
        const applyCall = transportCalls.find((item) => item.target.endsWith("/apply-ack"));
        assert.equal(applyCall.body.acknowledgements[0].ownerId, opaqueOwnerId);
        assert.equal(applyCall.body.acknowledgements[0].exact, b64(targetExact));
        const verifyCall = transportCalls.find((item) => item.target.endsWith("/verify"));
        assert.equal(verifyCall.body.acknowledgements[0].exact, b64(targetExact));
        assert.match(verifyCall.body.snapshotId, /^mode-snapshot-/);
        assert.equal(verifyCall.body.snapshotGeneration, 1);
        assert(sessionWrites.every((value) => !value.includes("SYNTHETIC_EXACT_CANARY")));
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          false,
        );

        const secondCallStart = transportCalls.length;
        failNextExternalApply = true;
        await assert.rejects(
          pack.mode("privacy-mode").transition("global", "private"),
          /synthetic external apply failure/,
        );
        assert.equal(decoder.decode(owner.exact), "public:SYNTHETIC_EXACT_CANARY");
        assert.deepEqual(
          transportCalls.slice(secondCallStart).map((item) => item.target.split("/").at(-1)),
          [
            "client-heartbeat", "reserve", "prepare",
            "rollback", "rollback", "rollback",
          ],
        );
        assert.deepEqual(calls.slice(7), [
          "settle", "inventory", "apply", "restore", "reload", "reconcile", "release",
        ]);
        assert.equal(frozen, false);
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          false,
        );

        let failureStart = calls.length;
        rejectSettlement = true;
        await assert.rejects(
          pack.mode("privacy-mode").transition("global", "private"),
          /synthetic settlement failure/,
        );
        rejectSettlement = false;
        assert.deepEqual(calls.slice(failureStart), ["settle", "release"]);
        assert.equal(frozen, false);

        failureStart = calls.length;
        invalidInventory = true;
        await assert.rejects(
          pack.mode("privacy-mode").transition("global", "private"),
          (error) => error.code === "browser_external_inventory_invalid",
        );
        invalidInventory = false;
        assert.deepEqual(calls.slice(failureStart), ["settle", "inventory", "release"]);
        assert.equal(frozen, false);

        failureStart = calls.length;
        const transportBeforeCancel = transportCalls.length;
        globalThis.confirm = () => false;
        assert.equal(await pack.mode("privacy-mode").transition("global", "public"), null);
        assert.deepEqual(calls.slice(failureStart), ["settle", "inventory", "release"]);
        assert.deepEqual(
          transportCalls.slice(transportBeforeCancel).map(
            (item) => item.target.split("/").at(-1),
          ),
          ["client-heartbeat"],
        );
        assert.equal(frozen, false);

        failureStart = calls.length;
        const transportBeforePrepareFailure = transportCalls.length;
        globalThis.confirm = () => true;
        failPrepare = true;
        await assert.rejects(
          pack.mode("privacy-mode").transition("global", "private"),
          (error) => error.code === "PRIVACY_BROWSER_REQUEST_FAILED",
        );
        assert.deepEqual(calls.slice(failureStart), [
          "settle", "inventory", "restore", "reload", "reconcile", "release",
        ]);
        assert.deepEqual(
          transportCalls.slice(transportBeforePrepareFailure).map(
            (item) => item.target.split("/").at(-1),
          ),
          ["client-heartbeat", "reserve", "prepare", "rollback", "rollback"],
        );
        assert.equal(frozen, false);
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          false,
        );

        failureStart = calls.length;
        const transportBeforeRollbackFailure = transportCalls.length;
        failPrepare = true;
        failRollbackRequests = 2;
        await assert.rejects(
          pack.mode("privacy-mode").transition("global", "private"),
          (error) => error.code === "PRIVACY_BROWSER_REQUEST_FAILED",
        );
        assert.deepEqual(calls.slice(failureStart), [
          "settle", "inventory", "release",
        ]);
        assert.deepEqual(
          transportCalls.slice(transportBeforeRollbackFailure).map(
            (item) => item.target.split("/").at(-1),
          ),
          ["client-heartbeat", "reserve", "prepare", "rollback", "rollback"],
        );
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          true,
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "browser_mode_transition_fenced",
        );

        failureStart = calls.length;
        const transportBeforeFailedRollbackResume = transportCalls.length;
        resumeRollback = true;
        const rollbackRecovery = await pack.mode("privacy-mode").transition(
          "global", "private",
        );
        resumeRollback = false;
        assert.equal(rollbackRecovery.effective, "public");
        assert.deepEqual(calls.slice(failureStart), [
          "settle", "inventory", "restore", "reload", "reconcile", "release",
        ]);
        assert.deepEqual(
          transportCalls.slice(transportBeforeFailedRollbackResume).map(
            (item) => item.target.split("/").at(-1),
          ),
          ["client-heartbeat", "resume", "rollback", "rollback"],
        );
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          false,
        );
        assert.doesNotThrow(() => graph.serialize());

        failureStart = calls.length;
        const transportBeforeTerminalReconcileFailure = transportCalls.length;
        failNextReconcile = true;
        await assert.rejects(
          pack.mode("privacy-mode").transition("global", "public"),
          /synthetic reconcile failure/,
        );
        assert.deepEqual(calls.slice(failureStart), [
          "settle", "inventory", "apply", "detached", "reload", "reconcile", "release",
        ]);
        assert.deepEqual(
          transportCalls.slice(transportBeforeTerminalReconcileFailure).map(
            (item) => item.target.split("/").at(-1),
          ),
          ["client-heartbeat", "reserve", "prepare", "apply-ack", "verify", "finalize"],
        );
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          true,
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "browser_mode_transition_fenced",
        );

        failureStart = calls.length;
        const transportBeforeTerminalReconcileRetry = transportCalls.length;
        const terminalRecovery = await pack.mode("privacy-mode").transition(
          "global", "public",
        );
        assert.equal(terminalRecovery.effective, "public");
        assert.deepEqual(calls.slice(failureStart), [
          "settle", "inventory", "apply", "reload", "reconcile", "release",
        ]);
        assert.deepEqual(
          transportCalls.slice(transportBeforeTerminalReconcileRetry).map(
            (item) => item.target.split("/").at(-1),
          ),
          ["client-heartbeat", "rebase"],
        );
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          false,
        );
        assert.doesNotThrow(() => graph.serialize());

        failureStart = calls.length;
        const transportBeforeReleaseFailure = transportCalls.length;
        failNextRelease = true;
        await assert.rejects(
          pack.mode("privacy-mode").transition("global", "public"),
          (error) => error.code === "browser_external_release_failed",
        );
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          true,
        );
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        const releaseRecovery = await pack.mode("privacy-mode").transition(
          "global", "public",
        );
        assert.equal(releaseRecovery.effective, "public");
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          false,
        );
        assert.doesNotThrow(() => graph.serialize());
        assert.deepEqual(
          transportCalls.slice(transportBeforeReleaseFailure).map(
            (item) => item.target.split("/").at(-1),
          ),
          [
            "client-heartbeat", "reserve", "prepare", "apply-ack", "verify", "finalize",
            "client-heartbeat", "rebase",
          ],
        );

        failureStart = calls.length;
        const transportBeforeResume = transportCalls.length;
        const coordinatorId = sessionValues.get(
          "helto_privacy_mode_coordinator:helto.director",
        );
        const recoverySecret = `hp-mode-resume-${"r".repeat(43)}`;
        originalAtReserve = new Uint8Array(owner.exact);
        rollbackCompleted = false;
        opaqueOwnerId = null;
        resumeRollback = true;
        sessionValues.set(
          "helto_privacy_mode_transition:helto.director:global",
          JSON.stringify({
            transitionId,
            requestId: "mode-request-" + "q".repeat(24),
            coordinatorId,
            resumeSecret: recoverySecret,
            scopeId: "global",
            target: "private",
            modeEpoch: currentEpoch,
            targetModeEpoch: currentEpoch + 1,
            priorDeclared: "public",
            clientLease: lease,
            clientLeaseEpoch: 1,
            serverBootEpoch: bootEpoch,
          }),
        );
        const recovered = await pack.mode("privacy-mode").transition("global", "private");
        resumeRollback = false;
        assert.equal(recovered.effective, "public");
        assert.equal(decoder.decode(owner.exact), "public:SYNTHETIC_EXACT_CANARY");
        assert.deepEqual(calls.slice(failureStart), [
          "settle", "inventory", "restore", "reload", "reconcile", "release",
        ]);
        assert.deepEqual(
          transportCalls.slice(transportBeforeResume).map(
            (item) => item.target.split("/").at(-1),
          ),
          ["client-heartbeat", "resume", "rollback", "rollback"],
        );
        assert.equal(
          sessionValues.has("helto_privacy_mode_transition:helto.director:global"),
          false,
        );

        const crossTabFenceKey = "helto_privacy_mode_fence:helto.director:global";
        localValues.set(crossTabFenceKey, JSON.stringify({
          coordinatorId: "mode-coordinator-" + "z".repeat(24),
          modeEpoch: currentEpoch,
          serverBootEpoch: bootEpoch,
          expiresAt: Date.now() + 60_000,
        }));
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        await assert.rejects(
          app.graphToPrompt(),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        await assert.rejects(
          app.queuePrompt(0, { output: { "12": { inputs: {} } }, workflow: { nodes: [] } }),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        await assert.rejects(
          pack.workflow("timeline").runWithSnapshot(
            "direct-queue",
            () => pack.execution("render").prepare(owner),
          ),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        localValues.delete(crossTabFenceKey);
        const epochKey = "helto_privacy_mode_epoch:helto.director:global";
        localValues.set(epochKey, JSON.stringify({
          modeEpoch: currentEpoch + 1,
          serverBootEpoch: bootEpoch,
        }));
        assert.throws(
          () => graph.serialize(),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        localValues.set(epochKey, JSON.stringify({
          modeEpoch: currentEpoch,
          serverBootEpoch: bootEpoch,
        }));
        """,
    )


def test_external_browser_operation_recovers_uncertain_apply_and_restores_exact_terminal(
    tmp_path,
):
    run_node_module_test(
        tmp_path,
        """
        const original = new TextEncoder().encode("SYNTHETIC_ORIGINAL_EXACT");
        const target = new TextEncoder().encode("SYNTHETIC_TARGET_EXACT");
        const encode = (value) => Buffer.from(value).toString("base64url");
        const transactionId = `hp-operation-${"t".repeat(32)}`;
        const resumeCapability = `hp-operation-resume-${"r".repeat(43)}`;
        const identity = {
          rootGraphId: "root",
          graphId: "root",
          nodeId: "12",
          fieldId: "timeline-state",
        };
        const sessionValues = new Map();
        globalThis.sessionStorage = {
          getItem(key) { return sessionValues.has(key) ? sessionValues.get(key) : null; },
          setItem(key, value) { sessionValues.set(String(key), String(value)); },
          removeItem(key) { sessionValues.delete(String(key)); },
        };

        const externalOperationMethods = [
          ...attestation().requiredBrowserAdapters[0].methods,
          "settleModeTransition",
          "inventoryModeTransitionOwners",
          "readModeTransitionOwnerExact",
          "applyModeTransitionOwnerExact",
          "extractDetachedModeTransitionOwnerExact",
          "restoreModeTransitionOwnerExact",
          "reloadModeTransitionRuntime",
          "reconcileModeTransitionRuntime",
          "settleExternalOperation",
          "identifyExternalOperationOwner",
          "resolveExternalOperationOwner",
          "readExternalOperationExact",
          "applyExternalOperation",
          "restoreExternalOperationExact",
          "reloadExternalOperationRuntime",
          "reconcileExternalOperationRuntime",
        ].sort();
        const operation = {
          id: "associate-captured-take",
          resourceId: "operations",
          route: null,
          method: "POST",
          scopeId: "global",
          sensitiveFields: [{ path: "*", class: "consumer-derived" }],
          safeProjection: [{ path: "items", kind: "count" }],
          subjectModeBindingId: null,
          referenceInputs: [],
          referenceOutputs: [],
          returnsLease: false,
          safePayloadProjectionId: null,
          deferredUi: false,
          recordDependencies: [],
          singletonDependencies: [],
          artifactDependencies: [],
          externalOperationBinding: {
            fieldId: "timeline-state",
            browserAdapter: "timeline-editor",
            policy: {
              ownerIdentity: "graph-node-v1",
              maxIdentityBytes: 1024,
              maxOriginalBytes: 1024,
              maxTargetBytes: 1024,
              leaseSeconds: 30,
            },
          },
        };
        serverAttestation = () => attestation({
          requiredBrowserAdapters: [{
            ...attestation().requiredBrowserAdapters[0],
            methods: externalOperationMethods,
          }, attestation().requiredBrowserAdapters[1]],
          resources: [
            ...attestation().resources,
            { id: "operations", kind: "operation" },
          ],
          protectedFields: [{
            ...attestation().protectedFields[0],
            stateAuthority: "external-browser-workflow",
            externalTransitionPolicy: {
              ownerIdentity: "graph-node-field-v1",
              maxOwners: 4,
              maxOriginalBytesPerOwner: 1024,
              maxTargetBytesPerOwner: 1024,
              maxTotalBytes: 4096,
              leaseSeconds: 60,
            },
          }],
          protectedOperations: [operation],
        });

        const owner = { id: 12, exact: original };
        const calls = [];
        let failRelease = true;
        const adapter = {
          apply() {}, clear() {}, normalize() { return {}; },
          readProtected() { return "SYNTHETIC_ENVELOPE"; },
          writeProtected() {}, onPrivacySessionChange() {},
          reconcileNode() {}, reconcileNodeDefinition() {},
          settleModeTransition() { return { settled: Promise.resolve({
            offlineRepresentationCount: 0,
          }), release() {} }; },
          inventoryModeTransitionOwners() { return []; },
          readModeTransitionOwnerExact() { return original; },
          applyModeTransitionOwnerExact() {},
          extractDetachedModeTransitionOwnerExact() { return original; },
          restoreModeTransitionOwnerExact() {},
          reloadModeTransitionRuntime() {},
          reconcileModeTransitionRuntime() {},
          settleExternalOperation() {
            calls.push("settle");
            return {
              settled: Promise.resolve(),
              release() {
                calls.push("release");
                if (failRelease) {
                  failRelease = false;
                  throw new Error("synthetic release failure");
                }
              },
            };
          },
          identifyExternalOperationOwner(value) {
            assert.equal(value, owner);
            calls.push("identify");
            return identity;
          },
          resolveExternalOperationOwner(value) {
            assert.deepEqual(value, identity);
            calls.push("resolve");
            return owner;
          },
          readExternalOperationExact(value) {
            assert.equal(value, owner);
            calls.push("read");
            return value.exact;
          },
          applyExternalOperation(value, browserValue) {
            assert.equal(value, owner);
            assert.deepEqual(browserValue, { captured: true });
            calls.push("apply");
            value.exact = target;
          },
          restoreExternalOperationExact(value, exact) {
            assert.equal(value, owner);
            calls.push("restore");
            value.exact = new Uint8Array(exact);
          },
          reloadExternalOperationRuntime() { calls.push("reload"); },
          reconcileExternalOperationRuntime() { calls.push("reconcile"); },
        };
        const app = {
          rootGraph: { _nodes: [owner] },
          registeredNodeTypes: {},
          registerExtension(extension) { this.extension = extension; },
        };
        const pack = await privacy.connectPrivacyPack({
          app,
          packId: "helto.director",
          profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: { "timeline-editor": adapter },
        });

        let serverPhase = "absent";
        let capturedIdentity = null;
        const response = (payload) => ({
          ok: true,
          status: 200,
          async json() { return payload; },
          async text() { return JSON.stringify(payload); },
        });
        const terminal = () => ({
          ok: true,
          transactionId,
          operationId: operation.id,
          phase: "completed",
          active: false,
          expiresInSeconds: 0,
          receiptId: `hp-operation-receipt-${"d".repeat(32)}`,
          ownerIdentity: capturedIdentity,
          exact: encode(target),
          result: {
            ok: true,
            data: { items: 1 },
            safePayload: null,
            references: [],
            lease: null,
            association: null,
            private: true,
            correlationId: `hp-operation-${"c".repeat(16)}`,
          },
        });
        externalOperationHandler = async (route, options) => {
          if (route.endsWith("/prepare")) {
            const body = JSON.parse(options.body);
            capturedIdentity = body.ownerIdentity;
            assert.equal(body.originalExact, encode(original));
            assert.deepEqual(body.input, { takeId: "take-7" });
            serverPhase = "prepared";
            return response({
              ok: true,
              transactionId,
              operationId: operation.id,
              phase: "prepared",
              active: true,
              expiresInSeconds: 30,
              receiptId: null,
              ownerIdentity: capturedIdentity,
              originalExact: encode(original),
              targetExact: null,
              browserValue: { captured: true },
              resumeCapability,
            });
          }
          assert.equal(
            options.headers["X-Helto-Privacy-Operation-Resume-Capability"],
            resumeCapability,
          );
          if (route.endsWith("/apply")) {
            assert.equal(JSON.parse(options.body).currentExact, encode(target));
            serverPhase = "completed";
            throw new Error("synthetic response loss after commit");
          }
          if (route.endsWith("/resume") && serverPhase === "completed") {
            return response(terminal());
          }
          assert.fail(`unexpected external operation route ${route}`);
        };

        const operations = pack.operations("operations");
        await assert.rejects(
          operations.invokeExternal(operation.id, owner, { takeId: "take-7" }),
          (error) => error.code === "browser_external_operation_release_failed",
        );
        assert.equal(sessionValues.size, 1);
        const result = await operations.invokeExternal(
          operation.id, owner, { takeId: "take-7" },
        );
        assert.deepEqual(result.data, { items: 1 });
        assert.equal(Buffer.from(owner.exact).toString(), "SYNTHETIC_TARGET_EXACT");
        assert.equal(sessionValues.size, 0);
        assert(calls.includes("apply"));
        assert(calls.includes("restore"));
        assert.deepEqual(calls.slice(-3), ["reload", "reconcile", "release"]);
        """,
    )


def test_two_browser_realms_fence_stale_owner_until_exact_reload(tmp_path):
    module_a = write_privacy_profile_module_tree(tmp_path / "tab-a")
    module_b = write_privacy_profile_module_tree(tmp_path / "tab-b")
    script = textwrap.dedent(
        """
        import assert from "node:assert/strict";
        import * as tabA from __TAB_A__;
        import * as tabB from __TAB_B__;

        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        const fingerprint = "a".repeat(64);
        const suiteDigest = "d".repeat(64);
        const bootEpoch = `hp-boot-${"b".repeat(32)}`;
        const transitionId = "2".repeat(32);
        const lease = `hp-mode-client-${"l".repeat(43)}`;
        const privateExact = encoder.encode("private:TWO_TAB_EXACT_CANARY");
        const publicExact = encoder.encode("public:TWO_TAB_EXACT_CANARY");
        let currentEpoch = 0;
        let opaqueOwnerId = null;
        const rebaseCalls = [];
        let failRebase = false;

        const sharedLocalValues = new Map();
        globalThis.localStorage = {
          getItem(key) { return sharedLocalValues.has(key) ? sharedLocalValues.get(key) : null; },
          setItem(key, value) { sharedLocalValues.set(String(key), String(value)); },
          removeItem(key) { sharedLocalValues.delete(String(key)); },
        };
        const makeSessionStorage = () => {
          const values = new Map();
          return {
            getItem(key) { return values.has(key) ? values.get(key) : null; },
            setItem(key, value) { values.set(String(key), String(value)); },
            removeItem(key) { values.delete(String(key)); },
          };
        };
        const sessionA = makeSessionStorage();
        const sessionB = makeSessionStorage();
        globalThis.sessionStorage = sessionB;
        globalThis.confirm = () => true;
        globalThis.document = { cookie: "" };

        const workflowMethods = [
          "apply", "applyModeTransitionOwnerExact", "clear",
          "extractDetachedModeTransitionOwnerExact", "inventoryModeTransitionOwners",
          "normalize", "onPrivacySessionChange", "readModeTransitionOwnerExact",
          "readProtected", "reconcileModeTransitionRuntime", "reconcileNode",
          "reconcileNodeDefinition", "reloadModeTransitionRuntime",
          "restoreModeTransitionOwnerExact", "settleModeTransition", "writeProtected",
        ];
        const attestation = {
          ok: true,
          id: "helto.two-tab",
          contract: tabA.PRIVACY_CONTRACT_V3,
          modeTransitionProtocol: tabA.MODE_TRANSITION_PROTOCOL,
          serverBootEpoch: bootEpoch,
          fingerprint,
          status: "ready",
          suiteStatus: "active",
          suiteManifestDigest: suiteDigest,
          requiredBrowserAdapters: [{
            id: "workflow-ui", nodeTypes: ["SyntheticNode"], methods: workflowMethods,
          }, {
            id: "mode-ui", nodeTypes: ["SyntheticNode"], methods: [
              "onPrivacySessionChange", "readDeclaredMode", "reconcileNode",
              "reconcileNodeDefinition", "writeDeclaredMode",
            ],
          }],
          resources: [
            { id: "privacy-mode", kind: "mode" },
            { id: "workflow", kind: "workflow" },
            { id: "execution", kind: "execution" },
          ],
          modeScopes: [{
            id: "global", modeResourceId: "privacy-mode", modeEditorAdapter: "mode-ui",
          }],
          protectedFields: [{
            id: "state",
            workflowResourceId: "workflow",
            scopeId: "global",
            browserAdapter: "workflow-ui",
            nodeTypes: ["SyntheticNode"],
            legacyReaderIds: [],
            execution: false,
            stateAuthority: "external-browser-workflow",
            externalTransitionPolicy: {
              ownerIdentity: "graph-node-field-v1",
              maxOwners: 4,
              maxOriginalBytesPerOwner: 1024,
              maxTargetBytesPerOwner: 1024,
              maxTotalBytes: 4096,
              leaseSeconds: 60,
            },
          }],
          executionProjections: [], subjectModeBindings: [], records: [], singletons: [],
          artifacts: [], protectedOperations: [], recordReferenceMigrations: [],
          safePayloadProjections: [],
        };
        const response = (payload) => ({
          ok: true,
          status: 200,
          async json() { return payload; },
          async text() { return JSON.stringify(payload); },
        });
        const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
        const makeOwnerId = async (secret) => {
          const key = await crypto.subtle.importKey(
            "raw", encoder.encode(secret),
            { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
          );
          const message = [
            "graph-node-field-v1", "helto.two-tab", fingerprint, "global",
            "root", "root", "7", "state",
          ].join("\\0");
          return `hp-owner-${b64(new Uint8Array(await crypto.subtle.sign(
            "HMAC", key, encoder.encode(message),
          )))}`;
        };

        globalThis.fetch = async (url, options = {}) => {
          const target = String(url);
          if (target.endsWith("/suite/browser-attestation")) return response({ ok: true });
          if (target.endsWith("/profiles/helto.two-tab")) return response(attestation);
          if (target.endsWith("/modes/global/resolve")) {
            return response({
              id: "global", modeResourceId: "privacy-mode",
              declared: currentEpoch ? "public" : "private",
              effective: currentEpoch ? "public" : "private",
              inheritedFrom: currentEpoch ? "declared-public" : "declared-private",
              floors: [], transitionStatus: "idle", modeEpoch: currentEpoch,
            });
          }
          if (target.endsWith("/modes")) {
            return response({ ok: true, serverBootEpoch: bootEpoch, scopes: [{
              id: "global", modeResourceId: "privacy-mode",
              declared: currentEpoch ? "public" : "private",
              effective: currentEpoch ? "public" : "private",
              inheritedFrom: currentEpoch ? "declared-public" : "declared-private",
              floors: [], transitionStatus: "idle", modeEpoch: currentEpoch,
            }] });
          }
          if (target.endsWith("/disposition")) {
            return response({ ok: true, disposition: "verified-current" });
          }
          if (target.endsWith("/protect")) {
            return response({ ok: true, envelope: "SYNTHETIC_CURRENT_ENVELOPE" });
          }
          if (target.endsWith("/reveal")) {
            return response({ ok: true, value: {} });
          }
          if (target.endsWith("/client-heartbeat")) return response({ ok: true });
          const body = options.body === undefined ? {} : JSON.parse(options.body);
          if (target.endsWith("/rebase")) {
            if (failRebase) {
              failRebase = false;
              throw new Error("synthetic rebase failure");
            }
            rebaseCalls.push({ body, headers: { ...options.headers } });
            return response({
              ok: true, scopeId: "global", fieldId: "state",
              exact: b64(publicExact), modeEpoch: currentEpoch,
              serverBootEpoch: bootEpoch,
            });
          }
          const secret = options.headers?.["X-Helto-Privacy-Resume-Capability"];
          if (target.endsWith("/reserve")) {
            return response({
              ok: true, transitionId, requestId: body.requestId,
              clientLease: lease, clientLeaseEpoch: 1, modeEpoch: 0,
              targetModeEpoch: 1, priorDeclared: "private",
            });
          }
          opaqueOwnerId ||= await makeOwnerId(secret);
          if (target.endsWith("/prepare")) {
            return response({
              ok: true, externalPhase: "prepared",
              pendingOwners: [{ ownerId: opaqueOwnerId, fieldId: "state", exact: b64(publicExact) }],
            });
          }
          if (target.endsWith("/apply-ack")) {
            return response({ ok: true, externalPhase: "applied", pendingOwners: [] });
          }
          if (target.endsWith("/verify")) {
            return response({ ok: true, externalPhase: "verified", pendingOwners: [] });
          }
          if (target.endsWith("/finalize")) {
            currentEpoch = 1;
            return response({
              ok: true, scopeId: "global", declared: "public", effective: "public",
              transitionStatus: "idle", modeEpoch: 1,
            });
          }
          if (target === "/prompt") return response({ ok: true });
          return response({ ok: true });
        };

        class TestApi {
          async fetchApi(route, options = {}) { return globalThis.fetch(route, options); }
          async queuePrompt(number, data) {
            return this.fetchApi("/prompt", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                client_id: "two-tab", prompt: data.output,
                extra_data: { extra_pnginfo: { workflow: data.workflow } },
                ...(number === -1 ? { front: true } : {}),
              }),
            });
          }
        }
        class TestApp {
          constructor(owner) {
            this.owner = owner;
            this.api = new TestApi();
            this.registeredNodeTypes = {};
            this.rootGraph = {
              _nodes: [owner],
              serialize: () => ({ nodes: [{ id: 7, exact: [...owner.exact] }] }),
            };
          }
          registerExtension(extension) { this.extension = extension; }
          async graphToPrompt() {
            return {
              workflow: this.rootGraph.serialize(),
              output: { "7": { inputs: {} } },
            };
          }
          async queuePrompt(...args) { return this.api.queuePrompt(...args); }
        }

        const createAdapters = (owner, events, controls = {}) => {
          let transitionSettled = false;
          const requireTransition = () => assert.equal(transitionSettled, true);
          return {
            "mode-ui": {
              readDeclaredMode: () => currentEpoch ? "public" : "private",
              writeDeclaredMode() {}, onPrivacySessionChange() {},
              reconcileNode() {}, reconcileNodeDefinition() {},
            },
            "workflow-ui": {
              apply() {}, clear() {}, normalize: (value) => value.live,
              readProtected: (value) => value.protected,
              writeProtected(value, protectedValue) { value.protected = protectedValue; },
              onPrivacySessionChange() {}, reconcileNode() {}, reconcileNodeDefinition() {},
              settleModeTransition() {
                assert.equal(transitionSettled, false);
                transitionSettled = true;
                events.push("freeze");
                return {
                  settled: Promise.resolve({ offlineRepresentationCount: 0 }),
                  async release() {
                    requireTransition();
                    events.push("release");
                    transitionSettled = false;
                  },
                };
              },
              async inventoryModeTransitionOwners() {
                requireTransition();
                return [{ owner, rootGraphId: "root", graphId: "root", nodeId: "7" }];
              },
              async readModeTransitionOwnerExact(value) {
                requireTransition();
                if (controls.corruptNextReadback) {
                  controls.corruptNextReadback = false;
                  const corrupted = new Uint8Array(value.exact);
                  corrupted[0] ^= 1;
                  return corrupted;
                }
                return value.exact;
              },
              async applyModeTransitionOwnerExact(value, exact) {
                requireTransition();
                events.push("exact-apply");
                value.exact = new Uint8Array(exact);
                if (controls.corruptAfterApply) {
                  controls.corruptAfterApply = false;
                  controls.corruptNextReadback = true;
                }
              },
              async extractDetachedModeTransitionOwnerExact(_value, serialized) {
                requireTransition();
                return new Uint8Array(serialized.nodes[0].exact);
              },
              async restoreModeTransitionOwnerExact(value, exact) {
                requireTransition();
                value.exact = new Uint8Array(exact);
              },
              async reloadModeTransitionRuntime() {
                requireTransition();
                events.push("exact-reload");
              },
              async reconcileModeTransitionRuntime() {
                requireTransition();
                events.push("exact-reconcile");
                if (controls.failReconcile) {
                  controls.failReconcile = false;
                  throw new Error("synthetic reconcile failure");
                }
              },
            },
          };
        };

        const ownerA = {
          id: 7, type: "SyntheticNode", live: {},
          protected: "SYNTHETIC_ENVELOPE", exact: new Uint8Array(privateExact),
        };
        const ownerB = {
          id: 7, type: "SyntheticNode", live: {},
          protected: "SYNTHETIC_ENVELOPE", exact: new Uint8Array(privateExact),
        };
        const eventsA = [];
        const eventsB = [];
        const controlsB = {};
        const appA = new TestApp(ownerA);
        const appB = new TestApp(ownerB);
        const packA = await tabA.connectPrivacyPack({
          app: appA, packId: "helto.two-tab", profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest, adapters: createAdapters(ownerA, eventsA),
        });
        const packB = await tabB.connectPrivacyPack({
          app: appB, packId: "helto.two-tab", profileFingerprint: fingerprint,
          suiteManifestDigest: suiteDigest,
          adapters: createAdapters(ownerB, eventsB, controlsB),
        });
        const workflowB = packB.workflow("workflow");
        globalThis.sessionStorage = sessionB;
        await workflowB.settle("manual-save");

        globalThis.sessionStorage = sessionA;
        await packA.mode("privacy-mode").transition("global", "public");
        assert.equal(decoder.decode(ownerA.exact), "public:TWO_TAB_EXACT_CANARY");
        assert.equal(decoder.decode(ownerB.exact), "private:TWO_TAB_EXACT_CANARY");

        globalThis.sessionStorage = sessionB;
        assert.throws(
          () => workflowB.markEdited(ownerB, "state"),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        assert.throws(
          () => appB.rootGraph.serialize(),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        await assert.rejects(
          appB.graphToPrompt(),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        await assert.rejects(
          appB.queuePrompt(0, { output: { "7": { inputs: {} } }, workflow: { nodes: [] } }),
          (error) => error.code === "browser_mode_transition_fenced",
        );
        await assert.rejects(
          workflowB.runWithSnapshot(
            "direct-queue", () => packB.execution("execution").prepare(ownerB),
          ),
          (error) => error.code === "browser_mode_transition_fenced",
        );

        const assertStillFenced = () => assert.throws(
          () => workflowB.markEdited(ownerB, "state"),
          (error) => error.code === "browser_mode_transition_fenced",
        );

        failRebase = true;
        await assert.rejects(
          workflowB.reload(ownerB, "state"),
          (error) => error.code === "PRIVACY_BROWSER_REQUEST_FAILED",
        );
        assert.deepEqual(eventsB.slice(-2), ["freeze", "release"]);
        assertStillFenced();

        controlsB.corruptAfterApply = true;
        await assert.rejects(
          workflowB.reload(ownerB, "state"),
          (error) => error.code === "browser_external_owner_drift",
        );
        assert.deepEqual(eventsB.slice(-3), ["freeze", "exact-apply", "release"]);
        assertStillFenced();

        controlsB.failReconcile = true;
        await assert.rejects(
          workflowB.reload(ownerB, "state"),
          /synthetic reconcile failure/,
        );
        assert.deepEqual(eventsB.slice(-5), [
          "freeze", "exact-apply", "exact-reload", "exact-reconcile", "release",
        ]);
        assertStillFenced();

        const successStart = eventsB.length;
        await workflowB.reload(ownerB, "state");
        assert.equal(decoder.decode(ownerB.exact), "public:TWO_TAB_EXACT_CANARY");
        assert.deepEqual(eventsB.slice(successStart), [
          "freeze", "exact-apply", "exact-reload", "exact-reconcile", "release",
        ]);
        assert.equal(rebaseCalls.length, 3);
        assert.equal(
          decoder.decode(Buffer.from(rebaseCalls[0].body.exact, "base64url")),
          "private:TWO_TAB_EXACT_CANARY",
        );
        assert.deepEqual(rebaseCalls[0].body, {
          fieldId: "state",
          exact: rebaseCalls[0].body.exact,
          modeEpoch: 1,
        });
        assert.equal(
          rebaseCalls[0].headers["X-Helto-Privacy-Boot-Epoch"],
          bootEpoch,
        );
        workflowB.markEdited(ownerB, "state");
        await workflowB.settle("manual-save");
        assert.doesNotThrow(() => appB.rootGraph.serialize());
        """
    ).replace("__TAB_A__", repr(module_a.as_uri())).replace(
        "__TAB_B__", repr(module_b.as_uri())
    )
    script_path = tmp_path / "two_tabs.mjs"
    script_path.write_text(script, encoding="utf-8")
    result = subprocess.run(
        ["node", str(script_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
