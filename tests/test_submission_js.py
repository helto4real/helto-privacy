import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUBMISSION = ROOT / "helto_privacy" / "web" / "privacy_submission.js"


def test_submission_service_direct_body_route_header_and_permit_contract(tmp_path):
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module_path = tmp_path / "privacy_submission.js"
    module_path.write_text(SUBMISSION.read_text(encoding="utf-8"), encoding="utf-8")
    script = tmp_path / "test.mjs"
    script.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import {{
              createPrivacyPromptSubmissionService,
              installPrivacySubmissionOwnership,
            }} from {module_path.as_uri()!r};

            class TestError extends Error {{
              constructor(code) {{ super("submission failed"); this.code = code; }}
            }}
            const createError = (code) => new TestError(code);
            let headerGetterCalls = 0;
            class TestApi {{
              mode = "normal";
              clientId = "client-direct";
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
                    extra_pnginfo: {{ workflow: data.workflow }},
                    ...(options?.previewMethod && options.previewMethod !== "default"
                      ? {{ preview_method: options.previewMethod }}
                      : {{}}),
                  }},
                  ...(number === -1 ? {{ front: true }} : {{}}),
                  ...(number !== 0 && number !== -1 ? {{ number }} : {{}}),
                }};
                const headers = {{ "Content-Type": "application/json" }};
                if (this.mode === "getter") {{
                  Object.defineProperty(headers, "Content-Type", {{
                    enumerable: true,
                    get() {{ headerGetterCalls += 1; return "application/json"; }},
                  }});
                }}
                if (this.mode === "extra") body.extra = true;
                const response = await this.fetchApi("/prompt", {{
                  method: "POST",
                  headers,
                  body: JSON.stringify(body),
                }});
                return response.json();
              }}
            }}
            class TestApp {{
              constructor(api) {{ this.api = api; }}
              async graphToPrompt() {{ return {{ workflow: {{}}, output: {{}} }}; }}
              async queuePrompt() {{ return true; }}
            }}

            const networkBodies = [];
            globalThis.fetch = async (route, options = {{}}) => {{
              networkBodies.push({{ route, options, body: JSON.parse(options.body) }});
              return {{ async json() {{ return {{ ok: true }}; }} }};
            }};
            const api = new TestApi();
            const app = new TestApp(api);
            const ownership = installPrivacySubmissionOwnership({{
              app,
              createError,
              requireAvailable() {{}},
              onConflict() {{ throw createError("PRIVACY_PROFILE_UNAVAILABLE"); }},
            }});
            const revoked = [];
            const service = createPrivacyPromptSubmissionService({{
              api,
              coreQueuePrompt: ownership.core.apiQueuePrompt,
              coreFetchApi: ownership.core.fetchApi,
              runSubmission: (operation) => operation(Object.freeze({{ id: "domain" }})),
              prepareSubmission: async (prompt, onMint) => {{
                onMint(Object.freeze({{ grant: `grant-${{revoked.length}}` }}));
                return structuredClone(prompt);
              }},
              validateSubmission() {{}},
              revokeMinted: async (references) => {{ revoked.push(references); }},
              createError,
            }});
            ownership.installHandlers({{
              graphToPrompt: (core, receiver, args) => core.apply(receiver, args),
              ...service.handlers,
            }});

            await api.queuePrompt(-1, {{
              output: {{ "1": {{ inputs: {{ seed: 7 }} }} }},
              workflow: {{ nodes: [{{ id: 1 }}] }},
            }}, {{ partialExecutionTargets: ["1"], previewMethod: "taesd" }});
            assert.equal(networkBodies.length, 1);
            assert.deepEqual(networkBodies[0].body, {{
              client_id: "client-direct",
              prompt: {{ "1": {{ inputs: {{ seed: 7 }} }} }},
              partial_execution_targets: ["1"],
              extra_data: {{
                extra_pnginfo: {{ workflow: {{ nodes: [{{ id: 1 }}] }} }},
                preview_method: "taesd",
              }},
              front: true,
            }});
            assert.equal(networkBodies[0].options.signal.aborted, false);
            await assert.rejects(
              api.fetchApi("/%70rompt", {{ method: "POST" }}),
              (error) => error.code === "PRIVACY_SNAPSHOT_OPERATION_INVALID",
            );
            assert.equal(networkBodies.length, 1);

            api.mode = "getter";
            await assert.rejects(api.queuePrompt(0, {{ output: {{}}, workflow: {{}} }}));
            assert.equal(headerGetterCalls, 0);
            assert.equal(networkBodies.length, 1);
            assert.equal(revoked.length, 1);

            api.mode = "extra";
            await assert.rejects(api.queuePrompt(0, {{ output: {{}}, workflow: {{}} }}));
            assert.equal(networkBodies.length, 1);
            assert.equal(revoked.length, 2);
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
