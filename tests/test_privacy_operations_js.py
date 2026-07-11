import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "helto_privacy" / "web" / "privacy_operations.js"


def test_protected_display_applies_only_verified_result_and_restores_on_failure(
    tmp_path,
):
    script = tmp_path / "test.mjs"
    script.write_text(
        textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import {{ createProtectedDisplayController }} from {OPERATIONS.as_uri()!r};

            const owner = {{ protected: "PREVIOUS", plain: "stale" }};
            const adapter = {{
              readProtected: (value) => value.protected,
              writeProtected: (value, protectedValue) => {{ value.protected = protectedValue; }},
              apply: (value, revealed) => {{ value.plain = revealed; }},
              clear: (value) => {{ value.plain = ""; }},
              block: (value) => {{ value.blocked = true; value.plain = ""; }},
            }};
            const allowed = createProtectedDisplayController({{
              adapter,
              invoke: async () => ({{ text: "AUTHORIZED" }}),
              project: (result) => result.text,
            }});
            assert.equal(await allowed.display(owner, "CURRENT", {{}}), "AUTHORIZED");
            assert.deepEqual(owner, {{ protected: "CURRENT", plain: "AUTHORIZED" }});

            const blocked = createProtectedDisplayController({{
              adapter,
              invoke: async () => {{ throw new Error("locked"); }},
              project: (result) => result.text,
              failureCode: "PRODUCT_REVEAL_BLOCKED",
            }});
            await assert.rejects(
              blocked.display(owner, "UNVERIFIED", {{}}),
              (error) => error.code === "PRODUCT_REVEAL_BLOCKED",
            );
            assert.deepEqual(owner, {{ protected: "CURRENT", plain: "" }});

            owner.plain = "previously revealed";
            await assert.rejects(
              blocked.display(owner, {{ malformed: true }}, {{}}),
              (error) => error.code === "PRODUCT_REVEAL_BLOCKED",
            );
            assert.deepEqual(owner, {{ protected: "CURRENT", plain: "" }});

            owner.plain = "revealed before cleanup fault";
            const restoreFaultAdapter = {{
              ...adapter,
              writeProtected(value, protectedValue) {{
                if (protectedValue === "CURRENT") throw new Error("restore failed");
                value.protected = protectedValue;
              }},
            }};
            const restoreFault = createProtectedDisplayController({{
              adapter: restoreFaultAdapter,
              invoke: async () => {{ throw new Error("locked"); }},
              project: (result) => result.text,
            }});
            await assert.rejects(restoreFault.display(owner, "CANDIDATE", {{}}));
            assert.equal(owner.blocked, true);
            assert.equal(owner.plain, "");

            delete owner.blocked;
            owner.plain = "revealed before clear fault";
            const clearFaultAdapter = {{
              ...adapter,
              clear: () => {{ throw new Error("clear failed"); }},
            }};
            const clearFault = createProtectedDisplayController({{
              adapter: clearFaultAdapter,
              invoke: async () => {{ throw new Error("locked"); }},
              project: (result) => result.text,
            }});
            await assert.rejects(clearFault.display(owner, "NEXT", {{}}));
            assert.equal(owner.blocked, true);
            assert.equal(owner.plain, "");
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
