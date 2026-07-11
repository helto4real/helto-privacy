from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_MODULE = ROOT / "helto_privacy" / "web" / "privacy_artifacts.js"


def test_artifact_lease_browser_helper_accepts_only_opaque_shared_urls(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for browser helper tests")
    module_path = tmp_path / "privacy_artifacts.mjs"
    module_path.write_text(ARTIFACTS_MODULE.read_text(encoding="utf-8"), encoding="utf-8")
    script = tmp_path / "test.mjs"
    script.write_text(
        """
        import assert from "node:assert/strict";
        import {
          PrivacyArtifactLeaseError,
          normalizeArtifactLease,
          resolveArtifactLeaseURL,
        } from "./privacy_artifacts.mjs";

        const lease = {
          url: "/helto_privacy/artifacts/hp-lease-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
          expiresInSeconds: 60,
        };
        assert.deepEqual(normalizeArtifactLease(lease), lease);
        assert.equal(resolveArtifactLeaseURL(lease), lease.url);
        assert.equal(resolveArtifactLeaseURL(lease, (path) => `/api${path}`), `/api${lease.url}`);

        const rejected = [
          { ...lease, token: "secret" },
          { ...lease, filename: "private.mp4" },
          { ...lease, path: "/private/video.mp4" },
          { ...lease, url: `${lease.url}?token=secret` },
          { ...lease, url: `${lease.url}#private` },
          { ...lease, url: "/helto_utils/private_media?token=encrypted" },
          { ...lease, expiresInSeconds: 0 },
        ];
        for (const candidate of rejected) {
          assert.throws(
            () => resolveArtifactLeaseURL(candidate),
            (error) => error instanceof PrivacyArtifactLeaseError
              && error.code === "PRIVACY_ARTIFACT_LEASE_INVALID",
          );
        }
        assert.throws(
          () => resolveArtifactLeaseURL(lease, "not-a-function"),
          (error) => error.code === "PRIVACY_ARTIFACT_URL_ADAPTER_INVALID",
        );
        """,
        encoding="utf-8",
    )

    completed = subprocess.run(
        [node, str(script)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, json.dumps(
        {"stdout": completed.stdout, "stderr": completed.stderr},
        indent=2,
    )
