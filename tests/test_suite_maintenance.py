import hashlib

from helto_privacy.suite_maintenance import (
    EncryptedCopyReceipt,
    OpaqueObjectReference,
)
from helto_privacy.suite_runtime import (
    SuiteInstallation,
)
from test_suite_runtime import _inventory, _release


class SyntheticMaintenanceBackend:
    def __init__(self):
        self.objects = {
            "source-1": b'{"encrypted":true,"ciphertext":"SYNTHETIC_CIPHERTEXT"}',
        }

    def read_envelope_header(self, reference):
        assert reference.id == "source-1"
        return {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "schema": "helto.synthetic.v1",
            "keyId": "opaque-key-1",
            "ciphertext": "SYNTHETIC_CIPHERTEXT",
        }

    def opaque_key_available(self, key_id):
        return key_id == "opaque-key-1"

    def copy_encrypted(self, source, destination):
        payload = self.objects[source.id]
        self.objects[destination.id] = payload
        return EncryptedCopyReceipt(
            object_id="copy-receipt-1",
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_count=len(payload),
        )


def test_maintenance_capability_is_operator_blind_and_product_data_free():
    release = _release(ready=True)
    installation = SuiteInstallation(release)
    installation.verify(_inventory(release.manifest))
    backend = SyntheticMaintenanceBackend()
    maintenance = installation.maintenance_capability(backend)
    source = OpaqueObjectReference("source-1")
    destination = OpaqueObjectReference("backup-1")

    assert maintenance.manifest().digest == release.manifest.digest
    assert maintenance.readiness().status is installation.status
    header = maintenance.envelope_header(source)
    assert header.version == 1
    assert header.algorithm == "AES-256-GCM"
    assert header.schema == "helto.synthetic.v1"
    assert header.opaque_key_id == "opaque-key-1"
    assert "SYNTHETIC_CIPHERTEXT" not in repr(header)
    assert maintenance.opaque_key_available("opaque-key-1") is True

    receipt = maintenance.copy_encrypted(source, destination)
    assert receipt.object_id == "copy-receipt-1"
    assert backend.objects["backup-1"] == backend.objects["source-1"]

    forbidden = {"decrypt", "reveal", "export_key", "live_payload_test"}
    assert forbidden.isdisjoint(dir(maintenance))
