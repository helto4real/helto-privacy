import pytest

from helto_privacy.profile import (
    PRIVACY_CONTRACT_V2,
    AdapterSlot,
    FieldLocation,
    FieldLocationKind,
    PrivacyProfile,
    PrivacyScope,
    ProtectedField,
    ProfileValidationError,
    ProfileResource,
    ResourceKind,
)


def test_profile_fingerprint_is_stable_and_order_independent():
    profile = PrivacyProfile(
        id="helto.director",
        distribution="comfyui-helto-director",
        contract=PRIVACY_CONTRACT_V2,
        resources=(
            ProfileResource(
                id="privacy-mode",
                kind=ResourceKind.MODE,
                adapter_slots=("privacy-mode-runtime",),
            ),
            ProfileResource(
                id="timeline",
                kind=ResourceKind.WORKFLOW,
                adapter_slots=("timeline-runtime", "timeline-editor"),
            ),
        ),
        server_adapters=(
            AdapterSlot(
                id="privacy-mode-runtime",
                capability=ResourceKind.MODE,
                resource_id="privacy-mode",
            ),
            AdapterSlot(
                id="timeline-runtime",
                capability=ResourceKind.WORKFLOW,
                resource_id="timeline",
            ),
        ),
        browser_adapters=(
            AdapterSlot(
                id="timeline-editor",
                capability=ResourceKind.WORKFLOW,
                resource_id="timeline",
                node_types=("HeltoTimeline",),
            ),
        ),
        scopes=(
            PrivacyScope(
                id="project",
                mode_resource_id="privacy-mode",
                mode_source_adapter="privacy-mode-runtime",
            ),
        ),
        protected_fields=(
            ProtectedField(
                id="timeline-state",
                workflow_resource_id="timeline",
                scope_id="project",
                node_types=("HeltoTimeline",),
                location=FieldLocation(FieldLocationKind.WIDGET, "timeline_data"),
                current_schema="helto.director.timeline.v2",
                purpose="timeline-state",
                legacy_reader_ids=("director-timeline-v1",),
                execution=True,
            ),
        ),
    )

    assert profile.fingerprint == "72bb529f716d344676041442d71ed612290e92876efd52eaad615a4dbf116eac"

    reordered = PrivacyProfile(
        id="helto.director",
        distribution="comfyui-helto-director",
        contract=PRIVACY_CONTRACT_V2,
        resources=(
            ProfileResource(
                id="privacy-mode",
                kind=ResourceKind.MODE,
                adapter_slots=("privacy-mode-runtime",),
            ),
            ProfileResource(
                id="timeline",
                kind=ResourceKind.WORKFLOW,
                adapter_slots=("timeline-editor", "timeline-runtime"),
            ),
        ),
        server_adapters=profile.server_adapters,
        browser_adapters=profile.browser_adapters,
        scopes=profile.scopes,
        protected_fields=profile.protected_fields,
    )

    assert reordered.fingerprint == profile.fingerprint


@pytest.mark.parametrize(
    ("profile_kwargs", "error_code"),
    [
        ({"contract": "consumer-selectable-contract"}, "contract_mismatch"),
        (
            {
                "resources": (
                    ProfileResource("timeline", ResourceKind.WORKFLOW),
                    ProfileResource("timeline", ResourceKind.WORKFLOW),
                ),
            },
            "duplicate_resource",
        ),
        (
            {
                "resources": (
                    ProfileResource(
                        "timeline",
                        ResourceKind.WORKFLOW,
                        adapter_slots=("missing-adapter",),
                    ),
                ),
            },
            "unknown_adapter_slot",
        ),
        (
            {
                "resources": (ProfileResource("timeline", ResourceKind.WORKFLOW),),
                "server_adapters": (
                    AdapterSlot("timeline-store", ResourceKind.RECORD, "timeline"),
                ),
            },
            "adapter_capability_mismatch",
        ),
        ({}, "partial_profile"),
        (
            {"resources": (ProfileResource("timeline", ResourceKind.WORKFLOW),)},
            "partial_profile",
        ),
        (
            {
                "resources": (ProfileResource("timeline", ResourceKind.WORKFLOW),),
                "server_adapters": (
                    AdapterSlot("timeline-store", ResourceKind.WORKFLOW, "timeline"),
                ),
            },
            "unbound_adapter_slot",
        ),
        (
            {
                "resources": (
                    ProfileResource("privacy-mode", ResourceKind.MODE, ("mode-source",)),
                ),
                "server_adapters": (
                    AdapterSlot("mode-source", ResourceKind.MODE, "privacy-mode"),
                ),
            },
            "missing_resource_product_facts",
        ),
    ],
)
def test_profile_rejects_incomplete_or_unknown_declarations(profile_kwargs, error_code):
    with pytest.raises(ProfileValidationError) as exc_info:
        PrivacyProfile(
            id="helto.director",
            distribution="comfyui-helto-director",
            **profile_kwargs,
        )

    assert exc_info.value.code == error_code
    assert "helto.director" not in str(exc_info.value)
