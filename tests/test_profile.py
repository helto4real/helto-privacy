import pytest

from helto_privacy.profile import (
    PRIVACY_CONTRACT_V2,
    AdapterSlot,
    PrivacyProfile,
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
                id="timeline",
                kind=ResourceKind.WORKFLOW,
                adapter_slots=("timeline-runtime", "timeline-editor"),
            ),
        ),
        server_adapters=(
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
    )

    assert profile.fingerprint == "32933c25bf77db99876cbbc40deea71c97baf88bda38cd8f3ab86c7b06ab8e5c"

    reordered = PrivacyProfile(
        id="helto.director",
        distribution="comfyui-helto-director",
        contract=PRIVACY_CONTRACT_V2,
        resources=(
            ProfileResource(
                id="timeline",
                kind=ResourceKind.WORKFLOW,
                adapter_slots=("timeline-editor", "timeline-runtime"),
            ),
        ),
        server_adapters=profile.server_adapters,
        browser_adapters=profile.browser_adapters,
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
