import pytest

from helto_privacy.profile import (
    PRIVACY_CONTRACT_V2,
    AdapterSlot,
    ArtifactDeclaration,
    ArtifactRetention,
    FieldLocation,
    FieldLocationKind,
    LegacyLocationKind,
    LegacyReaderBinding,
    PrivacyProfile,
    PrivacyScope,
    ProtectedField,
    ProtectedOperation,
    ProfileValidationError,
    ProfileResource,
    RecordDeclaration,
    RecordRevealProjection,
    ResourceKind,
)


def test_artifact_operations_must_use_the_typed_lease_contract():
    with pytest.raises(ProfileValidationError) as generic:
        PrivacyProfile(
            id="helto.artifact-contract",
            distribution="comfyui-artifact-contract",
            resources=(
                ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
                ProfileResource("media", ResourceKind.ARTIFACT, ("artifact",)),
            ),
            server_adapters=(
                AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
                AdapterSlot("artifact", ResourceKind.ARTIFACT, "media"),
            ),
            scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
            artifacts=(
                ArtifactDeclaration(
                    "thumbnail",
                    "media",
                    "main",
                    "thumbnail",
                    "artifact",
                    1,
                    ArtifactRetention.REGENERABLE_CACHE,
                    ("preview",),
                    media_type="image/webp",
                ),
            ),
            protected_operations=(
                ProtectedOperation(
                    "artifact.preview",
                    "media",
                    "artifact",
                    "/consumer/private-preview",
                ),
            ),
        )

    assert generic.value.code == "artifact_operation_must_use_typed_contract"


def test_record_reveal_contract_requires_explicit_fields_and_fixed_operations():
    with pytest.raises(ProfileValidationError) as missing_fields:
        RecordRevealProjection("use", ())
    assert missing_fields.value.code == "invalid_safe_projection_field"

    with pytest.raises(ProfileValidationError) as unsupported_operation:
        RecordRevealProjection("merge", ("prompt",))
    assert unsupported_operation.value.code == "invalid_record_reveal_operation"

    with pytest.raises(ProfileValidationError) as duplicate_operation:
        RecordDeclaration(
            "prompt-record",
            "library",
            "main",
            "helto.record.v1",
            "records",
            projections=(
                RecordRevealProjection("use", ("prompt",)),
                RecordRevealProjection("use", ("summary",)),
            ),
        )
    assert duplicate_operation.value.code == "duplicate_record_reveal_operation"

    declaration = RecordDeclaration(
        "prompt-record",
        "library",
        "main",
        "helto.record.v1",
        "records",
        projections=(
            RecordRevealProjection("use", ("prompt",)),
            RecordRevealProjection("details", ("summary",)),
        ),
    )
    assert declaration.reveal_operations == ("details", "use")


def test_protected_operation_compiles_a_fixed_same_origin_route_contract():
    operation = ProtectedOperation(
        "record.use",
        "library",
        "library-adapter",
        "/helto-example/records/use",
        "post",
    )

    assert operation.route == "/helto-example/records/use"
    assert operation.method == "POST"

    with pytest.raises(ProfileValidationError) as external:
        ProtectedOperation(
            "record.use",
            "library",
            "library-adapter",
            "https://example.com/records/use",
        )
    assert external.value.code == "invalid_protected_operation_route"

    with pytest.raises(ProfileValidationError) as templated:
        ProtectedOperation(
            "record.use",
            "library",
            "library-adapter",
            "/records/{record_id}",
        )
    assert templated.value.code == "invalid_protected_operation_route"


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
                state_adapter="timeline-runtime",
                browser_adapter="timeline-editor",
                node_types=("HeltoTimeline",),
                location=FieldLocation(FieldLocationKind.WIDGET, "timeline_data"),
                current_schema="helto.director.timeline.v2",
                purpose="timeline-state",
                legacy_reader_ids=("director-timeline-v1",),
                execution=True,
            ),
        ),
        legacy_bindings=(
            LegacyReaderBinding(
                "director-timeline-v1-binding",
                "director-timeline-v1",
                "timeline",
                LegacyLocationKind.WORKFLOW_FIELD,
                "timeline-state",
            ),
        ),
    )

    assert profile.fingerprint == (
        "de5654bfbc7a7c0e9a47e4854e82a3f707d1db21cca5d9e03a6b730371776d67"
    )

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
        legacy_bindings=profile.legacy_bindings,
    )

    assert reordered.fingerprint == profile.fingerprint

    assert profile.server_adapter_contracts == {
        "privacy-mode-runtime": (
            "commit_mode_transition",
            "prepare_mode_transition",
            "read_declared_mode",
            "rollback_mode_transition",
            "write_declared_mode",
        ),
        "timeline-runtime": (
            "apply_revealed",
            "capture",
            "clear_plaintext",
            "commit_mode_transition",
            "normalize",
            "prepare_mode_transition",
            "rollback_mode_transition",
        ),
    }


def test_protected_field_declares_sorted_distinct_mirror_locations():
    field = ProtectedField(
        id="display-text",
        workflow_resource_id="workflow",
        scope_id="display",
        state_adapter="workflow-state",
        browser_adapter="workflow-browser",
        node_types=("DisplayNode",),
        location=FieldLocation(FieldLocationKind.PROPERTY, "protected_text"),
        current_schema="helto.display",
        purpose="display-text",
        mirror_locations=(
            FieldLocation(FieldLocationKind.WIDGET, "encrypted_text_state"),
        ),
    )

    assert field.mirror_locations == (
        FieldLocation(FieldLocationKind.WIDGET, "encrypted_text_state"),
    )

    with pytest.raises(ProfileValidationError) as duplicate:
        ProtectedField(
            id="display-text",
            workflow_resource_id="workflow",
            scope_id="display",
            state_adapter="workflow-state",
            browser_adapter="workflow-browser",
            node_types=("DisplayNode",),
            location=FieldLocation(FieldLocationKind.PROPERTY, "protected_text"),
            current_schema="helto.display",
            purpose="display-text",
            mirror_locations=(
                FieldLocation(FieldLocationKind.PROPERTY, "protected_text"),
            ),
        )
    assert duplicate.value.code == "duplicate_field_location"


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


def test_profile_rejects_protected_field_without_matching_browser_binding():
    with pytest.raises(ProfileValidationError) as exc_info:
        PrivacyProfile(
            id="helto.browser-drift",
            distribution="comfyui-helto-browser-drift",
            resources=(
                ProfileResource("privacy-mode", ResourceKind.MODE, ("mode-source",)),
                ProfileResource(
                    "editor",
                    ResourceKind.WORKFLOW,
                    ("editor-browser", "editor-runtime"),
                ),
            ),
            server_adapters=(
                AdapterSlot("mode-source", ResourceKind.MODE, "privacy-mode"),
                AdapterSlot("editor-runtime", ResourceKind.WORKFLOW, "editor"),
            ),
            browser_adapters=(
                AdapterSlot(
                    "editor-browser",
                    ResourceKind.WORKFLOW,
                    "editor",
                    ("DifferentNode",),
                ),
            ),
            scopes=(PrivacyScope("editor", "privacy-mode", "mode-source"),),
            protected_fields=(
                ProtectedField(
                    "editor-state",
                    "editor",
                    "editor",
                    "editor-runtime",
                    "editor-browser",
                    ("HeltoEditor",),
                    FieldLocation(FieldLocationKind.WIDGET, "state"),
                    "helto.editor.v1",
                    "editor-state",
                ),
            ),
        )

    assert exc_info.value.code == "field_browser_binding_mismatch"


def test_profile_rejects_browser_adapter_used_as_server_mode_source():
    with pytest.raises(ProfileValidationError) as exc_info:
        PrivacyProfile(
            id="helto.wrong-side",
            distribution="comfyui-helto-wrong-side",
            resources=(
                ProfileResource("privacy-mode", ResourceKind.MODE, ("mode-browser",)),
            ),
            browser_adapters=(
                AdapterSlot(
                    "mode-browser",
                    ResourceKind.MODE,
                    "privacy-mode",
                    ("HeltoWrongSide",),
                ),
            ),
            scopes=(
                PrivacyScope("wrong-side", "privacy-mode", "mode-browser"),
            ),
        )

    assert exc_info.value.code == "resource_adapter_mismatch"
