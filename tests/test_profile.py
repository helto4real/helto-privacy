import pytest

from helto_privacy.profile import (
    PRIVACY_CONTRACT_V3,
    AdapterSlot,
    ArtifactDeclaration,
    ArtifactRetention,
    ExternalOperationBinding,
    ExternalOperationPolicy,
    ExternalTransitionPolicy,
    FieldLocation,
    FieldLocationKind,
    LegacyLocationKind,
    LegacyReaderBinding,
    PrivacyProfile,
    PrivacyScope,
    ProtectedStateAuthority,
    ProtectedField,
    ProtectedOperation,
    ProfileValidationError,
    ProfileResource,
    RecordDeclaration,
    RecordRevealProjection,
    ResourceKind,
    SafeDiagnosticField,
    SafeDiagnosticKind,
    SensitiveFieldClass,
    SensitiveFieldDeclaration,
)


def _protected_field(**overrides):
    values = {
        "id": "workflow-state",
        "workflow_resource_id": "workflow",
        "scope_id": "main",
        "state_adapter": "workflow-state",
        "browser_adapter": "workflow-ui",
        "node_types": ("WorkflowNode",),
        "location": FieldLocation(FieldLocationKind.WIDGET, "state"),
        "current_schema": "helto.workflow.v1",
        "purpose": "workflow-state",
        "state_authority": ProtectedStateAuthority.SERVER_DURABLE,
    }
    values.update(overrides)
    return ProtectedField(**values)


def _external_authority_profile():
    return PrivacyProfile(
        id="helto.external-authority",
        distribution="comfyui-external-authority",
        resources=(
            ProfileResource("privacy-mode", ResourceKind.MODE, ("mode-source",)),
            ProfileResource("workflow", ResourceKind.WORKFLOW, ("workflow-state", "workflow-ui")),
        ),
        server_adapters=(
            AdapterSlot("mode-source", ResourceKind.MODE, "privacy-mode"),
            AdapterSlot("workflow-state", ResourceKind.WORKFLOW, "workflow"),
        ),
        browser_adapters=(
            AdapterSlot("workflow-ui", ResourceKind.WORKFLOW, "workflow", ("WorkflowNode",)),
        ),
        scopes=(PrivacyScope("main", "privacy-mode", "mode-source"),),
        protected_fields=(
            _protected_field(
                state_authority=ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW,
                external_transition_policy=ExternalTransitionPolicy(
                    max_owners=7,
                    max_original_bytes_per_owner=2048,
                    max_target_bytes_per_owner=4096,
                    max_total_bytes=16384,
                    lease_seconds=90,
                ),
            ),
        ),
    )


def test_protected_field_requires_explicit_state_authority():
    with pytest.raises(TypeError):
        ProtectedField(
            "workflow-state",
            "workflow",
            "main",
            "workflow-state",
            "workflow-ui",
            ("WorkflowNode",),
            FieldLocation(FieldLocationKind.WIDGET, "state"),
            "helto.workflow.v1",
            "workflow-state",
        )


def test_external_authority_requires_policy_and_server_authority_forbids_it():
    with pytest.raises(ProfileValidationError) as missing:
        _protected_field(
            state_authority=ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW,
        )
    assert missing.value.code == "missing_external_transition_policy"

    with pytest.raises(ProfileValidationError) as unexpected:
        _protected_field(external_transition_policy=ExternalTransitionPolicy())
    assert unexpected.value.code == "unexpected_external_transition_policy"


@pytest.mark.parametrize(
    "overrides",
    [
        {"owner_identity": "graph-node-v0"},
        {"max_owners": 0},
        {"max_owners": 4097},
        {"max_original_bytes_per_owner": 1023},
        {"max_original_bytes_per_owner": 16 * 1024 * 1024 + 1},
        {"max_target_bytes_per_owner": 1023},
        {"max_target_bytes_per_owner": 16 * 1024 * 1024 + 1},
        {"max_total_bytes": 1023},
        {"max_total_bytes": 64 * 1024 * 1024 + 1},
        {"lease_seconds": 29},
        {"lease_seconds": 901},
    ],
)
def test_external_transition_policy_rejects_every_out_of_bounds_field(overrides):
    with pytest.raises(ProfileValidationError) as invalid:
        ExternalTransitionPolicy(**overrides)
    assert invalid.value.code == "invalid_external_transition_policy"


def test_external_authority_contract_attests_distinct_exact_bounds_and_adapter_seams():
    profile = _external_authority_profile()
    field = profile.protected_fields[0]

    assert field.contract_payload()["externalTransitionPolicy"] == {
        "ownerIdentity": "graph-node-field-v1",
        "maxOwners": 7,
        "maxOriginalBytesPerOwner": 2048,
        "maxTargetBytesPerOwner": 4096,
        "maxTotalBytes": 16384,
        "leaseSeconds": 90,
    }
    assert {
        "classify_mode_transition_representation",
        "decode_mode_transition_representation",
        "normalize_mode_transition_value",
        "encode_public_mode_transition",
    }.issubset(profile.server_adapter_contracts["workflow-state"])
    assert {
        "settleModeTransition",
        "inventoryModeTransitionOwners",
        "readModeTransitionOwnerExact",
        "applyModeTransitionOwnerExact",
        "extractDetachedModeTransitionOwnerExact",
        "restoreModeTransitionOwnerExact",
        "reloadModeTransitionRuntime",
        "reconcileModeTransitionRuntime",
    }.issubset(profile.browser_adapter_contracts["workflow-ui"])
    assert "planModeTransition" not in profile.browser_adapter_contracts["workflow-ui"]


def _external_operation_profile():
    base = _external_authority_profile()
    return PrivacyProfile(
        id=base.id,
        distribution=base.distribution,
        resources=(
            *base.resources,
            ProfileResource(
                "operations",
                ResourceKind.OPERATION,
                ("operation-adapter",),
            ),
        ),
        server_adapters=(
            *base.server_adapters,
            AdapterSlot(
                "operation-adapter",
                ResourceKind.OPERATION,
                "operations",
            ),
        ),
        browser_adapters=base.browser_adapters,
        scopes=base.scopes,
        protected_fields=base.protected_fields,
        protected_operations=(
            ProtectedOperation(
                "associate-captured-take",
                "operations",
                "operation-adapter",
                None,
                scope_id="main",
                sensitive_fields=(
                    SensitiveFieldDeclaration(
                        "*",
                        SensitiveFieldClass.CONSUMER_DERIVED,
                    ),
                ),
                safe_projection=(
                    SafeDiagnosticField("items", SafeDiagnosticKind.COUNT),
                ),
                external_operation_binding=ExternalOperationBinding(
                    "workflow-state",
                    "workflow-ui",
                    ExternalOperationPolicy(
                        max_identity_bytes=2048,
                        max_original_bytes=4096,
                        max_target_bytes=8192,
                        lease_seconds=60,
                    ),
                ),
            ),
        ),
    )


def test_external_operation_binding_is_canonical_and_compiles_fixed_adapters():
    profile = _external_operation_profile()
    operation = profile._canonical_value()["protectedOperations"][0]

    assert operation["route"] is None
    assert operation["externalOperationBinding"] == {
        "fieldId": "workflow-state",
        "browserAdapter": "workflow-ui",
        "policy": {
            "ownerIdentity": "graph-node-v1",
            "maxIdentityBytes": 2048,
            "maxOriginalBytes": 4096,
            "maxTargetBytes": 8192,
            "leaseSeconds": 60,
        },
    }
    assert {
        "capture_external_operation",
        "classify_external_operation",
        "prepare_external_operation",
        "finalize_external_operation",
        "rollback_external_operation",
    }.issubset(profile.server_adapter_contracts["operation-adapter"])
    assert {
        "settleExternalOperation",
        "identifyExternalOperationOwner",
        "resolveExternalOperationOwner",
        "readExternalOperationExact",
        "applyExternalOperation",
        "restoreExternalOperationExact",
        "reloadExternalOperationRuntime",
        "reconcileExternalOperationRuntime",
    }.issubset(profile.browser_adapter_contracts["workflow-ui"])


def test_external_operation_requires_an_external_browser_field_and_no_normal_route():
    base = _external_operation_profile()
    operation = base.protected_operations[0]

    with pytest.raises(ProfileValidationError) as routed:
        ProtectedOperation(
            operation.id,
            operation.resource_id,
            operation.adapter_slot,
            "/director/capture",
            scope_id=operation.scope_id,
            sensitive_fields=operation.sensitive_fields,
            safe_projection=operation.safe_projection,
            external_operation_binding=operation.external_operation_binding,
        )
    assert routed.value.code == "invalid_external_operation_binding"

    server_field = _protected_field()
    with pytest.raises(ProfileValidationError) as authority:
        PrivacyProfile(
            id=base.id,
            distribution=base.distribution,
            resources=base.resources,
            server_adapters=base.server_adapters,
            browser_adapters=base.browser_adapters,
            scopes=base.scopes,
            protected_fields=(server_field,),
            protected_operations=base.protected_operations,
        )
    assert authority.value.code == "external_operation_binding_mismatch"


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


def test_duplicate_record_reader_binding_is_rejected():
    binding = LegacyReaderBinding(
        "record-v1-binding",
        "record-v1",
        "library",
        LegacyLocationKind.RECORD,
        "prompt-record",
    )
    with pytest.raises(ProfileValidationError) as duplicate:
        PrivacyProfile(
            id="helto.record-binding-test",
            distribution="comfyui-record-binding-test",
            resources=(
                ProfileResource("privacy-mode", ResourceKind.MODE, ("mode",)),
                ProfileResource("library", ResourceKind.RECORD, ("records",)),
            ),
            server_adapters=(
                AdapterSlot("mode", ResourceKind.MODE, "privacy-mode"),
                AdapterSlot("records", ResourceKind.RECORD, "library"),
            ),
            scopes=(PrivacyScope("main", "privacy-mode", "mode"),),
            records=(
                RecordDeclaration(
                    "prompt-record",
                    "library",
                    "main",
                    "helto.record.v2",
                    "records",
                ),
            ),
            legacy_bindings=(
                binding,
                LegacyReaderBinding(
                    "record-v1-binding-copy",
                    binding.reader_id,
                    binding.resource_id,
                    binding.location_kind,
                    binding.location_id,
                ),
            ),
        )

    assert duplicate.value.code == "duplicate_legacy_location_binding"


def test_only_run_scoped_spills_may_omit_browser_operations():
    spill = ArtifactDeclaration(
        "replay-spill",
        "media",
        "main",
        "replay-spill",
        "artifact",
        1,
        ArtifactRetention.RUN_SCOPED_SPILL,
        (),
    )
    assert spill.operations == ()

    with pytest.raises(ProfileValidationError) as missing:
        ArtifactDeclaration(
            "thumbnail",
            "media",
            "main",
            "thumbnail",
            "artifact",
            1,
            ArtifactRetention.REGENERABLE_CACHE,
            (),
            media_type="image/webp",
        )
    assert missing.value.code == "missing_artifact_operation"


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

    with pytest.raises(ProfileValidationError) as unsafe_shell:
        RecordDeclaration(
            "prompt-record",
            "library",
            "main",
            "helto.record.v1",
            "records",
            safe_projection=("name",),
        )
    assert unsafe_shell.value.code == "unsafe_record_list_projection"

    with pytest.raises(ProfileValidationError) as unsafe_label:
        RecordDeclaration(
            "prompt-record",
            "library",
            "main",
            "helto.record.v1",
            "records",
            fixed_private_label="User-authored name",
        )
    assert unsafe_label.value.code == "invalid_private_record_label"

    with pytest.raises(ProfileValidationError) as unknown_mutation:
        RecordDeclaration(
            "prompt-record",
            "library",
            "main",
            "helto.record.v1",
            "records",
            mutation_operations=("merge",),
        )
    assert unknown_mutation.value.code == "invalid_record_mutation_operation"


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


def test_protected_operation_private_projection_requires_default_sensitive_rule():
    safe = SafeDiagnosticField(
        "performance.configured",
        SafeDiagnosticKind.BOOLEAN,
    )
    with pytest.raises(ProfileValidationError) as missing_scope:
        ProtectedOperation(
            "emit-run-info",
            "run-info",
            "run-info-adapter",
            "/run-info",
            safe_projection=(safe,),
        )
    assert missing_scope.value.code == "missing_protected_operation_scope"

    with pytest.raises(ProfileValidationError) as missing_default:
        ProtectedOperation(
            "emit-run-info",
            "run-info",
            "run-info-adapter",
            "/run-info",
            scope_id="generate",
            sensitive_fields=(
                SensitiveFieldDeclaration("debug", SensitiveFieldClass.DEBUG),
            ),
            safe_projection=(safe,),
        )
    assert missing_default.value.code == "missing_sensitive_default"

    declaration = ProtectedOperation(
        "emit-run-info",
        "run-info",
        "run-info-adapter",
        "/run-info",
        scope_id="generate",
        sensitive_fields=(
            SensitiveFieldDeclaration(
                "*",
                SensitiveFieldClass.CONSUMER_DERIVED,
            ),
            SensitiveFieldDeclaration("debug", SensitiveFieldClass.DEBUG),
        ),
        safe_projection=(safe,),
    )
    assert declaration.safe_projection == (safe,)


def test_backend_only_protected_operation_requires_a_safe_projection():
    with pytest.raises(ProfileValidationError) as missing_projection:
        ProtectedOperation(
            "emit-run-info",
            "run-info",
            "run-info-adapter",
            None,
        )
    assert (
        missing_projection.value.code
        == "missing_protected_operation_projection"
    )


def test_profile_fingerprint_is_stable_and_order_independent():
    profile = PrivacyProfile(
        id="helto.director",
        distribution="comfyui-helto-director",
        contract=PRIVACY_CONTRACT_V3,
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
                state_authority=ProtectedStateAuthority.SERVER_DURABLE,
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
        "82881492a8dd012c4abbe9c7335b359d4183b5850d53e849eea9e2d5aa3e6f5c"
    )

    reordered = PrivacyProfile(
        id="helto.director",
        distribution="comfyui-helto-director",
        contract=PRIVACY_CONTRACT_V3,
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
            "classify_mode_source",
            "compare_and_set_mode_source",
            "read_declared_mode",
            "read_mode_source",
            "rollback_mode_source",
        ),
        "timeline-runtime": (
            "apply_revealed",
            "capture",
            "classify_mode_transition",
            "clear_plaintext",
            "commit_mode_transition",
            "normalize",
            "plan_mode_transition",
            "prepare_mode_transition",
            "retire_mode_transition",
            "rollback_mode_transition",
            "verify_mode_transition",
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
        state_authority=ProtectedStateAuthority.SERVER_DURABLE,
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
            state_authority=ProtectedStateAuthority.SERVER_DURABLE,
            mirror_locations=(
                FieldLocation(FieldLocationKind.PROPERTY, "protected_text"),
            ),
        )
    assert duplicate.value.code == "duplicate_field_location"


@pytest.mark.parametrize(
    ("profile_kwargs", "error_code"),
    [
        ({"contract": "consumer-selectable-contract"}, "contract_mismatch"),
        ({"contract": "helto.privacy.v2"}, "contract_mismatch"),
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
                    ProtectedStateAuthority.SERVER_DURABLE,
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


def test_operation_is_a_complete_product_fact_for_workflow_resource():
    profile = PrivacyProfile(
        id="helto.operation-only-test",
        distribution="comfyui-operation-only-test",
        resources=(
            ProfileResource(
                "operations",
                ResourceKind.WORKFLOW,
                ("operation-adapter",),
            ),
        ),
        server_adapters=(
            AdapterSlot(
                "operation-adapter",
                ResourceKind.WORKFLOW,
                "operations",
            ),
        ),
        protected_operations=(
            ProtectedOperation(
                "source.view",
                "operations",
                "operation-adapter",
                "/operation-only/source/view",
            ),
        ),
    )

    assert profile.protected_operations[0].resource_id == "operations"
