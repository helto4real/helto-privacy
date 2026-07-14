"""Fixed restart-safe participant protocol for shared mode transitions."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Mapping

from .mode import (
    DeclaredPrivacyMode,
    EffectivePrivacyMode,
    ModeTransitionContext,
    normalize_declared_mode,
)
from .mode_values import ModeValueKind, PreparedModeValue


PRODUCT_STATE_KIND = "product-state"
EXTERNAL_WORKFLOW_KIND = "external-workflow"
RECORD_KIND = "record"
SINGLETON_KIND = "singleton"
ARTIFACT_KIND = "artifact"
MODE_SOURCE_KIND = "mode-source"
PARTICIPANT_DISPOSITIONS = frozenset({"prior", "prepared", "target", "final", "diverged"})
MAX_OPAQUE_PLAN_BYTES = 8 * 1024 * 1024


class ModeParticipantError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Privacy mode transition participant is unavailable.")


@dataclass(frozen=True, slots=True)
class ModeSourceSnapshot:
    revision: int
    declared: DeclaredPrivacyMode

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0 or not isinstance(
            self.declared, DeclaredPrivacyMode
        ):
            raise ModeParticipantError("mode_source_snapshot_invalid")

    def to_payload(self) -> dict[str, object]:
        return {"revision": self.revision, "declared": self.declared.value}


def participant_manifest(profile, scope) -> tuple[dict[str, str], ...]:
    """Return a deterministic typed participant list with the source last."""

    values: list[dict[str, str]] = []
    from .profile import ProtectedStateAuthority

    values.extend(
        {
            "id": f"external-workflow.{field.id}",
            "kind": EXTERNAL_WORKFLOW_KIND,
            "fieldId": field.id,
            "adapterId": field.state_adapter,
            "browserAdapterId": field.browser_adapter,
        }
        for field in sorted(profile.protected_fields, key=lambda value: value.id)
        if field.scope_id == scope.id
        and field.state_authority is ProtectedStateAuthority.EXTERNAL_BROWSER_WORKFLOW
    )
    state_adapters = sorted(
        {
            field.state_adapter
            for field in profile.protected_fields
            if field.scope_id == scope.id
            and field.state_authority is ProtectedStateAuthority.SERVER_DURABLE
        }
    )
    values.extend(
        {"id": f"product-state.{adapter_id}", "kind": PRODUCT_STATE_KIND, "adapterId": adapter_id}
        for adapter_id in state_adapters
    )
    values.extend(
        {
            "id": f"record.{item.resource_id}.{item.id}",
            "kind": RECORD_KIND,
            "resourceId": item.resource_id,
            "declarationId": item.id,
        }
        for item in sorted(profile.records, key=lambda value: (value.resource_id, value.id))
        if item.scope_id == scope.id
    )
    values.extend(
        {
            "id": f"singleton.{item.resource_id}.{item.id}",
            "kind": SINGLETON_KIND,
            "resourceId": item.resource_id,
            "declarationId": item.id,
        }
        for item in sorted(profile.singletons, key=lambda value: (value.resource_id, value.id))
        if item.scope_id == scope.id
    )
    if any(item.scope_id == scope.id for item in profile.artifacts):
        values.append({"id": "artifact.shared", "kind": ARTIFACT_KIND})
    values.append(
        {
            "id": f"mode-source.{scope.mode_source_adapter}",
            "kind": MODE_SOURCE_KIND,
            "adapterId": scope.mode_source_adapter,
        }
    )
    return tuple(values)


def prepare_participant_plans(installation, scope, context: ModeTransitionContext):
    """Capture every plan without mutating an authoritative representation."""

    from .artifacts import plan_artifact_mode_transition
    from .records import prepare_record_mode_transition_value
    from .singletons import SingletonError, prepare_singleton_mode_transition_value

    plans: list[dict[str, object]] = []
    manifest = participant_manifest(installation.profile, scope)
    if context.prior_mode is context.target_mode:
        manifest = manifest[-1:]
    for declaration in manifest:
        kind = declaration["kind"]
        item: dict[str, object] = dict(declaration)
        if kind == EXTERNAL_WORKFLOW_KIND:
            item["ownerIdentity"] = "graph-node-field-v1"
        elif kind == PRODUCT_STATE_KIND:
            adapter = installation.adapters[declaration["adapterId"]]
            item["plan"] = _opaque_plan(adapter.plan_mode_transition(context))
        elif kind == RECORD_KIND:
            record = next(value for value in installation.profile.records if value.id == declaration["declarationId"])
            adapter = installation.adapters[record.store_adapter]
            try:
                record_ids = tuple(sorted(str(value) for value in adapter.list_ids()))
            except Exception:
                raise ModeParticipantError("mode_record_inventory_failed") from None
            if len(record_ids) != len(set(record_ids)):
                raise ModeParticipantError("mode_record_inventory_failed")
            item["values"] = [
                _record_to_payload(
                    prepare_record_mode_transition_value(
                        profile=installation.profile,
                        adapters=installation.adapters,
                        resource_id=record.resource_id,
                        record_kind=record.id,
                        record_id=record_id,
                        prior_mode=context.prior_mode,
                        target_mode=context.target_mode,
                    )
                )
                for record_id in record_ids
            ]
        elif kind == SINGLETON_KIND:
            singleton = next(value for value in installation.profile.singletons if value.id == declaration["declarationId"])
            try:
                value = prepare_singleton_mode_transition_value(
                    profile=installation.profile,
                    adapters=installation.adapters,
                    resource_id=singleton.resource_id,
                    singleton_id=singleton.id,
                    prior_mode=context.prior_mode,
                    target_mode=context.target_mode,
                )
            except SingletonError as exc:
                if exc.code == "PRIVACY_SINGLETON_NOT_FOUND":
                    item["value"] = None
                else:
                    raise
            else:
                item["value"] = _singleton_to_payload(value)
        elif kind == ARTIFACT_KIND:
            item["plan"] = _artifact_to_payload(
                plan_artifact_mode_transition(installation, scope.id, context)
            )
        elif kind == MODE_SOURCE_KIND:
            adapter = installation.adapters[declaration["adapterId"]]
            prior = mode_source_snapshot(adapter.read_mode_source(scope.id))
            if prior.declared is not normalize_declared_mode(
                adapter.read_declared_mode(scope.id)
            ):
                raise ModeParticipantError("mode_source_snapshot_invalid")
            item["prior"] = prior.to_payload()
            item["targetDeclared"] = context.target_declared.value
        plans.append(item)
    _bounded_json(plans)
    return plans


def prepare_participant(installation, scope_id: str, context, item: Mapping[str, object]) -> None:
    from .artifacts import prepare_artifact_mode_transition

    kind = str(item["kind"])
    if kind == PRODUCT_STATE_KIND:
        _adapter(installation, item).prepare_mode_transition(context, _opaque_plan(item["plan"]))
    elif kind == ARTIFACT_KIND:
        prepare_artifact_mode_transition(installation, _artifact_from_payload(item["plan"]))
    elif kind in {RECORD_KIND, SINGLETON_KIND, MODE_SOURCE_KIND}:
        return
    else:
        raise ModeParticipantError("mode_participant_invalid")


def verify_prepared_participant(installation, context, item: Mapping[str, object]) -> None:
    from .artifacts import (
        ArtifactModeTransitionDisposition,
        classify_artifact_mode_transition,
    )

    kind = str(item["kind"])
    if kind == PRODUCT_STATE_KIND:
        adapter = _adapter(installation, item)
        plan = _opaque_plan(item["plan"])
        if _disposition(adapter.classify_mode_transition(context, plan)) not in {"prior", "prepared"}:
            raise ModeParticipantError("mode_participant_diverged")
        if adapter.verify_mode_transition(context, plan, "prepared") is not True:
            raise ModeParticipantError("mode_participant_verify_failed")
    elif kind == ARTIFACT_KIND:
        plan = _artifact_from_payload(item["plan"])
        states = classify_artifact_mode_transition(installation, plan)
        if any(value not in {ArtifactModeTransitionDisposition.PRIOR, ArtifactModeTransitionDisposition.PREPARED} for value in states):
            raise ModeParticipantError("mode_participant_diverged")


def commit_participant(installation, context, item: Mapping[str, object]) -> None:
    from .artifacts import commit_artifact_mode_transition
    from .records import commit_record_mode_transition_value
    from .singletons import commit_singleton_mode_transition_value

    kind = str(item["kind"])
    if kind == PRODUCT_STATE_KIND:
        adapter = _adapter(installation, item)
        plan = _opaque_plan(item["plan"])
        adapter.commit_mode_transition(context, plan)
        if _disposition(adapter.classify_mode_transition(context, plan)) not in {"target", "final"}:
            raise ModeParticipantError("mode_participant_verify_failed")
        if adapter.verify_mode_transition(context, plan, "target") is not True:
            raise ModeParticipantError("mode_participant_verify_failed")
    elif kind == RECORD_KIND:
        for value in item.get("values", []):
            transition = _record_from_payload(value)
            commit_record_mode_transition_value(
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=str(item["resourceId"]),
                record_kind=str(item["declarationId"]),
                transition=transition,
            )
    elif kind == SINGLETON_KIND and item.get("value") is not None:
        commit_singleton_mode_transition_value(
            profile=installation.profile,
            adapters=installation.adapters,
            resource_id=str(item["resourceId"]),
            transition=_singleton_from_payload(item["value"]),
        )
    elif kind == ARTIFACT_KIND:
        commit_artifact_mode_transition(installation, _artifact_from_payload(item["plan"]))
    elif kind == MODE_SOURCE_KIND:
        adapter = _adapter(installation, item)
        prior = mode_source_snapshot(item["prior"])
        target = mode_source_snapshot(
            adapter.compare_and_set_mode_source(
                context.scope_id,
                prior.revision,
                prior.declared,
                DeclaredPrivacyMode(str(item["targetDeclared"])),
            )
        )
        if target.revision != prior.revision + 1 or target.declared is not context.target_declared:
            raise ModeParticipantError("mode_source_cas_failed")
        if isinstance(item, dict):
            item["target"] = target.to_payload()
        if _disposition(adapter.classify_mode_source(context.scope_id, prior.to_payload(), target.to_payload())) != "target":
            raise ModeParticipantError("mode_source_cas_failed")
    else:
        raise ModeParticipantError("mode_participant_invalid")


def rollback_participant(installation, context, item: Mapping[str, object]) -> None:
    from .artifacts import rollback_artifact_mode_transition
    from .records import rollback_record_mode_transition_value
    from .singletons import rollback_singleton_mode_transition_value

    kind = str(item["kind"])
    if kind == PRODUCT_STATE_KIND:
        adapter = _adapter(installation, item)
        plan = _opaque_plan(item["plan"])
        adapter.rollback_mode_transition(context, plan)
        if _disposition(adapter.classify_mode_transition(context, plan)) != "prior":
            raise ModeParticipantError("mode_participant_rollback_failed")
    elif kind == RECORD_KIND:
        for value in reversed(item.get("values", [])):
            rollback_record_mode_transition_value(
                profile=installation.profile,
                adapters=installation.adapters,
                resource_id=str(item["resourceId"]),
                record_kind=str(item["declarationId"]),
                transition=_record_from_payload(value),
            )
    elif kind == SINGLETON_KIND and item.get("value") is not None:
        rollback_singleton_mode_transition_value(
            profile=installation.profile,
            adapters=installation.adapters,
            resource_id=str(item["resourceId"]),
            transition=_singleton_from_payload(item["value"]),
        )
    elif kind == ARTIFACT_KIND:
        rollback_artifact_mode_transition(installation, _artifact_from_payload(item["plan"]))
    elif kind == MODE_SOURCE_KIND:
        if item.get("target") is None:
            return
        adapter = _adapter(installation, item)
        restored = mode_source_snapshot(
            adapter.rollback_mode_source(context.scope_id, item["target"], item["prior"])
        )
        prior = mode_source_snapshot(item["prior"])
        if restored.declared is not prior.declared:
            raise ModeParticipantError("mode_source_rollback_failed")
    else:
        raise ModeParticipantError("mode_participant_invalid")


def retire_participant(installation, context, item: Mapping[str, object]) -> None:
    from .artifacts import retire_artifact_mode_transition

    kind = str(item["kind"])
    if kind == PRODUCT_STATE_KIND:
        adapter = _adapter(installation, item)
        plan = _opaque_plan(item["plan"])
        adapter.retire_mode_transition(context, plan)
        if _disposition(adapter.classify_mode_transition(context, plan)) != "final":
            raise ModeParticipantError("mode_participant_retire_failed")
    elif kind == ARTIFACT_KIND:
        retire_artifact_mode_transition(installation, _artifact_from_payload(item["plan"]))


def mode_source_snapshot(value: object) -> ModeSourceSnapshot:
    if not isinstance(value, Mapping) or set(value) != {"revision", "declared"}:
        raise ModeParticipantError("mode_source_snapshot_invalid")
    try:
        return ModeSourceSnapshot(int(value["revision"]), DeclaredPrivacyMode(str(value["declared"])))
    except (TypeError, ValueError):
        raise ModeParticipantError("mode_source_snapshot_invalid") from None


def _adapter(installation, item: Mapping[str, object]):
    try:
        return installation.adapters[str(item["adapterId"])]
    except Exception:
        raise ModeParticipantError("mode_participant_invalid") from None


def _opaque_plan(value: object) -> object:
    try:
        encoded = _bounded_json(value)
        return json.loads(encoded)
    except ModeParticipantError:
        raise
    except Exception:
        raise ModeParticipantError("mode_participant_plan_invalid") from None


def _bounded_json(value: object) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except Exception:
        raise ModeParticipantError("mode_participant_plan_invalid") from None
    if len(encoded.encode("utf-8")) > MAX_OPAQUE_PLAN_BYTES:
        raise ModeParticipantError("mode_participant_plan_too_large")
    return encoded


def _disposition(value: object) -> str:
    normalized = str(value)
    if normalized not in PARTICIPANT_DISPOSITIONS:
        raise ModeParticipantError("mode_participant_disposition_invalid")
    return normalized


def _prepared_to_payload(value: PreparedModeValue) -> dict[str, object]:
    return {
        "kind": value.kind.value,
        "priorMode": value.prior_mode.value,
        "targetMode": value.target_mode.value,
        "original": copy.deepcopy(value.original),
        "target": copy.deepcopy(value.target),
        "normalizedDigest": value.normalized_digest,
    }


def _prepared_from_payload(value: object) -> PreparedModeValue:
    if not isinstance(value, Mapping):
        raise ModeParticipantError("mode_participant_plan_invalid")
    return PreparedModeValue(
        ModeValueKind(str(value["kind"])),
        EffectivePrivacyMode(str(value["priorMode"])),
        EffectivePrivacyMode(str(value["targetMode"])),
        value["original"], value["target"], str(value["normalizedDigest"]),
    )


def _record_to_payload(value: RecordModeTransitionValue) -> dict[str, object]:
    return {
        "recordId": value.record_id,
        "original": {"revision": value.original.revision, "protected": value.original.protected},
        "target": {"revision": value.target.revision, "protected": value.target.protected},
        "prepared": _prepared_to_payload(value.prepared),
    }


def _record_from_payload(value: object) -> RecordModeTransitionValue:
    from .records import RecordModeTransitionValue, RecordSnapshot

    if not isinstance(value, Mapping) or not isinstance(value.get("original"), Mapping) or not isinstance(value.get("target"), Mapping):
        raise ModeParticipantError("mode_participant_plan_invalid")
    original, target = value["original"], value["target"]
    return RecordModeTransitionValue(
        str(value["recordId"]),
        RecordSnapshot(int(original["revision"]), original["protected"]),
        RecordSnapshot(int(target["revision"]), target["protected"]),
        _prepared_from_payload(value["prepared"]),
    )


def _singleton_to_payload(value: SingletonModeTransitionValue) -> dict[str, object]:
    return {
        "singletonId": value.singleton_id,
        "original": {"revision": value.original.revision, "protected": value.original.protected},
        "target": {"revision": value.target.revision, "protected": value.target.protected},
        "prepared": _prepared_to_payload(value.prepared),
    }


def _singleton_from_payload(value: object) -> SingletonModeTransitionValue:
    from .singletons import SingletonModeTransitionValue, SingletonSnapshot

    if not isinstance(value, Mapping) or not isinstance(value.get("original"), Mapping) or not isinstance(value.get("target"), Mapping):
        raise ModeParticipantError("mode_participant_plan_invalid")
    original, target = value["original"], value["target"]
    return SingletonModeTransitionValue(
        str(value["singletonId"]),
        SingletonSnapshot(int(original["revision"]), original["protected"]),
        SingletonSnapshot(int(target["revision"]), target["protected"]),
        _prepared_from_payload(value["prepared"]),
    )


def _artifact_to_payload(value: ArtifactModeTransitionPlan) -> dict[str, object]:
    return {
        "packId": value.pack_id,
        "profileFingerprint": value.profile_fingerprint,
        "scopeId": value.scope_id,
        "transitionId": value.transition_id,
        "priorMode": value.prior_mode.value,
        "targetMode": value.target_mode.value,
        "items": [
            {
                "artifactId": item.artifact_id,
                "artifactKind": item.artifact_kind,
                "resourceId": item.resource_id,
                "ownerId": item.owner_id,
                "retention": item.retention,
                "action": item.action,
                "expectedRevision": item.expected_revision,
                "priorFileDigest": item.prior_file_digest,
                "payloadDigest": item.payload_digest,
                "targetFileDigest": item.target_file_digest,
            }
            for item in value.items
        ],
    }


def _artifact_from_payload(value: object) -> ArtifactModeTransitionPlan:
    from .artifacts import ArtifactModeTransitionItem, ArtifactModeTransitionPlan

    if not isinstance(value, Mapping) or not isinstance(value.get("items"), list):
        raise ModeParticipantError("mode_participant_plan_invalid")
    return ArtifactModeTransitionPlan(
        str(value["packId"]), str(value["profileFingerprint"]), str(value["scopeId"]),
        str(value["transitionId"]), EffectivePrivacyMode(str(value["priorMode"])),
        EffectivePrivacyMode(str(value["targetMode"])),
        tuple(
            ArtifactModeTransitionItem(
                str(item["artifactId"]), str(item["artifactKind"]), str(item["resourceId"]),
                str(item["ownerId"]), str(item["retention"]), str(item["action"]),
                int(item["expectedRevision"]), str(item["priorFileDigest"]),
                (str(item["payloadDigest"]) if item.get("payloadDigest") is not None else None),
                (str(item["targetFileDigest"]) if item.get("targetFileDigest") is not None else None),
            )
            for item in value["items"]
        ),
    )
