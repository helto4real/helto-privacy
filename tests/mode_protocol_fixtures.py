"""Strict recoverable mode-transition adapters for shared synthetic fixtures."""

from __future__ import annotations

from helto_privacy.mode import DeclaredPrivacyMode, normalize_declared_mode


class ModeSourceProtocolFixture:
    """Revisioned in-memory CAS source used only by synthetic tests."""

    def _mode_revisions(self):
        revisions = getattr(self, "_synthetic_mode_revisions", None)
        if revisions is None:
            revisions = {}
            self._synthetic_mode_revisions = revisions
        return revisions

    def read_mode_source(self, scope_id):
        return {
            "revision": self._mode_revisions().get(scope_id, 0),
            "declared": normalize_declared_mode(self.read_declared_mode(scope_id)).value,
        }

    def compare_and_set_mode_source(
        self,
        scope_id,
        expected_revision,
        expected_declared,
        target_declared,
    ):
        current = self.read_mode_source(scope_id)
        if (
            current["revision"] != expected_revision
            or current["declared"] != normalize_declared_mode(expected_declared).value
        ):
            raise RuntimeError("synthetic mode source conflict")
        self.write_declared_mode(scope_id, normalize_declared_mode(target_declared))
        self._mode_revisions()[scope_id] = expected_revision + 1
        return self.read_mode_source(scope_id)

    def classify_mode_source(self, scope_id, prior, target):
        current = self.read_mode_source(scope_id)
        if current == prior:
            return "prior"
        if current == target:
            return "target"
        return "diverged"

    def rollback_mode_source(self, scope_id, target, prior):
        current = self.read_mode_source(scope_id)
        if current == prior:
            return current
        if current != target:
            raise RuntimeError("synthetic mode source conflict")
        prior_mode = DeclaredPrivacyMode(str(prior["declared"]))
        self.write_declared_mode(scope_id, prior_mode)
        self._mode_revisions()[scope_id] = int(target["revision"]) + 1
        return self.read_mode_source(scope_id)


class MutableModeSourceFixture(ModeSourceProtocolFixture):
    def __init__(self, declared=None):
        self.declared = declared

    def read_declared_mode(self, _scope_id):
        return self.declared

    def write_declared_mode(self, _scope_id, declared):
        self.declared = declared

class ProductStateProtocolFixture:
    """Canonical restart-safe empty plan for fixtures without persisted state."""

    def _transition_states(self):
        states = getattr(self, "_synthetic_transition_states", None)
        if states is None:
            states = {}
            self._synthetic_transition_states = states
        return states

    def plan_mode_transition(self, context):
        return {
            "scopeId": context.scope_id,
            "transitionId": context.transition_id,
            "priorMode": context.prior_mode.value,
            "targetMode": context.target_mode.value,
        }

    def prepare_mode_transition(self, context, plan):
        self._transition_states()[context.transition_id] = "prepared"

    def classify_mode_transition(self, context, plan):
        return self._transition_states().get(context.transition_id, "prior")

    def verify_mode_transition(self, context, plan, expected):
        actual = self.classify_mode_transition(context, plan)
        return actual == expected or (expected == "target" and actual == "final")

    def commit_mode_transition(self, context, plan):
        self._transition_states()[context.transition_id] = "target"

    def rollback_mode_transition(self, context, plan):
        self._transition_states()[context.transition_id] = "prior"

    def retire_mode_transition(self, context, plan):
        self._transition_states()[context.transition_id] = "final"
