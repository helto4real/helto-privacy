"""Package-content checks that reject duplicated consumer privacy engines."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .._suite_codec import canonical_json_bytes, is_stable_id
from .models import AcceptanceError


@dataclass(frozen=True, slots=True)
class StaticCheckRule:
    id: str
    pattern: str

    def __post_init__(self) -> None:
        if not is_stable_id(self.id) or not isinstance(self.pattern, str) or not self.pattern:
            raise AcceptanceError("invalid_static_check_rule")
        try:
            re.compile(self.pattern)
        except re.error:
            raise AcceptanceError("invalid_static_check_rule") from None


@dataclass(frozen=True, slots=True)
class StaticCheckViolation:
    rule_id: str
    source_id: str


DEFAULT_CONSUMER_PRIVACY_RULES = (
    StaticCheckRule("consumer-aes-implementation", r"\bAESGCM\s*\("),
    StaticCheckRule(
        "consumer-codec-definition",
        r"(?:def\s+(?:encrypt|decrypt)_(?:state|bytes)|function\s+(?:encrypt|decrypt)(?:State|Bytes))\s*\(",
    ),
    StaticCheckRule(
        "consumer-token-authority",
        r"(?:PRIVACY_TOKEN_(?:HEADER|COOKIE)\s*=|helto_privacy_token\s*=)",
    ),
    StaticCheckRule(
        "consumer-vendored-fallback",
        r"(?:_vendored_keystore|helto_privacy_compat|vendored[_-]privacy)",
    ),
    StaticCheckRule(
        "consumer-local-privacy-route",
        r"/(?:privacy|helto_privacy)/(?:encrypt|decrypt|unlock|lock|keystore)",
    ),
)


def scan_consumer_privacy_duplication(
    sources: Mapping[str, str | bytes],
    rules: Iterable[StaticCheckRule] = DEFAULT_CONSUMER_PRIVACY_RULES,
) -> tuple[StaticCheckViolation, ...]:
    if not isinstance(sources, Mapping):
        raise AcceptanceError("invalid_static_source_set")
    rule_values = tuple(rules)
    if any(not isinstance(rule, StaticCheckRule) for rule in rule_values):
        raise AcceptanceError("invalid_static_check_rule")
    violations: list[StaticCheckViolation] = []
    for source_id, payload in sources.items():
        if not isinstance(source_id, str) or not source_id or not isinstance(payload, (str, bytes)):
            raise AcceptanceError("invalid_static_source_set")
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
        for rule in rule_values:
            if re.search(rule.pattern, text, flags=re.MULTILINE):
                violations.append(StaticCheckViolation(rule.id, source_id))
    return tuple(sorted(violations, key=lambda item: (item.rule_id, item.source_id)))


def static_check_digest(violations: Iterable[StaticCheckViolation]) -> str:
    values = tuple(violations)
    if any(not isinstance(item, StaticCheckViolation) for item in values):
        raise AcceptanceError("invalid_static_check_result")
    return hashlib.sha256(
        canonical_json_bytes(
            [
                {"ruleId": item.rule_id, "sourceId": item.source_id}
                for item in sorted(values, key=lambda item: (item.rule_id, item.source_id))
            ]
        )
    ).hexdigest()
