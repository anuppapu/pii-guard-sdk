from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .exceptions import InputTooLargeError, PolicyValidationError

Severity = Literal["low", "medium", "high", "critical"]
Action = Literal["allow", "mask", "hash", "redact", "block"]
VALID_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})
VALID_ACTIONS: frozenset[str] = frozenset({"allow", "mask", "hash", "redact", "block"})
SEVERITY_RANK: dict[str, int] = {"low": 10, "medium": 20, "high": 30, "critical": 40}
FLAG_MAP: dict[str, re.RegexFlag] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected value. Do not write ``value`` to logs or telemetry."""

    name: str
    category: str
    severity: Severity
    start: int
    end: int
    value: str
    strategy: Action
    source_field: str | None = None

    @property
    def masked_value(self) -> str:
        return mask_value(self.value)

    def safe_summary(self) -> dict[str, str | int | None]:
        """Return audit-safe metadata without the raw PII value."""
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "strategy": self.strategy,
            "source_field": self.source_field,
            "start": self.start,
            "end": self.end,
            "masked_value": self.masked_value,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]
    sanitized_text: str
    blocked: bool

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)

    @property
    def safe_findings(self) -> tuple[dict[str, str | int | None], ...]:
        return tuple(finding.safe_summary() for finding in self.findings)


@dataclass(frozen=True, slots=True)
class RecordScanResult:
    sanitized_record: dict[str, Any]
    findings: tuple[Finding, ...]
    blocked: bool

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)

    @property
    def safe_findings(self) -> tuple[dict[str, str | int | None], ...]:
        return tuple(finding.safe_summary() for finding in self.findings)


@dataclass(frozen=True, slots=True)
class PatternRule:
    name: str
    category: str
    severity: Severity
    regex: str
    strategy: Action = "redact"
    flags: tuple[str, ...] = ()
    validator: str | None = None
    capture_group: int = 0
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class FieldRule:
    """Protects an entire structured-record field by its field name."""

    name: str
    category: str
    severity: Severity
    strategy: Action
    enabled: bool = True


def mask_value(value: str, visible_tail: int = 4) -> str:
    compact = "".join(value.split())
    if not compact:
        return ""
    if len(compact) <= visible_tail:
        return "*" * len(compact)
    return "*" * (len(compact) - visible_tail) + compact[-visible_tail:]


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def valid_luhn(value: str) -> bool:
    digits = _digits(value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for index, character in enumerate(reversed(digits)):
        digit = int(character)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def valid_iban(value: str) -> bool:
    compact = "".join(value.split()).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for character in rearranged:
        expanded = str(ord(character) - 55) if character.isalpha() else character
        for digit in expanded:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def valid_aba_routing(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 9 or digits == "000000000":
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    return sum(int(digit) * weight for digit, weight in zip(digits, weights, strict=True)) % 10 == 0


def valid_ein(value: str) -> bool:
    """Perform basic US EIN format validation; this does not prove issuance."""
    digits = _digits(value)
    return len(digits) == 9 and digits != "000000000" and not digits.startswith("00")


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "luhn": valid_luhn,
    "iban": valid_iban,
    "aba_routing": valid_aba_routing,
    "ein": valid_ein,
}


class PIIGuard:
    """Thread-safe configurable PII scanner for text and nested CRM records; regex rules identify values in text, field rules protect complete values in structured records; irreversible masking, HMAC hashing, redaction or blocking; no reversible token maps."""

    def __init__(
        self,
        rules: Iterable[PatternRule],
        *,
        field_rules: Mapping[str, FieldRule] | None = None,
        minimum_severity: Severity = "low",
        default_action: Action = "redact",
        hash_key: str | bytes | None = None,
        max_text_length: int = 100_000,
    ) -> None:
        if minimum_severity not in VALID_SEVERITIES:
            raise PolicyValidationError("minimum_severity is invalid")
        if default_action not in VALID_ACTIONS:
            raise PolicyValidationError("default_action is invalid")
        if max_text_length < 1:
            raise PolicyValidationError("max_text_length must be positive")
        self._lock = threading.RLock()
        self.minimum_severity = minimum_severity
        self.default_action = default_action
        self.max_text_length = max_text_length
        self._hash_key = self._normalize_hash_key(hash_key)
        self._rules: list[tuple[PatternRule, re.Pattern[str]]] = []
        self._field_rules: dict[str, FieldRule] = {}
        self.replace_rules(rules)
        self.replace_field_rules(field_rules or {})

    @classmethod
    def from_json(cls, path: str | Path, **kwargs: Any) -> PIIGuard:
        try:
            policy = json.loads(Path(path).read_text(encoding="utf-8"))
        except OSError as exc:
            raise PolicyValidationError(f"Unable to read policy file: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyValidationError(f"Policy is not valid JSON: {exc}") from exc
        if not isinstance(policy, dict):
            raise PolicyValidationError("Policy root must be a JSON object")
        patterns = policy.get("patterns", [])
        if not isinstance(patterns, list):
            raise PolicyValidationError("patterns must be a JSON array")
        rules: list[PatternRule] = []
        for item in patterns:
            if not isinstance(item, dict):
                raise PolicyValidationError("Every pattern must be a JSON object")
            try:
                rules.append(
                    PatternRule(
                        name=str(item["name"]),
                        category=str(item.get("category", "custom")),
                        severity=item.get("severity", "medium"),
                        regex=str(item["regex"]),
                        strategy=item.get("strategy", "redact"),
                        flags=tuple(item.get("flags", [])),
                        validator=item.get("validator"),
                        capture_group=int(item.get("capture_group", 0)),
                        enabled=bool(item.get("enabled", True)),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise PolicyValidationError("Invalid pattern rule configuration") from exc
        sensitive_fields = policy.get("sensitive_fields", {})
        if not isinstance(sensitive_fields, dict):
            raise PolicyValidationError("sensitive_fields must be a JSON object")
        field_rules: dict[str, FieldRule] = {}
        for field_name, item in sensitive_fields.items():
            if not isinstance(item, dict):
                raise PolicyValidationError("Every sensitive field must be a JSON object")
            field_rules[str(field_name).lower()] = FieldRule(
                name=str(item.get("name", f"{field_name}_field")),
                category=str(item.get("category", "crm_sensitive_field")),
                severity=item.get("severity", "high"),
                strategy=item.get("strategy", "redact"),
                enabled=bool(item.get("enabled", True)),
            )
        return cls(rules, field_rules=field_rules, **kwargs)

    @staticmethod
    def _normalize_hash_key(hash_key: str | bytes | None) -> bytes | None:
        if hash_key is None:
            return None
        normalized = hash_key.encode("utf-8") if isinstance(hash_key, str) else hash_key
        if len(normalized) < 16:
            raise PolicyValidationError(
                "hash_key must contain at least 16 bytes; use a secret manager"
            )
        return normalized

    @staticmethod
    def _validate_rule(rule: PatternRule) -> None:
        if not rule.name or not rule.regex:
            raise PolicyValidationError("Rule name and regex are required")
        if rule.severity not in VALID_SEVERITIES:
            raise PolicyValidationError(f"Invalid severity for rule '{rule.name}'")
        if rule.strategy not in VALID_ACTIONS:
            raise PolicyValidationError(f"Invalid action for rule '{rule.name}'")
        if rule.capture_group < 0:
            raise PolicyValidationError(f"Invalid capture group for rule '{rule.name}'")
        if rule.validator is not None and rule.validator not in VALIDATORS:
            raise PolicyValidationError(f"Unknown validator for rule '{rule.name}'")

    @staticmethod
    def _validate_field_rule(field_name: str, rule: FieldRule) -> None:
        if not field_name or not rule.name:
            raise PolicyValidationError("Field rule names are required")
        if rule.severity not in VALID_SEVERITIES:
            raise PolicyValidationError(f"Invalid severity for field '{field_name}'")
        if rule.strategy not in VALID_ACTIONS:
            raise PolicyValidationError(f"Invalid action for field '{field_name}'")

    def replace_rules(self, rules: Iterable[PatternRule]) -> None:
        compiled: list[tuple[PatternRule, re.Pattern[str]]] = []
        for rule in rules:
            self._validate_rule(rule)
            if not rule.enabled:
                continue
            flags = re.UNICODE
            for flag_name in rule.flags:
                if flag_name not in FLAG_MAP:
                    raise PolicyValidationError(
                        f"Unsupported regex flag '{flag_name}' in rule '{rule.name}'"
                    )
                flags |= FLAG_MAP[flag_name]
            try:
                compiled.append((rule, re.compile(rule.regex, flags)))
            except re.error as exc:
                raise PolicyValidationError(
                    f"Invalid regex in rule '{rule.name}': {exc}"
                ) from exc
        with self._lock:
            self._rules = compiled

    def replace_field_rules(self, field_rules: Mapping[str, FieldRule]) -> None:
        validated: dict[str, FieldRule] = {}
        for field_name, rule in field_rules.items():
            self._validate_field_rule(field_name, rule)
            if rule.enabled:
                validated[field_name.lower()] = rule
        with self._lock:
            self._field_rules = validated

    def _check_text_size(self, text: str) -> None:
        if len(text) > self.max_text_length:
            raise InputTooLargeError(
                f"Input has {len(text)} characters; limit is {self.max_text_length}"
            )

    def scan(self, text: str, *, source_field: str | None = None) -> tuple[Finding, ...]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        self._check_text_size(text)
        with self._lock:
            rules = tuple(self._rules)
        candidates: list[Finding] = []
        minimum_rank = SEVERITY_RANK[self.minimum_severity]
        for rule, regex in rules:
            if SEVERITY_RANK[rule.severity] < minimum_rank:
                continue
            validator = VALIDATORS.get(rule.validator or "")
            for match in regex.finditer(text):
                try:
                    start, end = match.span(rule.capture_group)
                    value = match.group(rule.capture_group)
                except IndexError as exc:
                    raise PolicyValidationError(
                        f"Invalid capture group in rule '{rule.name}'"
                    ) from exc
                if value and (validator is None or validator(value)):
                    candidates.append(
                        Finding(
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            start=start,
                            end=end,
                            value=value,
                            strategy=rule.strategy,
                            source_field=source_field,
                        )
                    )
        candidates.sort(key=lambda finding: (finding.start, -(finding.end - finding.start)))
        accepted: list[Finding] = []
        for finding in candidates:
            if not any(
                finding.start < chosen.end and finding.end > chosen.start
                for chosen in accepted
            ):
                accepted.append(finding)
        # Replacing overlapping spans would corrupt the output. At a shared position, retain the longest match and return accepted values in order.
        return tuple(sorted(accepted, key=lambda finding: finding.start))

    def _replacement(
        self,
        finding: Finding,
        action: Action,
        *,
        preserve_type: bool,
    ) -> str:
        if action == "allow":
            return finding.value
        if action == "mask":
            return mask_value(finding.value)
        if action == "hash":
            if self._hash_key is None:
                raise PolicyValidationError(
                    "A hash_key is required when a policy uses strategy='hash'"
                )
            digest = hmac.new(
                self._hash_key, finding.value.encode("utf-8"), hashlib.sha256
            ).hexdigest()[:24]
            return f"[{finding.name.upper()}_HMAC:{digest}]"
        if action == "block":
            return f"[{finding.name.upper()}_BLOCKED]"
        return (
            f"[{finding.name.upper()}_REDACTED]" if preserve_type else "[REDACTED]"
        )

    def protected_value_for(
        self, finding: Finding, *, preserve_type: bool = True
    ) -> str:
        """Protect a finding; do not expose or log finding.value."""
        return self._replacement(finding, finding.strategy, preserve_type=preserve_type)

    def sanitize(
        self,
        text: str,
        *,
        action: Action | None = None,
        preserve_type: bool = True,
        source_field: str | None = None,
    ) -> ScanResult:
        if action is not None and action not in VALID_ACTIONS:
            raise ValueError("action is invalid")
        findings = self.scan(text, source_field=source_field)
        sanitized = text
        blocked = False
        # Work right-to-left so source positions remain valid.
        for finding in reversed(findings):
            selected_action = action or finding.strategy or self.default_action
            blocked |= selected_action == "block"
            replacement = self._replacement(
                finding, selected_action, preserve_type=preserve_type
            )
            sanitized = sanitized[: finding.start] + replacement + sanitized[finding.end :]
        return ScanResult(findings=findings, sanitized_text=sanitized, blocked=blocked)

    def sanitize_record(
        self,
        record: Mapping[str, Any],
        *,
        action: Action | None = None,
        preserve_type: bool = True,
    ) -> RecordScanResult:
        if not isinstance(record, Mapping):
            raise TypeError("record must be a mapping")
        if action is not None and action not in VALID_ACTIONS:
            raise ValueError("action is invalid")
        with self._lock:
            field_rules = dict(self._field_rules)
        findings: list[Finding] = []
        blocked = False
        minimum_rank = SEVERITY_RANK[self.minimum_severity]

        def visit(value: Any, path: str, field_name: str | None = None) -> Any:
            nonlocal blocked
            if isinstance(value, Mapping):
                result: dict[str, Any] = {}
                for key, nested_value in value.items():
                    string_key = str(key)
                    nested_path = f"{path}.{string_key}" if path else string_key
                    result[string_key] = visit(nested_value, nested_path, string_key)
                return result
            if isinstance(value, list):
                return [
                    visit(item, f"{path}[{index}]", field_name)
                    for index, item in enumerate(value)
                ]
            if not isinstance(value, str):
                return value
            self._check_text_size(value)
            field_rule = field_rules.get((field_name or "").lower())
            if field_rule and SEVERITY_RANK[field_rule.severity] >= minimum_rank:
                finding = Finding(
                    name=field_rule.name,
                    category=field_rule.category,
                    severity=field_rule.severity,
                    start=0,
                    end=len(value),
                    value=value,
                    strategy=field_rule.strategy,
                    source_field=path,
                )
                findings.append(finding)
                selected_action = action or field_rule.strategy
                blocked |= selected_action == "block"
                return self._replacement(
                    finding, selected_action, preserve_type=preserve_type
                )
            result = self.sanitize(
                value,
                action=action,
                preserve_type=preserve_type,
                source_field=path,
            )
            findings.extend(result.findings)
            blocked |= result.blocked
            return result.sanitized_text

        sanitized_record = visit(dict(record), "")
        return RecordScanResult(
            sanitized_record=sanitized_record,
            findings=tuple(findings),
            blocked=blocked,
        )
