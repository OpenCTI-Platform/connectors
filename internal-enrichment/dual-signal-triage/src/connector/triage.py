"""Pure dual-signal triage — ML confidence ≠ signature true positive."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, NamedTuple


ML_ONLY_PATTERNS = (
    r"\bis_ml_only\b",
    r"\bml[_ -]?only\b",
    r"\bgid[\s:_=]*411\b",
    r"\bgenerator[\s_-]?id[\s:_=]*411\b",
    r"\bsnortml\b",
    r"\blearning\s*\(ml/dl\)\b",
    r"\bnever_equate_ml\b",
    r"\bnever[_ -]?equate[_ -]?ml[_ -]?to[_ -]?signature\b",
)

SIGNATURE_PATTERNS = (
    r"\bis_ml_only\s*[:=]\s*false\b",
    r"\bsignature[_ -]?high\b",
    r"\bsignature[_ -]?tp\b",
    r"\banalytic\.type_id\s*[:=]\s*1\b",
    r"\ba network trojan was detected\b",
    r"\bprivilege gain\b",
    r"\bmalware command and control\b",
    r"\bknown malware command and control\b",
)

CORROBORATED_PATTERNS = (
    r"\bis_corroborated\b",
    r"\bcorroborat(?:ed|ion)\b",
    r"\bsignature[_ -]?and[_ -]?(?:eve|ml|high)\b",
    r"\bdual[_ -]?signal[_ -]?corroborat",
    r"\bsignature\s*\+\s*(?:ml|eve)\b",
)


class TriageResult(NamedTuple):
    signal_basis: str
    disposition: str
    labels: tuple[str, ...]
    deny_auto_contain: bool
    summary: str


def _flatten_entity(entity: Mapping[str, Any] | None) -> str:
    if not entity:
        return ""
    parts: list[str] = []
    for key in ("name", "value", "description", "content", "pattern", "abstract"):
        val = entity.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val)
    labels = entity.get("labels") or entity.get("x_opencti_labels") or []
    if isinstance(labels, list):
        for label in labels:
            if isinstance(label, str):
                parts.append(label)
            elif isinstance(label, Mapping):
                value = label.get("value") or label.get("name")
                if isinstance(value, str):
                    parts.append(value)
    custom = entity.get("customFieldValues") or entity.get("x_opencti_custom_fields")
    if isinstance(custom, list):
        for item in custom:
            if isinstance(item, Mapping):
                parts.extend(str(v) for v in item.values() if v is not None)
    elif isinstance(custom, Mapping):
        parts.extend(str(v) for v in custom.values() if v is not None)
    for key, val in entity.items():
        if key.startswith("x_") and isinstance(val, (str, bool, int, float)):
            parts.append(f"{key}={val}")
    return "\n".join(parts).lower()


def _any_match(text: str, patterns: Iterable[str]) -> bool:
    return any(re.search(pat, text, flags=re.IGNORECASE) for pat in patterns)


def triage_text(text: str) -> TriageResult:
    blob = (text or "").lower()
    has_ml = _any_match(blob, ML_ONLY_PATTERNS)
    has_signature = _any_match(blob, SIGNATURE_PATTERNS)
    is_corroborated = _any_match(blob, CORROBORATED_PATTERNS) or (
        has_ml and has_signature
    )
    is_ml_only = has_ml and not is_corroborated
    is_signature = has_signature and not is_corroborated

    if is_corroborated:
        return TriageResult(
            signal_basis="corroborated",
            disposition="gated_fix_now",
            labels=(
                "dual-signal:corroborated",
                "gate:fix-now",
                "remediation:hitl-required",
            ),
            deny_auto_contain=False,
            summary=(
                "Corroborated dual-signal finding (rule/signature + second signal). "
                "Eligible for Gate→Prove remediation after human/policy confirmation. "
                "Do not auto-contain without Gate."
            ),
        )

    if is_ml_only:
        return TriageResult(
            signal_basis="ml_only",
            disposition="escalate",
            labels=(
                "dual-signal:ml-only",
                "gate:escalate",
                "remediation:deny-auto-contain",
            ),
            deny_auto_contain=True,
            summary=(
                "ML-only signal path. Machine-learning confidence must not be treated as "
                "equivalent to a classic signature true positive. Escalate for corroboration; "
                "deny auto-containment."
            ),
        )

    if is_signature:
        return TriageResult(
            signal_basis="signature",
            disposition="gated_fix_now",
            labels=(
                "dual-signal:signature",
                "gate:fix-now",
                "remediation:hitl-required",
            ),
            deny_auto_contain=False,
            summary=(
                "Classic rule/signature true-positive candidate. Prefer gated remediation "
                "(HITL/policy Gate→Prove) over ungated automation."
            ),
        )

    return TriageResult(
        signal_basis="unknown",
        disposition="accept",
        labels=("dual-signal:unknown", "gate:accept"),
        deny_auto_contain=True,
        summary=(
            "Insufficient dual-signal markers. Default to accept/monitor; do not auto-contain."
        ),
    )


def triage_entity(entity: Mapping[str, Any] | None) -> TriageResult:
    return triage_text(_flatten_entity(entity))
