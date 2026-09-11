from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

ALLOWED_STATES = {"open", "in_progress", "ready_for_validation", "closed"}


@dataclass(frozen=True)
class RemediationEvidence:
    finding_id: str
    state: str
    owner: str
    change_reference: str
    before_value: str
    after_value: str
    validation_method: str
    evidence_complete: bool
    control_effective: bool

    @staticmethod
    def from_dict(raw: dict) -> "RemediationEvidence":
        required = {"finding_id", "state", "owner", "change_reference", "before_value", "after_value",
                    "validation_method", "evidence_complete", "control_effective"}
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        if raw["state"] not in ALLOWED_STATES:
            raise ValueError(f"unsupported state: {raw['state']}")
        return RemediationEvidence(**{k: raw[k] for k in required})


@dataclass(frozen=True)
class ValidationResult:
    validation_id: str
    finding_id: str
    status: str
    reason: str


def validate_remediation(item: RemediationEvidence) -> ValidationResult:
    reasons: list[str] = []
    if not item.owner.strip():
        reasons.append("missing accountable owner")
    if not item.change_reference.strip():
        reasons.append("missing change reference")
    if item.before_value == item.after_value:
        reasons.append("before and after state are unchanged")
    if not item.validation_method.strip():
        reasons.append("validation method not recorded")
    if not item.evidence_complete:
        reasons.append("validation evidence incomplete")
    if not item.control_effective:
        reasons.append("control effectiveness not demonstrated")

    if item.state == "closed" and reasons:
        status = "invalid_closure"
    elif reasons:
        status = "needs_evidence"
    elif item.state in {"ready_for_validation", "closed"}:
        status = "validated"
    else:
        status = "ready_for_validation"

    reason = "; ".join(reasons) if reasons else "required remediation and validation evidence is present"
    digest = sha256(f"{item.finding_id}|{status}|{reason}".encode()).hexdigest()[:12]
    return ValidationResult(f"VAL-{digest}", item.finding_id, status, reason)


def validate_batch(items: Iterable[RemediationEvidence]) -> list[ValidationResult]:
    items = list(items)
    ids = [i.finding_id for i in items]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate finding_id in remediation evidence")
    return [validate_remediation(item) for item in items]
