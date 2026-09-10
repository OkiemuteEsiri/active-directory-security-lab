"""Defensive Active Directory posture assessment for synthetic lab data.

This module evaluates identity and configuration metadata. It does not perform
credential attacks, exploitation, directory modification, or live targeting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}


@dataclass(frozen=True)
class DirectoryObject:
    name: str
    object_type: str
    privileged: bool = False
    enabled: bool = True
    mfa_required: bool = True
    password_never_expires: bool = False
    stale_days: int = 0
    unconstrained_delegation: bool = False
    reversible_password_storage: bool = False
    owner: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("name is required")
        if self.object_type not in {"user", "service_account", "computer", "group"}:
            raise ValueError(f"unsupported object_type: {self.object_type}")
        if self.stale_days < 0:
            raise ValueError("stale_days cannot be negative")


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    asset: str
    title: str
    evidence: str
    remediation: str
    validation: str
    mitre_attack: tuple[str, ...] = ()


def assess_object(obj: DirectoryObject) -> list[Finding]:
    findings: list[Finding] = []

    if obj.privileged and obj.enabled and not obj.mfa_required:
        findings.append(Finding(
            "AD-001", "critical", obj.name,
            "Privileged identity does not require MFA",
            "Privileged=true, Enabled=true, MFARequired=false",
            "Require phishing-resistant MFA for privileged interactive access and enforce conditional access where supported.",
            "Re-run assessment and confirm privileged enabled identities report MFARequired=true.",
            ("T1078",),
        ))

    if obj.password_never_expires and obj.object_type in {"user", "service_account"}:
        findings.append(Finding(
            "AD-002", "high", obj.name,
            "Long-lived password configuration",
            "PasswordNeverExpires=true",
            "Move service identities to managed identities/gMSA where possible; otherwise enforce rotation with documented ownership.",
            "Confirm PasswordNeverExpires=false or approved managed-service-account exception is documented.",
            ("T1078", "T1555"),
        ))

    if obj.unconstrained_delegation:
        findings.append(Finding(
            "AD-003", "critical", obj.name,
            "Unconstrained delegation enabled",
            "UnconstrainedDelegation=true",
            "Remove unconstrained delegation and use constrained/resource-based constrained delegation where the business dependency requires delegation.",
            "Confirm unconstrained delegation is disabled and application authentication still functions.",
            ("T1550.003",),
        ))

    if obj.reversible_password_storage:
        findings.append(Finding(
            "AD-004", "critical", obj.name,
            "Reversible password storage enabled",
            "ReversiblePasswordStorage=true",
            "Disable reversible password storage, reset affected credentials, and validate dependent legacy applications.",
            "Confirm the setting is disabled and affected credentials have been rotated.",
            ("T1003",),
        ))

    if obj.enabled and obj.stale_days >= 90 and obj.object_type in {"user", "service_account", "computer"}:
        severity = "high" if obj.privileged else "medium"
        findings.append(Finding(
            "AD-005", severity, obj.name,
            "Stale enabled directory object",
            f"Enabled=true, StaleDays={obj.stale_days}",
            "Validate business ownership, disable unused objects, and remove after the approved retention period.",
            "Confirm the object is disabled/removed or stale_days is below policy threshold with a documented exception.",
            ("T1078",),
        ))

    if obj.object_type in {"user", "service_account", "computer"} and not obj.owner.strip():
        findings.append(Finding(
            "AD-006", "low", obj.name,
            "Directory object lacks accountable owner",
            "Owner field is empty",
            "Assign an accountable technical or business owner and establish periodic access review.",
            "Confirm owner metadata is populated and review cadence is recorded.",
        ))

    return findings


def assess_directory(objects: Iterable[DirectoryObject]) -> list[Finding]:
    names: set[str] = set()
    findings: list[Finding] = []
    for obj in objects:
        key = obj.name.casefold()
        if key in names:
            raise ValueError(f"duplicate directory object: {obj.name}")
        names.add(key)
        findings.extend(assess_object(obj))
    return sorted(findings, key=lambda f: (-SEVERITY_WEIGHT[f.severity], f.asset, f.control_id))


def posture_score(findings: Iterable[Finding]) -> int:
    deduction = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return max(0, 100 - min(100, deduction))
