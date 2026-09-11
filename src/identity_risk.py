from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Iterable

ALLOWED_EVENT_TYPES = {"logon_failure", "logon_success", "mfa_challenge", "privileged_logon", "account_change"}
ALLOWED_RISK_LEVELS = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class AuthEvent:
    event_id: str
    timestamp: datetime
    principal: str
    event_type: str
    source: str
    success: bool
    privileged: bool = False
    mfa_satisfied: bool = False
    known_device: bool = True
    known_location: bool = True

    @staticmethod
    def from_dict(raw: dict) -> "AuthEvent":
        required = {"event_id", "timestamp", "principal", "event_type", "source", "success"}
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        if raw["event_type"] not in ALLOWED_EVENT_TYPES:
            raise ValueError(f"unsupported event_type: {raw['event_type']}")
        ts = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
        if ts.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return AuthEvent(
            event_id=str(raw["event_id"]),
            timestamp=ts.astimezone(timezone.utc),
            principal=str(raw["principal"]),
            event_type=str(raw["event_type"]),
            source=str(raw["source"]),
            success=bool(raw["success"]),
            privileged=bool(raw.get("privileged", False)),
            mfa_satisfied=bool(raw.get("mfa_satisfied", False)),
            known_device=bool(raw.get("known_device", True)),
            known_location=bool(raw.get("known_location", True)),
        )


@dataclass(frozen=True)
class IdentityRiskFinding:
    finding_id: str
    principal: str
    rule_id: str
    title: str
    risk_level: str
    score: int
    evidence: str
    attack_id: str | None
    remediation: str
    validation: str


def _finding(principal: str, rule_id: str, title: str, risk_level: str, score: int, evidence: str,
             attack_id: str | None, remediation: str, validation: str) -> IdentityRiskFinding:
    if risk_level not in ALLOWED_RISK_LEVELS:
        raise ValueError("invalid risk level")
    digest = sha256(f"{principal.lower()}|{rule_id}|{evidence}".encode()).hexdigest()[:12]
    return IdentityRiskFinding(
        finding_id=f"IDR-{digest}", principal=principal, rule_id=rule_id, title=title,
        risk_level=risk_level, score=min(max(score, 0), 100), evidence=evidence,
        attack_id=attack_id, remediation=remediation, validation=validation,
    )


def assess_identity_events(events: Iterable[AuthEvent]) -> list[IdentityRiskFinding]:
    events = list(events)
    ids = [e.event_id for e in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event_id detected")

    findings: list[IdentityRiskFinding] = []
    by_principal: dict[str, list[AuthEvent]] = {}
    for event in events:
        by_principal.setdefault(event.principal.lower(), []).append(event)

    for principal_key, principal_events in by_principal.items():
        principal = principal_events[0].principal
        failures = [e for e in principal_events if e.event_type == "logon_failure"]
        if len(failures) >= 5:
            sources = len({e.source for e in failures})
            findings.append(_finding(
                principal, "ID-101", "Repeated authentication failures", "high", min(55 + len(failures), 85),
                f"{len(failures)} failures from {sources} source(s)", "T1110.003",
                "Review authentication failures, source context and account protections; reset credentials only when justified.",
                "A fresh review window no longer exceeds the approved failure threshold and suspicious sources are dispositioned.",
            ))

        risky_success = [e for e in principal_events if e.success and (not e.known_device or not e.known_location)]
        if risky_success:
            findings.append(_finding(
                principal, "ID-102", "Successful authentication from unfamiliar context", "high", 72,
                f"{len(risky_success)} successful event(s) from unknown device/location context", "T1078",
                "Validate user activity, strengthen conditional access and revoke sessions if compromise is confirmed.",
                "Subsequent successful authentication requires approved device/location context or documented exception.",
            ))

        privileged_without_mfa = [e for e in principal_events if e.success and e.privileged and not e.mfa_satisfied]
        if privileged_without_mfa:
            findings.append(_finding(
                principal, "ID-103", "Privileged authentication without MFA evidence", "critical", 95,
                f"{len(privileged_without_mfa)} privileged successful event(s) without MFA evidence", "T1078.002",
                "Require phishing-resistant MFA for privileged access and investigate existing sessions.",
                "Fresh privileged authentication telemetry shows MFA satisfied for all in-scope privileged sessions.",
            ))

    return sorted(findings, key=lambda f: (-f.score, f.principal.lower(), f.rule_id))


def portfolio_metrics(findings: Iterable[IdentityRiskFinding]) -> dict[str, int]:
    items = list(findings)
    return {
        "findings": len(items),
        "critical": sum(f.risk_level == "critical" for f in items),
        "high": sum(f.risk_level == "high" for f in items),
        "principals_at_risk": len({f.principal.lower() for f in items}),
        "max_score": max((f.score for f in items), default=0),
    }
