# Identity Risk Analytics Model

## Objective

Extend directory posture assessment with authentication-event analytics while remaining offline, deterministic, and defensive. The module consumes synthetic or sanitized exported telemetry only; it does not authenticate to Active Directory, Entra ID, or a SIEM.

## Inputs

Each event records an immutable event ID, timezone-aware timestamp, principal, event type, source, outcome, privilege context, MFA evidence, and whether the device/location context is known.

Fail-closed validation rejects unsupported event types, missing required fields, naive timestamps, and duplicate event IDs.

## Detection Logic

| Rule | Condition | Risk | ATT&CK context |
|---|---|---|---|
| ID-101 | Five or more failed logons for a principal in the supplied assessment window | High | T1110.003 Password Spraying |
| ID-102 | Successful logon from an unknown device or location context | High | T1078 Valid Accounts |
| ID-103 | Successful privileged logon without MFA evidence | Critical | T1078.002 Domain Accounts |

The ATT&CK references provide threat-model context only. A finding is a defensive control signal, not proof of attacker activity.

## Scoring

Each rule produces a transparent 0–100 score used only to order findings. Scores are bounded and deliberately simple. Critical control failures, particularly privileged access without MFA evidence, remain explicit rather than being hidden behind an aggregate score.

## Triage Workflow

1. Validate telemetry completeness and the assessment window.
2. Confirm whether the principal is human, service, emergency-access, or privileged.
3. Review source, device, location, and MFA evidence.
4. Correlate with approved change, service, travel, and access context.
5. Escalate only when evidence supports suspicious or unsafe conditions.
6. Apply identity controls through normal change-management processes.
7. Re-run assessment with fresh telemetry and document validation evidence.

## Limitations

This model intentionally does not implement probabilistic UEBA, geolocation lookups, impossible-travel logic, password-spray execution, credential validation, or live tenant queries. Production deployments should additionally consider sign-in risk, token/session telemetry, conditional-access outcomes, identity-protection alerts, service-principal behavior, workload identities, emergency accounts, and identity governance context.
