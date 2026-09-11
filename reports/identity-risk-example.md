# Example Identity Risk Assessment

> Synthetic demonstration only. No production identities, credentials, client data, or live authentication systems are represented.

## Executive Summary

The synthetic assessment identified three distinct identity-risk conditions requiring different defensive responses: repeated authentication failures for a service identity, a successful sign-in from unfamiliar context for a workforce user, and privileged authentication without recorded MFA evidence.

The highest-priority condition is the privileged authentication control gap because privileged access without MFA evidence materially increases the impact of valid-account compromise. The correct response is not to assume compromise, but to validate the authentication event, enforce the expected privileged-access control, review active sessions, and confirm through fresh telemetry that the control is effective.

## Findings

| Rule | Principal | Risk | Score | ATT&CK context |
|---|---|---:|---:|---|
| ID-103 | `tier0-admin` | Critical | 95 | T1078.002 |
| ID-102 | `analyst01` | High | 72 | T1078 |
| ID-101 | `svc-build` | High | 61 | T1110.003 |

## Remediation Priorities

1. Require phishing-resistant MFA for privileged authentication and validate that all new privileged sessions carry MFA evidence.
2. Review the unfamiliar-context successful authentication and apply conditional-access or device-trust improvements where justified.
3. Investigate repeated failures for the service identity, validate dependent jobs, and remediate stale credentials or misconfiguration without disrupting approved services.

## Validation Standard

A finding is not considered closed solely because a ticket or change exists. Closure requires accountable ownership, a change reference, evidence that the control state changed, a defined validation method, complete evidence, and confirmation that the control is effective.

The bundled `remediation_evidence.json` intentionally includes one invalid closure to demonstrate that the validation engine rejects administrative closure when the before/after control state is unchanged and effectiveness is not demonstrated.
