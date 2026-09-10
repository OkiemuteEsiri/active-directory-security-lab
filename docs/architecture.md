# Architecture

## Objective

This lab demonstrates defensive Active Directory and identity-security engineering using synthetic, offline data. It combines two complementary capabilities:

1. **Relationship analysis** — model identity-to-asset edges and identify shortest synthetic paths to privileged assets.
2. **Posture assessment** — evaluate directory-object metadata against deterministic security controls and generate evidence-driven findings.

## Components

```text
Synthetic identity edges ──> attack_path_analyzer.py ──> path output

Synthetic directory JSON ──> cli.py ──> ad_posture.py ──> reporting.py ──> Markdown assessment
                                      │
                                      └──> deterministic findings + posture score
```

## Trust and safety boundaries

The project intentionally excludes live LDAP binds, credential collection, password spraying, Kerberos abuse, exploit execution, persistence, directory modification, and production targeting. Input is synthetic or exported metadata supplied by the operator.

## Data model

`DirectoryObject` captures a deliberately small, auditable subset of identity posture attributes: object class, privilege state, enabled state, MFA policy, password lifetime configuration, inactivity, delegation, reversible password storage, and accountable ownership.

`Finding` records a stable control identifier, severity, affected object, evidence, remediation, validation criteria, and optional MITRE ATT&CK defensive context.

## Control philosophy

Controls are designed to be explainable. A finding must show the exact metadata that caused it and provide a validation step so remediation can be retested. The posture score is secondary to finding-level evidence and should not be interpreted as an enterprise risk rating.

## Extensibility

Future provider adapters can normalize approved exports from Microsoft Entra ID, Active Directory inventory tools, or CMDB sources into the same domain model without changing assessment logic. Production connectors should use read-only service identities and explicit tenant authorization.
