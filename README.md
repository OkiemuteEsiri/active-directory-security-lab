# Active Directory Security Lab

A recruiter-facing defensive identity-security engineering project for analyzing **Active Directory attack paths, privileged-access relationships, directory hygiene, authentication controls, delegation risk, and remediation validation** using synthetic/offline data.

The lab is intentionally safe: it does not perform password attacks, credential dumping, ticket abuse, exploitation, persistence, directory modification, or live tenant/domain targeting.

## Problem Statement

Identity compromise often depends on combinations of weak authentication controls, stale accounts, unmanaged service identities, risky delegation, and excessive trust relationships rather than one isolated vulnerability. Security teams need repeatable ways to inventory those conditions, explain why they matter, prioritize remediation, and demonstrate that risk has actually been reduced.

This project implements two complementary defensive capabilities:

1. **Attack-path analysis** — models synthetic identity relationships as a directed graph and identifies shortest paths toward privileged assets.
2. **Directory posture assessment** — evaluates identity/computer metadata against deterministic security controls and produces evidence-driven findings with remediation and validation criteria.

## Architecture

```text
Synthetic identity edges ──> attack_path_analyzer.py ──> relationship path output

Synthetic directory JSON ──> cli.py ──> ad_posture.py ──> reporting.py ──> Markdown assessment
                                      │
                                      └──> control findings + posture score
```

See [`docs/architecture.md`](docs/architecture.md) for design boundaries and extension points.

## Implemented Security Controls

| Control | Risk condition | Default severity |
|---|---|---|
| AD-001 | Enabled privileged identity without MFA requirement | Critical |
| AD-002 | User/service identity with non-expiring password | High |
| AD-003 | Unconstrained delegation enabled | Critical |
| AD-004 | Reversible password storage enabled | Critical |
| AD-005 | Enabled user/service/computer inactive for 90+ days | Medium/High |
| AD-006 | Directory object lacks accountable owner | Low |

Every finding carries evidence, a remediation recommendation, and an explicit revalidation condition. Findings are sorted using transparent severity weights; the 0–100 posture score is a bounded summary and is not presented as an enterprise risk rating.

## Repository Structure

```text
.github/workflows/security-quality.yml  Compile, unit-test and report smoke-test CI
data/synthetic_identity_edges.csv       Synthetic relationship graph
data/synthetic_directory_inventory.json Synthetic AD posture inventory
docs/architecture.md                    Component and trust-boundary design
docs/methodology.md                     Assessment/remediation methodology
docs/attack-path-remediation.md         Attack-path remediation guidance
src/attack_path_analyzer.py             Defensive graph/path utility
src/ad_posture.py                       Directory posture model and controls
src/reporting.py                        Markdown assessment rendering
src/cli.py                              Offline assessment CLI
tests/                                  Unit tests
```

## Usage

Run the posture assessment:

```bash
python -m src.cli data/synthetic_directory_inventory.json --output reports/generated-assessment.md
```

Run the relationship analysis:

```bash
python src/attack_path_analyzer.py
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

The bundled datasets contain fictional principals, hosts, owners and relationships only.

## Detection and Risk Context

The lab maps defensive observations to MITRE ATT&CK where useful:

- **T1078 — Valid Accounts:** stale identities, weak privileged authentication and long-lived credentials can increase valid-account abuse exposure.
- **T1550.003 — Pass the Ticket:** delegation configuration is reviewed because Kerberos trust design affects ticket exposure paths.
- **T1003 — OS Credential Dumping:** reversible password storage represents a credential-protection weakness.
- **T1555 — Credentials from Password Stores:** long-lived static credentials increase impact if secrets are disclosed.
- Existing attack-path documentation also references **T1087**, **T1069**, **T1021**, and **T1098** as defensive discovery/access context.

These mappings are threat-model references only; they do **not** claim that compromise or attacker activity occurred.

## Remediation and Validation Workflow

1. Establish an approved inventory scope and export only required metadata.
2. Normalize objects and relationships into the lab schemas.
3. Run posture and relationship analysis.
4. Review evidence and business context before accepting severity.
5. Assign accountable remediation owners.
6. Apply least-privilege/authentication/lifecycle changes through normal change control.
7. Re-export fresh evidence and rerun the assessment.
8. Close findings only when the validation condition is met and dependent applications/services remain healthy.

Examples include enforcing phishing-resistant MFA for privileged access, migrating service identities toward gMSA/managed identities, removing unnecessary delegation, disabling stale accounts, assigning ownership, and rotating credentials when protection settings change.

## Engineering Design Decisions

- **Fail-closed validation:** unsupported object classes, negative inactivity values and duplicate case-insensitive names are rejected.
- **Immutable models:** directory objects and findings use frozen dataclasses to reduce accidental mutation during assessment.
- **Explainability over opaque scoring:** each rule exposes the exact condition that created the finding.
- **Offline by default:** no LDAP, WinRM, SMB, Kerberos, Entra, or cloud API connection is required.
- **Safe synthetic datasets:** examples can be reproduced without employer/client information or credentials.
- **Revalidation built in:** remediation advice includes measurable closure criteria.

## CI/CD Security Quality

The GitHub Actions workflow uses read-only repository permissions and performs:

- Python source/test compilation
- full `unittest` discovery
- synthetic assessment generation
- report-content smoke validation

A workflow being present does not imply a run passed; CI status should be checked for the relevant commit.

## Limitations

This project is intentionally not a complete enterprise AD assessment suite. Production identity reviews should additionally consider privileged tiering, nested group/ACL analysis, Group Policy, AD CS, domain/forest trusts, Kerberos encryption, LDAP signing/channel binding, SMB hardening, local admin management, privileged workstations, identity governance, conditional access, endpoint telemetry, exception management, and business-critical service dependencies.

## Skills Demonstrated

- Active Directory / identity security engineering
- Graph-based privilege-path reasoning
- Security control design and evidence modeling
- Privileged-access and service-account risk analysis
- MITRE ATT&CK contextual mapping
- Python defensive automation
- Unit-test design
- Synthetic security-data modeling
- Remediation and revalidation workflow design
- CI/CD quality controls
- Technical security documentation and risk communication

## Roadmap

- Add group nesting and transitive privilege analysis.
- Add configurable policy thresholds instead of fixed defaults.
- Add authorized read-only adapters for exported Entra ID / AD inventory formats.
- Add richer risk context for tier-0 identities and crown-jewel systems.
- Add detection examples for identity lifecycle and privileged-authentication anomalies.
- Add structured JSON/SARIF output for integration with governance workflows.

## Safety and Ethics

Use this repository only for isolated labs, defensive engineering, training, and systems for which explicit authorization exists. It contains no real credentials, production directory data, credential-theft tooling, exploit payloads, persistence mechanisms, or instructions for attacking third-party environments.
