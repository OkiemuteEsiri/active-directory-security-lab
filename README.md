# Active Directory Security Lab

A flagship defensive **Active Directory / Identity Security Engineering** project for analyzing directory posture, privilege paths, authentication risk, delegation exposure, and remediation validation using synthetic offline data.

> **Recruiter quick review:** start with [`docs/recruiter-review.md`](docs/recruiter-review.md), then inspect the example report, control-validation matrix, core modules, tests, and least-privilege CI workflow.

The lab is intentionally safe: it does not perform password attacks, credential dumping, ticket abuse, exploitation, persistence, directory modification, or live tenant/domain targeting.

## Why This Project Matters

Identity compromise often depends on combinations of weak authentication controls, stale accounts, unmanaged service identities, risky delegation, excessive trust relationships, and incomplete remediation evidence rather than one isolated vulnerability. Security teams need repeatable ways to inventory those conditions, explain why they matter, prioritize remediation, and prove that risk has actually been reduced.

This project implements four complementary defensive capabilities:

1. **Attack-path analysis** — models synthetic identity relationships as a directed graph and identifies shortest paths toward privileged assets.
2. **Directory posture assessment** — evaluates identity/computer metadata against deterministic security controls and produces evidence-driven findings.
3. **Identity-risk analytics** — evaluates exported authentication telemetry for repeated failures, unfamiliar-context successes, and privileged logons without MFA evidence.
4. **Remediation validation** — rejects administrative closure when accountable ownership, changed control state, validation evidence, or demonstrated control effectiveness is missing.

## Recruiter Signal at a Glance

| Area | What is demonstrated |
|---|---|
| Identity security engineering | Directory controls, authentication-risk analysis, ownership and lifecycle reasoning |
| Attack-path reasoning | Directed graph analysis of synthetic privilege relationships |
| Detection engineering | Deterministic authentication rules with evidence and ATT&CK context |
| Risk communication | Explainable severities, rationale, limitations, and analyst-facing reports |
| Remediation governance | Evidence-driven validation rather than ticket-state trust |
| Secure engineering | Fail-closed validation, deterministic IDs, unit tests, least-privilege CI |
| Documentation | Architecture, methodology, control matrix, remediation guidance, example outputs |

## Architecture

```text
Synthetic relationship edges ──> attack_path_analyzer.py ──> privilege-path output
Synthetic directory inventory ──> ad_posture.py ──────────> posture findings
Synthetic auth telemetry ────────> identity_risk.py ───────> identity-risk findings
Synthetic remediation evidence ─> remediation_validator.py -> validation decisions
                                      │
                                      └──> reporting.py / example reports
```

Design references:

- [`docs/architecture.md`](docs/architecture.md) — component boundaries and data flow
- [`docs/methodology.md`](docs/methodology.md) — assessment and remediation methodology
- [`docs/identity-risk-model.md`](docs/identity-risk-model.md) — telemetry analytics and limits
- [`docs/attack-path-remediation.md`](docs/attack-path-remediation.md) — privilege-path remediation guidance
- [`docs/control-validation-matrix.md`](docs/control-validation-matrix.md) — control, evidence, remediation, and revalidation mapping
- [`docs/recruiter-review.md`](docs/recruiter-review.md) — concise technical review path

## Implemented Security Controls

### Directory posture

| Control | Risk condition | Default severity |
|---|---|---|
| AD-001 | Enabled privileged identity without MFA requirement | Critical |
| AD-002 | User/service identity with non-expiring password | High |
| AD-003 | Unconstrained delegation enabled | Critical |
| AD-004 | Reversible password storage enabled | Critical |
| AD-005 | Enabled user/service/computer inactive for 90+ days | Medium/High |
| AD-006 | Directory object lacks accountable owner | Low |

### Authentication telemetry

| Rule | Risk condition | Risk | ATT&CK |
|---|---|---|---|
| ID-101 | Five or more failed logons for one principal in the supplied assessment window | High | T1110.003 |
| ID-102 | Successful authentication from unknown device/location context | High | T1078 |
| ID-103 | Successful privileged authentication without MFA evidence | Critical | T1078.002 |

Every finding exposes evidence, remediation guidance, and a measurable revalidation condition. Scores are transparent and bounded; they are prioritization aids, not claims of compromise or enterprise risk ratings.

## Repository Structure

```text
.github/workflows/security-quality.yml   Compile, unit-test and report smoke-test CI

data/synthetic_identity_edges.csv        Synthetic relationship graph
data/synthetic_directory_inventory.json  Synthetic AD posture inventory
data/synthetic_auth_events.json          Synthetic authentication telemetry
data/remediation_evidence.json            Synthetic remediation evidence

docs/architecture.md                     Component and trust-boundary design
docs/methodology.md                       Assessment/remediation methodology
docs/attack-path-remediation.md           Attack-path remediation guidance
docs/identity-risk-model.md               Identity analytics design and limits
docs/control-validation-matrix.md         Control/evidence/revalidation matrix
docs/recruiter-review.md                  5-minute technical review guide

src/attack_path_analyzer.py              Defensive graph/path utility
src/ad_posture.py                         Directory posture model and controls
src/identity_risk.py                      Authentication-risk analytics
src/remediation_validator.py              Evidence-based closure validation
src/reporting.py                          Markdown assessment rendering
src/cli.py                                Offline posture assessment CLI

tests/                                   Unit tests
reports/identity-risk-example.md          Recruiter-facing synthetic output
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

Run all tests:

```bash
python -m unittest discover -s tests -v
```

The bundled datasets contain fictional principals, hosts, owners, events, and relationships only.

## Detection and MITRE ATT&CK Context

The lab maps defensive observations to ATT&CK where useful:

- **T1078 — Valid Accounts:** stale identities, unfamiliar-context successful authentication, and weak authentication controls increase valid-account abuse exposure.
- **T1078.002 — Domain Accounts:** privileged domain authentication without MFA evidence is treated as a critical control gap.
- **T1110.003 — Password Spraying:** repeated failed authentication is modeled as a defensive detection condition only; this repository does not execute password spraying.
- **T1550.003 — Pass the Ticket:** delegation configuration is reviewed because Kerberos trust design affects ticket exposure paths.
- **T1003 — OS Credential Dumping:** reversible password storage represents a credential-protection weakness.
- **T1555 — Credentials from Password Stores:** long-lived static credentials increase impact if secrets are disclosed.
- Attack-path documentation also references **T1087**, **T1069**, **T1021**, and **T1098** as defensive discovery/access context.

These mappings are threat-model references only; they do **not** claim that compromise or attacker activity occurred.

## Remediation and Revalidation Workflow

1. Establish an approved inventory and telemetry scope.
2. Normalize directory objects, relationships, and authentication events into the documented schemas.
3. Run posture, path, and identity-risk analysis.
4. Review evidence and business context before accepting severity.
5. Assign accountable remediation owners.
6. Apply least-privilege, MFA, lifecycle, delegation, or service-identity changes through approved change control.
7. Capture before/after state plus a change reference and validation method.
8. Re-export fresh evidence and rerun the assessment.
9. Close only when the control state changed and effectiveness is demonstrated.

The remediation validator deliberately distinguishes `ready_for_validation`, `validated`, `needs_evidence`, and `invalid_closure`. A ticket marked closed does not override missing technical evidence.

The [`control-validation matrix`](docs/control-validation-matrix.md) makes the evidence standard explicit for every implemented control and analytic rule.

## Engineering Design Decisions

- **Fail-closed validation:** unsupported object classes/event types, negative inactivity values, duplicate identifiers, and timestamps without timezone context are rejected.
- **Immutable models:** directory objects, authentication events, findings, and remediation evidence use frozen dataclasses where implemented.
- **Deterministic identifiers:** findings and validation decisions use stable SHA-derived identifiers to support repeatable comparisons.
- **Explainability over opaque scoring:** each rule exposes the exact condition that created the finding.
- **Offline by default:** no LDAP, WinRM, SMB, Kerberos, Entra, SIEM, or cloud API connection is required.
- **Safe synthetic datasets:** examples are reproducible without employer/client information or credentials.
- **Evidence-driven closure:** remediation requires measurable proof of changed and effective control state.

## CI/CD Security Quality

The GitHub Actions workflow uses read-only repository permissions and performs Python source/test compilation, `unittest` discovery, synthetic assessment generation, and report-content smoke validation.

CI status is intentionally treated as **commit-specific evidence**. The presence of a workflow or a historical successful run is not presented as proof that a newer commit is green; the exact commit must be checked before making that claim.

## Limitations

This project is intentionally not a complete enterprise AD assessment suite. Production identity reviews should additionally consider privileged tiering, nested group/ACL analysis, Group Policy, AD CS, domain/forest trusts, Kerberos encryption, LDAP signing/channel binding, SMB hardening, LAPS, privileged workstations, identity governance, conditional access, endpoint telemetry, token/session risk, workload identities, emergency access, exception management, and business-critical service dependencies.

The identity analytics are deterministic control checks rather than UEBA. They do not perform geolocation lookups, impossible-travel inference, credential validation, or probabilistic compromise scoring.

## Skills Demonstrated

- Active Directory / identity security engineering
- Graph-based privilege-path reasoning
- Authentication telemetry and privileged-access analysis
- Detection engineering and evidence modeling
- Security control design and risk communication
- MITRE ATT&CK contextual mapping
- Python defensive automation
- Deterministic risk prioritization
- Unit-test design
- Synthetic security-data modeling
- Remediation and revalidation workflow design
- CI/CD security quality controls
- Technical architecture and methodology documentation

## Roadmap

- Add group nesting and transitive privilege analysis.
- Add configurable policy thresholds instead of fixed defaults.
- Add authorized read-only adapters for exported Entra ID / AD inventory formats.
- Add richer tier-0/crown-jewel risk context.
- Add structured JSON/SARIF output for governance integrations.
- Extend remediation evidence with timestamps, approvers, exception expiry, and regression detection.
- Add defensive identity-detection examples for risky token/session and service-principal activity.

## Safety and Ethics

Use this repository only for isolated labs, defensive engineering, training, and systems for which explicit authorization exists. It contains no real credentials, production directory data, credential-theft tooling, exploit payloads, persistence mechanisms, or instructions for attacking third-party environments.
