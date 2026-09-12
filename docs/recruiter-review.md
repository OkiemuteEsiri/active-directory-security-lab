# Recruiter Review Guide

This repository is designed to be reviewable without requiring a live Active Directory environment. All evidence is synthetic and the implementation is defensive/offline.

## 5-Minute Review Path

1. Start with the main `README.md` for the problem statement and architecture.
2. Review `src/ad_posture.py` for deterministic directory-control checks.
3. Review `src/identity_risk.py` for authentication telemetry analysis.
4. Review `src/attack_path_analyzer.py` for graph-based privilege-path reasoning.
5. Review `src/remediation_validator.py` to see how closure evidence is validated rather than trusted administratively.
6. Open `reports/identity-risk-example.md` for analyst-facing output.
7. Open `.github/workflows/security-quality.yml` for compile, test, and report-generation quality gates.

## What This Project Demonstrates

| Capability | Evidence in repository |
|---|---|
| Active Directory security engineering | Directory posture controls and identity relationship analysis |
| Detection engineering | Authentication-event rules with explicit evidence and ATT&CK context |
| Attack-path reasoning | Directed graph analysis toward privileged assets |
| Risk communication | Deterministic severities, rationale, and analyst-facing Markdown reporting |
| Remediation governance | Evidence-based revalidation states and closure rejection when proof is incomplete |
| Secure engineering | Fail-closed input handling, immutable models, deterministic identifiers, tests, and least-privilege CI |
| Documentation | Architecture, methodology, risk model, remediation guidance, and limitations |

## Security Boundaries

The project does not perform LDAP enumeration, credential validation, password attacks, Kerberos ticket abuse, credential dumping, remote execution, persistence, directory modification, or live production targeting.

MITRE ATT&CK mappings are defensive threat-model references. They describe why a control matters; they do not claim that an attack occurred.

## Technical Review Questions This Repository Answers

- How are identity-security findings produced reproducibly from structured evidence?
- How are privilege paths represented without requiring live attack tooling?
- How are authentication anomalies distinguished from proof of compromise?
- How is remediation closure tied to changed control state and validation evidence?
- How are unsafe assumptions constrained by schema validation and explicit limitations?

## Recommended Deep-Dive Files

- `docs/architecture.md` — components and trust boundaries
- `docs/methodology.md` — assessment lifecycle and analyst workflow
- `docs/identity-risk-model.md` — identity telemetry logic and limitations
- `docs/attack-path-remediation.md` — mitigation and revalidation guidance
- `docs/control-validation-matrix.md` — control, evidence, remediation, and validation mapping

## Portfolio Positioning

This repository is a flagship identity-security engineering project rather than an offensive AD exploitation lab. Its value is in repeatable analysis, control design, evidence handling, prioritization, remediation, and validation using safe synthetic data.
