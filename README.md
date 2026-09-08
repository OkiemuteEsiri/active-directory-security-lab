# Active Directory Security Lab

A defensive identity-security engineering project for analyzing **Active Directory attack paths, privileged access relationships, authentication risk, and remediation strategy** in an isolated environment. The project deliberately uses synthetic identities and systems so its analysis can be reproduced without exposing organizational directory data.

## Engineering Objectives

- Model identity relationships as a directed graph.
- Identify paths from lower-privilege principals to protected assets.
- Explain which group membership, administrative-right or session edges create exposure.
- Prioritize least-privilege remediation at the weakest relationship in a path.
- Re-run analysis after remediation to validate risk reduction.
- Map relevant defensive observations to MITRE ATT&CK without claiming unobserved attacker activity.

## Repository Structure

```text
data/synthetic_identity_edges.csv   Synthetic users, groups, computers and relationships
src/attack_path_analyzer.py         Defensive graph/path analysis utility
tests/test_attack_path_analyzer.py  Unit tests for path discovery
docs/attack-path-remediation.md     Remediation and validation methodology
```

## Focus Areas

- Active Directory architecture and trust relationships
- Privileged group and local-admin exposure
- Kerberos and service-account risk
- NTLM and legacy authentication exposure
- Delegation and certificate-service misconfiguration
- BloodHound-oriented attack-path analysis
- Group Policy security review
- Identity hardening and remediation validation

## Example Lab Workflow

```bash
python src/attack_path_analyzer.py
python -m unittest discover -s tests
```

The bundled example evaluates a synthetic path from `alex` toward the protected `DC-LAB` asset. It demonstrates graph reasoning only; the repository does not perform credential access, exploitation, remote execution, or changes to a directory.

## Risk Model

A path is investigated in context rather than treated as a vulnerability merely because graph connectivity exists. Review factors include target criticality, privilege represented by each edge, whether a relationship is required, endpoint trust, credential/session exposure, monitoring coverage and compensating controls.

## Remediation Strategy

Typical controls include reducing standing administrative membership, separating privileged and standard identities, limiting service-account rights, protecting privileged sessions, removing unnecessary delegation, reducing legacy authentication dependencies and continuously validating identity relationships.

## ATT&CK Context

The remediation guide references ATT&CK behaviors such as Account Discovery (T1087), Permission Groups Discovery (T1069), Remote Services (T1021), Valid Accounts (T1078) and Account Manipulation (T1098). These mappings guide telemetry and detection reviews; they do not represent claims that attacks occurred.

## Evidence Model

Each case study should document the vulnerable condition, attack-path logic, affected synthetic identities/assets, exploitability assumptions, security impact, detection opportunities, remediation decision and retest result.

## Safety

This repository is for **isolated labs, defensive engineering and authorized assessments only**. It contains no production credentials, real corporate directory data, credential-dumping code, persistence mechanisms or instructions for targeting third-party systems.
