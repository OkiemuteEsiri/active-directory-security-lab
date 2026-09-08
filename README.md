# Active Directory Security Lab

A defensive and offensive identity-security lab for analyzing Active Directory attack paths, privileged access, authentication weaknesses, and remediation strategies in an isolated environment.

## Focus Areas

- Active Directory architecture and trust relationships
- Privileged group and local-admin exposure
- Kerberos security and service-account risk
- NTLM and legacy authentication exposure
- Delegation and certificate-service misconfiguration
- BloodHound-based attack-path analysis
- Group Policy security review
- Identity hardening and remediation validation

## Lab Method

1. Build or import a synthetic AD environment.
2. Inventory users, groups, computers, trusts, SPNs, and privilege relationships.
3. Identify risky identity paths and configuration weaknesses.
4. Map findings to ATT&CK techniques and business impact.
5. Apply least-privilege and hardening recommendations.
6. Re-run analysis to confirm the attack path is reduced or removed.

## Evidence Model

Each case study should document the vulnerable condition, attack-path logic, affected identities/assets, exploitability, business impact, detection opportunities, remediation, and retest result.

## Safety

This repository is designed for isolated labs and authorized security assessments only. It does not contain production credentials, real corporate directory data, or instructions to target third-party systems.
