# Assessment Methodology

## Scope

The assessment is an offline defensive review of synthetic or explicitly authorized Active Directory metadata. It is not an exploitation framework and does not validate compromise.

## Workflow

1. **Normalize inventory** — represent identities and computers using the `DirectoryObject` schema.
2. **Validate input** — reject unsupported object types, invalid inactivity values, and case-insensitive duplicate names.
3. **Evaluate controls** — run deterministic rules against each object.
4. **Prioritize findings** — sort by severity using transparent weights.
5. **Remediate** — assign accountable owners and implement the control-specific recommendation.
6. **Revalidate** — re-export the same metadata fields and rerun the assessment; closure requires the validation condition to be satisfied.

## Implemented controls

| ID | Condition | Default risk |
|---|---|---|
| AD-001 | Enabled privileged identity without MFA requirement | Critical |
| AD-002 | User/service identity configured with non-expiring password | High |
| AD-003 | Unconstrained delegation enabled | Critical |
| AD-004 | Reversible password storage enabled | Critical |
| AD-005 | Enabled user/service/computer inactive for 90+ days | Medium/High |
| AD-006 | User/service/computer lacks accountable owner | Low |

## MITRE ATT&CK context

Mappings provide defensive threat-model context only. They do not assert that a technique occurred.

- **T1078 — Valid Accounts:** weak lifecycle, stale identities, and insufficient privileged authentication controls can increase exposure from valid-account abuse.
- **T1550.003 — Pass the Ticket:** delegation design is reviewed because Kerberos trust configuration affects credential/ticket exposure paths.
- **T1003 — OS Credential Dumping:** reversible credential storage is treated as a credential-protection weakness.
- **T1555 — Credentials from Password Stores:** long-lived static credentials increase the consequence of credential disclosure.

## Remediation validation

A finding is not considered closed solely because a ticket is resolved. Revalidation requires fresh evidence showing the risky state changed, plus application/service validation where identity or delegation changes could affect availability.

## Limitations

This lab does not model every AD control. Important production reviews also include tiering, protected users, privileged group nesting, ACL analysis, GPO security, certificate services, Kerberos encryption, domain/forest trust, LDAP signing/channel binding, SMB hardening, identity governance, and endpoint telemetry.
