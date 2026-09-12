# Identity Control Validation Matrix

This matrix connects each implemented control or analytic rule to its evidence requirement, likely impact, remediation objective, revalidation condition, and defensive ATT&CK context.

| ID | Control / analytic condition | Security impact | Evidence used | Remediation objective | Revalidation condition | ATT&CK context |
|---|---|---|---|---|---|---|
| AD-001 | Enabled privileged identity without MFA requirement | Privileged account compromise can have disproportionate directory impact | Synthetic identity metadata, enabled state, privilege flag, MFA requirement | Require strong MFA and review privileged-account usage | Fresh inventory shows MFA required for the privileged identity | T1078.002 |
| AD-002 | Non-expiring password on user/service identity | Long-lived static credentials increase persistence of credential exposure | Password-policy metadata | Remove unnecessary non-expiring passwords; use governed service-identity controls | Fresh inventory shows corrected password lifecycle or approved managed identity pattern | T1078, T1555 |
| AD-003 | Unconstrained delegation enabled | Broad Kerberos delegation can expand credential/ticket exposure paths | Delegation configuration metadata | Remove unconstrained delegation and adopt constrained alternatives where justified | Fresh configuration export shows the unsafe delegation state removed | T1550.003 |
| AD-004 | Reversible password storage enabled | Password material can be exposed in a recoverable form | Directory password-policy metadata | Disable reversible storage and rotate affected credentials under change control | Fresh inventory confirms reversible storage disabled and rotation evidence is recorded | T1003 |
| AD-005 | Enabled stale directory object | Dormant accounts or hosts may retain unnecessary access paths | Enabled state and inactivity age | Disable, remove, or formally justify stale objects | Fresh inventory confirms lifecycle action and no unintended dependency remains | T1078 |
| AD-006 | Directory object lacks accountable owner | Unowned objects weaken lifecycle and remediation accountability | Ownership field | Assign accountable technical/business owner | Fresh inventory contains valid ownership metadata | Governance context |
| ID-101 | Repeated failed logons for one principal | May indicate authentication pressure or misconfiguration requiring investigation | Synthetic authentication events within assessment window | Investigate source/context, tune controls, and address credential or service issues | Re-run telemetry no longer breaches threshold or documented benign cause is validated | T1110.003 |
| ID-102 | Successful authentication from unfamiliar context | Successful use of a valid account from an unexpected context may increase identity risk | Success state plus device/location familiarity fields | Validate user/session context and strengthen conditional access/device controls where appropriate | Fresh telemetry confirms expected context or control enforcement | T1078 |
| ID-103 | Successful privileged authentication without MFA evidence | Privileged access without strong authentication materially increases account-abuse exposure | Privilege flag, success state, MFA evidence | Enforce MFA for privileged access and validate policy effectiveness | Fresh telemetry demonstrates MFA-backed privileged authentication | T1078.002 |

## Validation Principles

1. **Administrative closure is not technical closure.** A ticket state alone is insufficient.
2. **Fresh evidence is required.** Revalidation should use a new export or assessment after the change.
3. **Control state and effectiveness are separate.** A setting may be configured but still require operational evidence that it works as intended.
4. **Exceptions do not erase exposure.** Accepted risk should be time-bound, owned, approved, and reviewed separately from technical severity.
5. **ATT&CK mappings are contextual.** They explain adversary relevance but do not establish compromise.

## Evidence Quality Levels

| Level | Description | Closure use |
|---|---|---|
| Insufficient | Claim or ticket note without technical proof | Reject closure |
| Partial | Change reference exists but post-change state is missing | Keep open / needs evidence |
| Adequate | Changed state plus fresh technical validation | Eligible for validation |
| Strong | Changed state, fresh validation, accountable owner, and repeatable evidence trail | Preferred closure standard |

## Scope Limitation

The matrix applies only to the synthetic controls implemented in this repository. It is not a complete Active Directory benchmark and should not be treated as a substitute for an enterprise identity architecture review, CIS/Microsoft security baseline assessment, or authorized production validation.
