# Attack-Path Remediation Workflow

This lab treats an identity attack path as a chain of relationships that could allow a low-privilege principal to reach a sensitive identity or system. The included dataset is synthetic.

## Assessment sequence

1. Identify the starting principal and protected target.
2. Enumerate group membership, administrative rights, active-session exposure, delegation and other trust relationships.
3. Calculate the shortest meaningful paths to privileged targets.
4. Review each edge for necessity, business ownership and compensating controls.
5. Remove or constrain the weakest relationship rather than treating every node as equally risky.
6. Re-run the graph analysis and document whether the path was removed or materially lengthened.

## Defensive priorities

| Condition | Risk | Defensive action |
|---|---|---|
| Broad administrative group membership | High | Apply least privilege and role-specific groups |
| Privileged session on lower-trust endpoint | High | Use privileged access workstations and session controls |
| Service account with excessive rights | High | Reduce rights, rotate credentials and prefer managed identities/accounts |
| Legacy authentication dependency | Medium-High | Inventory dependencies and migrate toward stronger authentication |
| Unnecessary delegation | High | Remove delegation or scope it to the minimum required service |

## ATT&CK-oriented detection context

Relevant defensive review areas include account discovery (T1087), permission groups discovery (T1069), remote services (T1021), valid accounts (T1078), and account manipulation (T1098). ATT&CK mapping describes the behaviors defenders should be able to observe; it is not evidence that a technique occurred.

## Validation evidence

A remediation record should capture the original path, control owner, approved change, post-change graph, remaining path length, telemetry available for related behaviors and any accepted residual risk.
