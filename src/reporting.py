"""Reporting helpers for the defensive AD lab."""
from __future__ import annotations

from collections import Counter
from .ad_posture import Finding, posture_score


def render_markdown(findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [
        "# Active Directory Security Assessment",
        "",
        f"**Posture score:** {posture_score(findings)}/100",
        "",
        "## Executive summary",
        "",
        f"Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}",
        "",
        "This report is generated from synthetic/offline directory metadata and is intended for defensive validation only.",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No findings were identified by the implemented controls.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### {index}. [{finding.severity.upper()}] {finding.title}",
            "",
            f"- **Control:** `{finding.control_id}`",
            f"- **Affected object:** `{finding.asset}`",
            f"- **Evidence:** {finding.evidence}",
            f"- **Remediation:** {finding.remediation}",
            f"- **Validation:** {finding.validation}",
            f"- **MITRE ATT&CK:** {', '.join(finding.mitre_attack) if finding.mitre_attack else 'N/A'}",
            "",
        ])
    return "\n".join(lines) + "\n"
