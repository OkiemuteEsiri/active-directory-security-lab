"""Command-line interface for offline Active Directory posture assessment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ad_posture import DirectoryObject, assess_directory
from .reporting import render_markdown


def load_objects(path: str | Path) -> list[DirectoryObject]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("inventory must be a JSON array")
    return [DirectoryObject(**item) for item in payload]


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic/offline AD identity posture")
    parser.add_argument("inventory", help="Path to JSON directory inventory")
    parser.add_argument("--output", default="reports/generated-assessment.md", help="Markdown report path")
    args = parser.parse_args()

    findings = assess_directory(load_objects(args.inventory))
    report = render_markdown(findings)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Wrote {len(findings)} findings to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
