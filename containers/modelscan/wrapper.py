#!/usr/bin/env python3
"""ModelScan wrapper: normalize scanner output to the unified verdict schema.

Reads a target path from argv, invokes the ModelScan CLI in JSON reporting
mode, and prints one JSON object (docs/verdict-schema.md) to stdout. Exit
codes 0 benign / 1 malicious / 2 error, mirroring the ModelScan CLI.
"""

import json
import os
import subprocess
import sys

VERSION = "0.8.8"
COMMIT = "61fcec9"


def emit(scanner_data: dict) -> int:
    print(json.dumps(scanner_data))
    return scanner_data["exit_code"]


def main() -> int:
    if len(sys.argv) < 2:
        return emit({
            "scanner": "modelscan",
            "version": VERSION,
            "commit": COMMIT,
            "target": "",
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"total_issues": 0, "scanned": 0, "errors": 1},
            "raw_output": "Missing required target path",
        })

    target = sys.argv[1]
    if not os.path.exists(target):
        return emit({
            "scanner": "modelscan",
            "version": VERSION,
            "commit": COMMIT,
            "target": target,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"total_issues": 0, "scanned": 0, "errors": 1},
            "raw_output": f"Path {target} does not exist",
        })

    report_file = "/tmp/modelscan-report.json"
    cmd = ["modelscan", "-p", target, "-r", "json", "-o", report_file]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return emit({
            "scanner": "modelscan",
            "version": VERSION,
            "commit": COMMIT,
            "target": target,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"total_issues": 0, "scanned": 0, "errors": 1},
            "raw_output": "modelscan timed out",
        })

    raw_output = (proc.stdout or "") + (proc.stderr or "")

    report = {}
    if os.path.exists(report_file):
        try:
            with open(report_file, encoding="utf-8") as f:
                report = json.load(f)
        except (json.JSONDecodeError, OSError):
            report = {}

    findings = []
    for issue in report.get("issues", []):
        findings.append({
            "module": issue.get("module", ""),
            "operator": issue.get("operator", ""),
            "severity": issue.get("severity", ""),
        })

    summary = {
        "total_issues": report.get("summary", {}).get("total_issues", 0),
        "scanned": report.get("summary", {}).get("scanned", {}).get("total_scanned", 0),
        "errors": len(report.get("errors", [])),
    }

    if proc.returncode == 2:
        verdict, exit_code = "error", 2
    elif proc.returncode == 1:
        verdict, exit_code = "malicious", 1
    elif proc.returncode == 3:
        verdict, exit_code = "benign", 3
    else:
        verdict, exit_code = "benign", 0

    return emit({
        "scanner": "modelscan",
        "version": VERSION,
        "commit": COMMIT,
        "target": target,
        "verdict": verdict,
        "exit_code": exit_code,
        "findings": findings,
        "summary": summary,
        "raw_output": raw_output.strip(),
    })


if __name__ == "__main__":
    sys.exit(main())