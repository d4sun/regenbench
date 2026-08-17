#!/usr/bin/env python3
"""Fickling wrapper: normalize scanner output to the unified verdict schema.

Reads a target path from argv, invokes the Fickling CLI in check-safety mode
with JSON output, and prints one JSON object (docs/verdict-schema.md) to
stdout. Exit codes 0 benign / 1 malicious / 2 error, mirroring Fickling's
ClamAV-compatible exit codes.
"""

import json
import os
import subprocess
import sys

VERSION = "0.1.12"
COMMIT = "c3c695c"
REPORT_FILE = "/tmp/fickling-results.json"


def emit(record: dict) -> int:
    print(json.dumps(record))
    return record["exit_code"]


def parse_report() -> list[dict]:
    """Fickling appends one JSON object per stacked pickle; parse them all."""
    if not os.path.exists(REPORT_FILE):
        return []
    try:
        with open(REPORT_FILE, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []

    records = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx] in " \t\r\n":
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        records.append(obj)
        idx = end
    return records


def main() -> int:
    if len(sys.argv) < 2:
        return emit({
            "scanner": "fickling",
            "version": VERSION,
            "commit": COMMIT,
            "target": "",
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": "Missing required target path",
        })

    target = sys.argv[1]
    if not os.path.exists(target):
        return emit({
            "scanner": "fickling",
            "version": VERSION,
            "commit": COMMIT,
            "target": target,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": f"Path {target} does not exist",
        })

    # fickling reads the target as a file; a directory would raise an uncaught
    # IsADirectoryError -> process exit 1 -> a false `malicious` verdict.
    if os.path.isdir(target):
        return emit({
            "scanner": "fickling",
            "version": VERSION,
            "commit": COMMIT,
            "target": target,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": f"Path {target} is a directory, not a pickle file",
        })

    if os.path.exists(REPORT_FILE):
        os.remove(REPORT_FILE)

    cmd = [
        "fickling",
        "--check-safety",
        "--json-output", REPORT_FILE,
        "--print-results",
        target,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return emit({
            "scanner": "fickling",
            "version": VERSION,
            "commit": COMMIT,
            "target": target,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": "fickling timed out",
        })

    raw_output = (proc.stdout or "") + (proc.stderr or "")
    records = parse_report()

    findings = []
    dangerous = 0
    suspicious = 0
    for rec in records:
        severity = rec.get("severity", "LIKELY_SAFE")
        if severity in ("LIKELY_UNSAFE", "LIKELY_OVERTLY_MALICIOUS", "OVERTLY_MALICIOUS"):
            dangerous += 1
        elif severity in ("POSSIBLY_UNSAFE", "SUSPICIOUS"):
            suspicious += 1
        if severity == "LIKELY_SAFE":
            continue
        findings.append({
            "severity": severity,
            "analysis": rec.get("analysis", ""),
            "detailed_results": rec.get("detailed_results", {}),
        })

    if proc.returncode == 2:
        verdict, exit_code = "error", 2
    elif proc.returncode == 1:
        verdict, exit_code = "malicious", 1
    elif proc.returncode == 0:
        verdict, exit_code = "benign", 0
    else:
        # Fail-closed: an unexpected exit code (crash/signal) means the scan did
        # not complete; never report it as benign.
        verdict, exit_code = "error", 2

    return emit({
        "scanner": "fickling",
        "version": VERSION,
        "commit": COMMIT,
        "target": target,
        "verdict": verdict,
        "exit_code": exit_code,
        "findings": findings,
        "summary": {
            "scanned": 1,
            "dangerous": dangerous,
            "suspicious": suspicious,
        },
        "raw_output": raw_output.strip(),
    })


if __name__ == "__main__":
    sys.exit(main())