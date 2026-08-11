#!/usr/bin/env python3.13
"""PickleScan wrapper: normalize scanner output to the unified verdict schema.

Reads a target path from argv, runs PickleScan's Python API, and prints one
JSON object (see docs/verdict-schema.md) to stdout. Exit codes mirror the
PickleScan CLI: 0 clean, 1 malware, 2 error.
"""

import argparse
import io
import json
import logging
import os
import sys

from picklescan.scanner import (
    SafetyLevel,
    ScanFilter,
    scan_directory_path,
    scan_file_path,
)

VERSION = "1.0.5"
COMMIT = "f15d54d"


def main() -> int:
    parser = argparse.ArgumentParser(description="PickleScan verdict wrapper")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--strict", action="store_true", help="Promote suspicious globals to dangerous")
    args = parser.parse_args()

    # Capture scanner log output as raw_output for audit.
    raw_buf = io.StringIO()
    handler = logging.StreamHandler(raw_buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("picklescan")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    target = os.path.abspath(args.path)
    if not os.path.exists(target):
        print(json.dumps({
            "scanner": "picklescan",
            "version": VERSION,
            "commit": COMMIT,
            "target": args.path,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned_files": 0, "infected_files": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": f"Path {args.path} does not exist",
        }))
        return 2

    try:
        if os.path.isdir(target):
            scan_result = scan_directory_path(target, scan_filter=ScanFilter(), strict=args.strict)
        else:
            scan_result = scan_file_path(target, strict=args.strict)
    except Exception as exc:  # noqa: BLE001 - any scanner failure maps to error
        print(json.dumps({
            "scanner": "picklescan",
            "version": VERSION,
            "commit": COMMIT,
            "target": args.path,
            "verdict": "error",
            "exit_code": 2,
            "findings": [],
            "summary": {"scanned_files": 0, "infected_files": 0, "dangerous": 0, "suspicious": 0},
            "raw_output": f"Scan failed: {exc}",
        }))
        return 2

    findings = [
        {"module": g.module, "name": g.name, "safety": g.safety.value}
        for g in scan_result.globals
        if g.safety in (SafetyLevel.Dangerous, SafetyLevel.Suspicious)
    ]
    dangerous = sum(1 for f in findings if f["safety"] == "dangerous")
    suspicious = sum(1 for f in findings if f["safety"] == "suspicious")

    if scan_result.scan_err:
        verdict = "error"
        exit_code = 2
    elif scan_result.issues_count > 0:
        verdict = "malicious"
        exit_code = 1
    else:
        verdict = "benign"
        exit_code = 0

    print(json.dumps({
        "scanner": "picklescan",
        "version": VERSION,
        "commit": COMMIT,
        "target": args.path,
        "verdict": verdict,
        "exit_code": exit_code,
        "findings": findings,
        "summary": {
            "scanned_files": scan_result.scanned_files,
            "infected_files": scan_result.infected_files,
            "dangerous": dangerous,
            "suspicious": suspicious,
        },
        "raw_output": raw_buf.getvalue().strip(),
    }))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
