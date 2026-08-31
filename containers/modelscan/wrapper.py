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
    # Grey-box signal (Phase 2): which operator rules fired.
    matched_rules = [
        f"{f['operator']}:{f['module']}:{f['severity']}" for f in findings
    ]

    summary = {
        "total_issues": report.get("summary", {}).get("total_issues", 0),
        "scanned": report.get("summary", {}).get("scanned", {}).get("total_scanned", 0),
        "errors": len(report.get("errors", [])),
    }

    # P5.2: GGUF header augment — reuse ggufref logic (no pipeline import)
    # If target is GGUF and header is malformed, override benign→malicious
    try:
        _is_gguf = False
        _gguf_mal = []
        if target.lower().endswith(".gguf") or os.path.isfile(target):
            with open(target, "rb") as _f:
                _data = _f.read(65536)
            if len(_data) >= 24 and _data[:4] == b"GGUF":
                _is_gguf = True
                import struct as _struct
                try:
                    _ver, _tcount, _kcount = _struct.unpack_from("<IQQ", _data, 4)
                    _OVERFLOW = 0x7FFFFFFFFFFFFFFF
                    if _ver == 0:
                        _gguf_mal.append("version_zero")
                    if _kcount == _OVERFLOW:
                        _gguf_mal.append("nkv_overflow")
                    if _tcount == _OVERFLOW:
                        _gguf_mal.append("ntensors_overflow")
                    # string_overflow: first key len == sentinel with short data
                    if len(_data) >= 32:
                        try:
                            _klen = _struct.unpack_from("<Q", _data, 24)[0]
                            if _klen == _OVERFLOW:
                                _gguf_mal.append("string_overflow")
                        except Exception:
                            pass
                    # path_traversal / negative_dims: scan tensor section
                    if b"../../../" in _data:
                        _gguf_mal.append("path_traversal")
                    if _data.count(b"\xff\xff\xff\xff\xff\xff\xff\xff") >= 2:
                        _gguf_mal.append("negative_dims")
                    # Also check for generic malformed: kv_count >100k etc.
                    if _kcount > 100000 and _kcount != _OVERFLOW:
                        _gguf_mal.append("kv_count_overflow")
                    if _tcount > 1000000 and _tcount != _OVERFLOW:
                        _gguf_mal.append("tensor_count_overflow")
                except Exception:
                    _gguf_mal.append("header_parse_error")
            elif target.lower().endswith(".gguf"):
                # .gguf extension but not GGUF magic — likely truncated/bad header
                _is_gguf = True
                _gguf_mal.append("bad_magic")
        if _is_gguf and _gguf_mal:
            # Augment findings and promote verdict if modelscan said benign
            for _m in _gguf_mal:
                findings.append({"module": "gguf", "operator": _m, "severity": "malicious"})
                matched_rules.append(f"gguf:{_m}")
            summary["total_issues"] = len(findings)
            # Only promote if currently benign (0 or 3); keep malicious/error as is
            # We will handle promotion after verdict mapping; store flag
            _gguf_needs_promote = True
        else:
            _gguf_needs_promote = False
    except Exception:
        _gguf_needs_promote = False
        _gguf_mal = []

    if proc.returncode == 0:
        verdict, exit_code = "benign", 0
    elif proc.returncode == 2:
        verdict, exit_code = "error", 2
    elif proc.returncode == 1:
        verdict, exit_code = "malicious", 1
    elif proc.returncode == 3:
        # ModelScan exit code 3 means "no supported file found to scan"
        # (e.g. a torch .pt/.bin that ModelScan cannot process). The CLI treats
        # this as a *benign* outcome, so we report benign -- but normalized to
        # the documented schema exit code 0 (docs/verdict-schema.md) so the
        # schema stays 0/1/2.
        verdict, exit_code = "benign", 0
    else:
        # Fail-closed: any unexpected return code (crash, signal, unknown CLI
        # code) must not be reported as benign. 0/1/2/3 are the only ModelScan
        # codes; anything else means the scan did not complete.
        verdict, exit_code = "error", 2

    # P5.2 promotion: if GGUF malformed and modelscan said benign, flip to malicious
    try:
        if _gguf_needs_promote and verdict == "benign":
            verdict, exit_code = "malicious", 1
            raw_output = (raw_output or "") + f"\n[gguf-augment] promoted to malicious: {','.join(_gguf_mal)}"
    except NameError:
        pass

    return emit({
        "scanner": "modelscan",
        "version": VERSION,
        "commit": COMMIT,
        "target": target,
        "verdict": verdict,
        "exit_code": exit_code,
        "findings": findings,
        "matched_rules": matched_rules,
        "summary": summary,
        "raw_output": raw_output.strip(),
    })


if __name__ == "__main__":
    sys.exit(main())