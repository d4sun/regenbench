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

# Framework plumbing present in every legitimate torch checkpoint
# (_rebuild_tensor_v2 et al.). Fickling's stdlib-centric heuristic flags these
# as LIKELY_UNSAFE ("imports a non-stdlib module"), which would render the
# scanner useless on torch artifacts (100% FP -- even the benign CI corpus
# trips it). Mirror PickleScan's precedent: suppress ONLY these exact
# import pairs. Deliberately narrow -- dynamic sinks such as torch.load,
# torch.jit.*, eval/exec are NOT allowlisted and keep firing.
_TORCH_ALLOWLIST = {
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_tensor_v3"),
    ("torch._utils", "_rebuild_tensor"),
    ("torch.storage", "_load_from_bytes"),
    ("torch.storage", "_rebuild_tensor_from_storage"),
    ("collections", "OrderedDict"),
    ("argparse", "Namespace"),
    ("torch", "FloatStorage"),
    ("torch", "HalfStorage"),
    ("torch", "DoubleStorage"),
    ("torch", "BFloat16Storage"),
    ("torch", "ByteStorage"),
    ("torch", "CharStorage"),
    ("torch", "ShortStorage"),
    ("torch", "IntStorage"),
    ("torch", "LongStorage"),
    ("torch", "BoolStorage"),
}

import re as _re

_IMPORT_RE = _re.compile(r"`from ([\w.]+) import ([\w.]+)`")


def _is_allowlisted(analysis: str) -> bool:
    """True only when *every* non-stdlib import in the analysis is torch
    plumbing on the allowlist.

    Fickling reports one combined ``analysis`` string per record, so a record
    can list legitimate torch imports *and* a genuinely malicious one (e.g.
    ``IPython.utils.process.system``). The record may only be suppressed when
    ALL its imports are allowlisted — otherwise the malicious finding is
    swallowed and a real detection is reported as benign.
    """
    imports = _IMPORT_RE.findall(analysis or "")
    if not imports:
        return False
    return all((m, n) in _TORCH_ALLOWLIST for m, n in imports)


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

    # P5.1: GGUF format pre-filter — fickling is pickle-only, GGUF bytes as pickle
    # would be 100% FP (24/24 benign). Check magic and return unsupported-format.
    try:
        with open(target, "rb") as _f:
            _gguf_magic = _f.read(4)
        if _gguf_magic == b"GGUF":
            return emit({
                "scanner": "fickling",
                "version": VERSION,
                "commit": COMMIT,
                "target": target,
                "verdict": "error",
                "exit_code": 2,
                "findings": [{"rule": "unsupported-format:gguf"}],
                "matched_rules": ["unsupported-format:gguf"],
                "summary": {"scanned": 0, "dangerous": 0, "suspicious": 0},
                "raw_output": "unsupported format: gguf for pickle scanner (magic GGUF)",
            })
        # Also check extension for truncated header case (bad_magic.gguf with bad magic but .gguf ext)
        if target.lower().endswith(".gguf"):
            return emit({
                "scanner": "fickling",
                "version": VERSION,
                "commit": COMMIT,
                "target": target,
                "verdict": "error",
                "exit_code": 2,
                "findings": [{"rule": "unsupported-format:gguf"}],
                "matched_rules": ["unsupported-format:gguf"],
                "summary": {"scanned": 0, "dangerous": 0, "suspicious": 0},
                "raw_output": "unsupported format: gguf extension for pickle scanner",
            })
    except OSError:
        pass

    if os.path.exists(REPORT_FILE):
        os.remove(REPORT_FILE)

    # Torch checkpoints (.pt/.pth) are ZIP archives. Fickling is a raw-pickle
    # AST analyzer and cannot parse torch-zip natively (`fickling --trace` on a
    # .pt -> "No pickle files detected"). Surface this as an explicit
    # format-coverage gap (like the GGUF pre-filter above) instead of
    # force-extracting the embedded member, which would be scanning beyond the
    # scanner's native capability. The pipeline excludes torch artifacts from
    # Fickling via SCANNERS exts (see pipeline/scanners.py).
    try:
        with open(target, "rb") as _f:
            _magic = _f.read(4)
        if _magic.startswith(b"PK\x03\x04"):
            return emit({
                "scanner": "fickling",
                "version": VERSION,
                "commit": COMMIT,
                "target": target,
                "verdict": "error",
                "exit_code": 2,
                "findings": [{"rule": "unsupported-format:torch-zip"}],
                "matched_rules": ["unsupported-format:torch-zip"],
                "summary": {"scanned": 0, "dangerous": 0, "suspicious": 0},
                "raw_output": "unsupported format: torch-zip archive for raw-pickle "
                              "scanner (magic PK)",
            })
    except OSError:
        pass

    scan_target = target
    cmd = [
        "fickling",
        "--check-safety",
        "--json-output", REPORT_FILE,
        "--print-results",
        scan_target,
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
    suppressed = 0
    for rec in records:
        severity = rec.get("severity", "LIKELY_SAFE")
        if severity in ("LIKELY_UNSAFE", "LIKELY_OVERTLY_MALICIOUS", "OVERTLY_MALICIOUS"):
            dangerous += 1
        elif severity in ("POSSIBLY_UNSAFE", "SUSPICIOUS"):
            suspicious += 1
        if severity == "LIKELY_SAFE":
            continue
        analysis = rec.get("analysis", "")
        if _is_allowlisted(analysis):
            suppressed += 1
            continue
        findings.append({
            "rule": f"fickling:{severity}",
            "severity": severity,
            "analysis": analysis,
            "detailed_results": rec.get("detailed_results", {}),
        })

    if proc.returncode == 2:
        verdict, exit_code = "error", 2
    elif proc.returncode == 1:
        # Exit 1 means "some finding fired"; after allowlist suppression only
        # non-plumbing findings justify a malicious verdict.
        verdict, exit_code = ("malicious", 1) if findings else ("benign", 0)
    elif proc.returncode == 0:
        verdict, exit_code = "benign", 0
    else:
        # Fail-closed: an unexpected exit code (crash/signal) means the scan did
        # not complete; never report it as benign.
        verdict, exit_code = "error", 2

    # Grey-box signal (Phase 2): severity buckets that fired.
    matched_rules = [f["rule"] for f in findings]

    if suppressed:
        raw_output = f"[allowlist] {suppressed} torch-plumbing finding(s) suppressed]\n" + raw_output

    return emit({
        "scanner": "fickling",
        "version": VERSION,
        "commit": COMMIT,
        "target": target,
        "verdict": verdict,
        "exit_code": exit_code,
        "findings": findings,
        "matched_rules": matched_rules,
        "summary": {
            "scanned": 1,
            "dangerous": dangerous,
            "suspicious": suspicious,
        },
        "raw_output": raw_output.strip(),
    })


if __name__ == "__main__":
    sys.exit(main())