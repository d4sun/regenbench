#!/usr/bin/env python3
"""GGUF reference-oracle wrapper: normalize loader output to the unified
verdict schema (docs/verdict-schema.md).

Classification rules (fail-closed):
  * ``malicious``  -- reference reader rejects the header (malformed-header
     attacks) or the chat template is a Jinja2 SSTI payload (CVE-2024-34359).
  * ``benign``     -- parses cleanly with no dangerous chat template.
  * ``error``      -- the artifact could not be read at all.
Exit codes: 0 benign / 1 malicious / 2 error.
"""

import json
import os
import subprocess
import sys

VERSION = "0.1.0"
LOADER = "/usr/local/bin/gguf-loader"


def emit(obj) -> int:
    print(json.dumps(obj))
    return obj.get("exit_code", 2)


def main() -> int:
    base = {
        "scanner": "ggufref",
        "version": VERSION,
        "commit": "regenbench-gguf",
        "target": "",
        "verdict": "error",
        "exit_code": 2,
        "decision_score": None,
        "findings": [],
        "summary": {"load_ok": False, "tensors": 0, "kv": 0},
        "raw_output": "",
    }

    if len(sys.argv) < 2:
        return emit({**base, "raw_output": "Missing required target path"})

    target = sys.argv[1]
    if not os.path.exists(target):
        return emit({**base, "target": target, "raw_output": f"Path {target} does not exist"})

    try:
        proc = subprocess.run(
            ["python3.13", LOADER, target],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return emit({**base, "target": target,
                     "findings": ["reference-loader-timeout"],
                     "raw_output": "reference loader timed out"})

    try:
        detail = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return emit({**base, "target": target,
                     "findings": ["reference-loader-error"],
                     "raw_output": (proc.stdout or proc.stderr or "").strip()[-400:]})

    header = detail.get("header", {})
    malformed = detail.get("malformed", [])
    ssti = detail.get("ssti_suspicious", [])
    triggered = bool(detail.get("triggered"))
    load_ok = bool(detail.get("load_ok"))

    findings = list(malformed) + [f"ssti:{s}" for s in ssti]
    if detail.get("reference_error"):
        findings.append(f"reference-error:{detail['reference_error'][:120]}")
    if triggered:
        findings.append("ssti:triggered")

    verdict, exit_code, decision_score = "benign", 0, 1.0
    if malformed:
        verdict, exit_code, decision_score = "malicious", 1, -1.0
    elif ssti or triggered:
        verdict, exit_code, decision_score = "malicious", 1, -1.0
    # else: benign (reader rejection without an attack signature stays benign)

    raw = [
        f"ggufref {VERSION} | load_ok={load_ok}",
        f"header: magic={header.get('magic')} version={header.get('version')} "
        f"tensor_count={header.get('tensor_count')} kv_count={header.get('kv_count')}",
    ]
    if detail.get("reference_error"):
        raw.append(f"reference_error: {detail['reference_error']}")
    if malformed:
        raw.append("malformed: " + ", ".join(malformed))
    if detail.get("chat_template_present"):
        raw.append(f"chat_template: ssti_signals={ssti} triggered={triggered}")
    if detail.get("render_error"):
        raw.append(f"render_error: {detail['render_error']}")

    return emit({
        **base,
        "target": target,
        "verdict": verdict,
        "exit_code": exit_code,
        "decision_score": decision_score,
        "findings": findings,
        "summary": {
            "load_ok": load_ok,
            "tensors": header.get("tensor_count"),
            "kv": header.get("kv_count"),
        },
        "raw_output": "\n".join(raw)[:20000],
    })


if __name__ == "__main__":
    sys.exit(main())