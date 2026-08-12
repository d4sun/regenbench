#!/usr/bin/env python3
"""T1.4 - Smoke test: scanner panel + oracle on 6 sanity models.

Runs the full panel (picklescan/modelscan/fickling/modeltracer) plus the
DynaHug oracle against a 6-model sanity set (3 obviously-benign + 3 obviously-
malicious) and records the verdict log to reference/sanity-verdict-log.json.
Purpose is to confirm each tool runs correctly and returns well-formed verdicts
in the local containers, NOT to reproduce paper numbers.

Sanity set (mixed: committed corpus + one real HF text-generation model):

    benign    ci/corpus/pkl/benign/benign_01.pkl       safe pickle
    benign    ci/corpus/torch/benign/benign.pt         safe torch state_dict
    benign    <real model> pytorch_model.bin           text-generation model
    malicious ci/corpus/pkl/malicious/malicious_01.pkl __reduce__ pickle
    malicious ci/corpus/torch/malicious/malicious.pt  __reduce__ torch
    malicious ci/corpus/pkl/malicious/malicious_02.pkl eval pickle

The real-model entry is fetched at runtime (like scripts/oracle_sanity.py, T1.3)
and staged as a .pt so modelscan + the oracle can consume it; the file itself
is not committed. For that entry the oracle is expected to return benign / exit
0 with a positive decision_score (in-distribution), demonstrating the benign
path of the pretrained OCSVM.

Usage:
    python3 scripts/sanity_smoke.py [--model openai-community/gpt2]
        [--backend podman] [--out reference/sanity-verdict-log.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

from pipeline.scanners import run_scan

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = {
    "picklescan": "regenbench/picklescan:latest",
    "modelscan": "regenbench/modelscan:latest",
    "fickling": "regenbench/fickling:latest",
    "modeltracer": "regenbench/modeltracer:latest",
    "dynahug": "regenbench/dynahug:latest",
}
DEFAULT_MODEL = "openai-community/gpt2"

# artifact (repo-relative) -> scanners to run, in order of appearance.
MANIFEST = {
    "ci/corpus/pkl/benign/benign_01.pkl": {
        "expected": "benign",
        "scanners": ["picklescan", "fickling", "modeltracer"],
    },
    "ci/corpus/torch/benign/benign.pt": {
        "expected": "benign",
        "scanners": ["modelscan", "dynahug"],
    },
    "__real_model__": {
        "expected": "benign",
        "scanners": ["modelscan", "dynahug"],
        "note": (
            "real HF text-generation model; dynahug in-distribution -> "
            "benign / exit 0 / positive decision_score"
        ),
    },
    "ci/corpus/pkl/malicious/malicious_01.pkl": {
        "expected": "malicious",
        "scanners": ["picklescan", "fickling", "modeltracer"],
    },
    "ci/corpus/torch/malicious/malicious.pt": {
        "expected": "malicious",
        "scanners": ["modelscan", "dynahug"],
    },
    "ci/corpus/pkl/malicious/malicious_02.pkl": {
        "expected": "malicious",
        "scanners": ["picklescan", "fickling", "modeltracer"],
    },
}


def main() -> int:
    ap = argparse.ArgumentParser(prog="sanity_smoke", description=__doc__)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--model-file", default=None,
                    help="use an already-downloaded pytorch_model.bin instead of fetching")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--out", default="reference/sanity-verdict-log.json")
    args = ap.parse_args()

    staged: dict[str, str] = {}
    tmp = tempfile.mkdtemp(prefix="sanity-smoke-")
    try:
        for entry, meta in MANIFEST.items():
            if entry != "__real_model__":
                staged[entry] = os.path.join(ROOT, entry)
            elif args.model_file:
                src, sha = stage_local(args.model_file, tmp)
                staged[entry] = src
                print(f"[sanity] real model from {args.model_file}: {sha[:16]}... staged")
                meta["sha256"] = sha
            else:
                src, sha = fetch_model(args.model, tmp)
                staged[entry] = src
                print(f"[sanity] real model {args.model}: {sha[:16]}... staged")
                meta["sha256"] = sha

        log = {
            "task": "T1.4",
            "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "backend": args.backend,
            "model": args.model,
            "expectations": {
                k: {"expected": v["expected"], "scanners": v["scanners"]}
                for k, v in MANIFEST.items()
            },
            "results": [],
        }

        allpass = True
        count = 0
        for entry, meta in MANIFEST.items():
            src = staged[entry]
            for scanner in meta["scanners"]:
                count += 1
                t0 = time.time()
                out, err = run_scan(args.backend, IMAGES[scanner], src, timeout=300)
                dur = round(time.time() - t0, 2)
                r = {
                    "artifact": None if entry == "__real_model__" else entry,
                    "model": args.model if entry == "__real_model__" else None,
                    "scanner": scanner,
                    "expected": meta["expected"],
                    "duration": dur,
                }
                if err:
                    r.update({"status": "error", "error": err})
                    allpass = False
                else:
                    r.update({
                        "status": "ran",
                        "verdict": out.get("verdict"),
                        "exit_code": out.get("exit_code"),
                        "decision_score": out.get("decision_score"),
                    })
                if scanner == "dynahug" and entry == "__real_model__":
                    ok = r.get("verdict") == "benign" and r.get("decision_score", -99) > 0
                elif scanner == "dynahug":
                    # committed micro-checkpoints are OOD per the T0.7 caveat;
                    # the faithful pretrained output is malicious.
                    ok = r.get("verdict") == "malicious"
                else:
                    ok = r.get("verdict") == meta["expected"]
                r["ok"] = bool(ok)
                allpass = allpass and r["ok"]
                log["results"].append(r)
                flag = "PASS" if r["ok"] else "FAIL"
                label = r.get("artifact") or f"real:{args.model}"
                print(f"[{flag}] {scanner:<11} {label:<44} "
                      f"{r.get('verdict','?'):<9} exit={r.get('exit_code')} "
                      f"score={r.get('decision_score')} {dur}s")

        log["passed"] = allpass
        log["tasks"] = count
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(log, f, indent=2)
        print(f"\n{sum(1 for r in log['results'] if r['ok'])}/{count} checks passed -> {args.out}")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    return 0 if allpass else 1


def stage_local(model_bin: str, workdir: str) -> tuple[str, str]:
    """Stage an already-downloaded pytorch_model.bin as model.pt (no network)."""
    tar = os.path.abspath(model_bin)
    sha = hashlib.sha256()
    with open(tar, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    target = os.path.join(workdir, "model.pt")
    import shutil
    shutil.copyfile(tar, target)
    return target, sha.hexdigest()


def fetch_model(model: str, workdir: str) -> tuple[str, str]:
    """Download the real checkpoint (not committed) and stage as model.pt."""
    try:
        from huggingface_hub import snapshot_download
        repo = snapshot_download(repo_id=model, allow_patterns=["pytorch_model.bin"])
    except ImportError:
        sys.exit("huggingface_hub not installed (pip install huggingface_hub)")
    bin_path = os.path.join(repo, "pytorch_model.bin")
    if not os.path.isfile(bin_path):
        sys.exit(f"model {model} has no pytorch_model.bin")
    sha = hashlib.sha256()
    with open(bin_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    target = os.path.join(workdir, "model.pt")
    try:
        os.link(bin_path, target)
    except OSError:
        import shutil
        shutil.copyfile(bin_path, target)
    return target, sha.hexdigest()


if __name__ == "__main__":
    sys.exit(main())