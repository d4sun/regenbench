#!/usr/bin/env python3
"""T1.3 — Load pretrained DynaHug oracle; sanity-check on a known-benign model.

The T0.7 dynahug image already bundles the pretrained text-generation OCSVM
(oneclass_svm_model/scaler/vectorizer.pkl) and the wrapper scores without
retraining. This script closes the remaining gap: it fetches a small *real*
HuggingFace text-generation checkpoint (in-distribution for that OCSVM),
runs it through the oracle container, and records the decision_score as a
working-checkpoint record.

The model file is fetched at runtime and kept OUT of git; only the recorded
JSON (reference/oracle-sanity.json) is committed.

Usage:
    python3 scripts/oracle_sanity.py [--model sshleifer/tiny-gpt2] \
        [--model-file path/to/pytorch_model.bin] \
        [--out reference/oracle-sanity.json]

--model-file uses an already-downloaded checkpoint instead of fetching.

Prereqs: regenbench/dynahug image built (containers/dynahug), and from the
repo root (so `pipeline` is importable) or with PYTHONPATH=<repo root>.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

from pipeline.scanners import run_scan

DEFAULT_MODEL = "sshleifer/tiny-gpt2"
BIN_FILE = "pytorch_model.bin"
IMAGE = "regenbench/dynahug:latest"


def main() -> int:
    ap = argparse.ArgumentParser(prog="oracle_sanity", description=__doc__)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--model-file", default=None,
                    help="use an already-downloaded pytorch_model.bin instead of fetching")
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--out", default="reference/oracle-sanity.json")
    ap.add_argument("--keep", action="store_true", help="keep the downloaded copy (default removes)")
    args = ap.parse_args()

    if args.model_file:
        bin_path = os.path.abspath(args.model_file)
        if not os.path.isfile(bin_path):
            sys.exit(f"model file not found: {bin_path}")
    else:
        try:
            from huggingface_hub import snapshot_download
            repo = snapshot_download(repo_id=args.model, allow_patterns=[BIN_FILE, "config.json"])
        except ImportError:
            sys.exit("huggingface_hub not installed (pip install huggingface_hub)")
        bin_path = os.path.join(repo, BIN_FILE)
        if not os.path.isfile(bin_path):
            sys.exit(f"model {args.model} has no {BIN_FILE}; cannot torch.load")

    sha = hashlib.sha256()
    with open(bin_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)

    with tempfile.TemporaryDirectory(prefix="dynahug-sanity-") as td:
        # the oracle mounts /artifact and expects a torch checkpoint
        target = os.path.join(td, "model.pt")
        try:
            os.link(bin_path, target)
        except OSError:
            import shutil
            shutil.copyfile(bin_path, target)

        out, err = run_scan(args.backend, args.image, target, timeout=180)
        if err:
            sys.exit(f"oracle run failed: {err}")
        if out is None:
            sys.exit("oracle produced no verdict")

        record = {
            "task": "T1.3",
            "model": args.model if not args.model_file else f"local:{os.path.basename(args.model_file)}",
            "file": BIN_FILE,
            "sha256": sha.hexdigest(),
            "image": args.image,
            "verdict": out.get("verdict"),
            "exit_code": out.get("exit_code"),
            "decision_score": out.get("decision_score"),
            "note": (
                "In-distribution text-generation checkpoint: a positive "
                "decision_score / exit 0 is the expected benign path of the "
                "pretrained OCSVM (arXiv:2604.19438 default model)."
            ),
            "raw_output_tail": (out.get("raw_output") or "")[-2000:],
        }
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(record, f, indent=2)
        print(json.dumps(record, indent=2))

    return 0 if out.get("exit_code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
