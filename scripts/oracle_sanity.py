#!/usr/bin/env python3
"""Oracle regression guard: fail loudly on decision-score collapse (T1.3 / Plan Phase 4.5).

The Section 7a bug class was silent: the pretrained DynaHug OCSVM returned a
constant decision_function (~ -rho = -1.3489) for every input in this
environment, degrading the oracle to an all-"malicious" classifier without any
crash or error verdict. The single-model check cannot catch a degenerate
boundary; this guard scores a *diverse batch* of real benign checkpoints and
fails loudly when:

  * every score in the batch is (near-)identical   -> constant/collapsed output
  * no benign checkpoint scores positive           -> all-"malicious" collapse

Modes:
  default      single known-benign model working-checkpoint record (legacy).
  --batch N    score N diverse checkpoints from the benign corpus/split.

Use --model-dir to test a recalibrated oracle (DYNAHUG_MODEL_DIR); omit it to
test the image-embedded pretrained oracle.

Exit codes: 0 ok | 1 runtime failure | 2 COLLAPSE DETECTED.

Usage:
    python3 scripts/oracle_sanity.py --batch 8 \
        [--split-file real_benign_corpus/oracle-split.json --role eval] \
        [--model-dir real_benign_corpus/oracle-calibrated/current]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.scanners import full_image, run_scan  # noqa: E402

DEFAULT_MODEL = "sshleifer/tiny-gpt2"
BIN_FILE = "pytorch_model.bin"
IMAGE = "regenbench/dynahug:latest"
COLLAPSE_SPREAD_EPS = 1e-6


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_batch(split_file: str, role: str, corpus_dir: str, n: int) -> list[str]:
    """Diverse batch: one model per cluster rotation from the split list."""
    if split_file and Path(split_file).exists():
        wanted = set(json.loads(Path(split_file).read_text())[role])
        by_repo = {}
        for p in sorted(Path(corpus_dir).glob("*.bin")):
            stem = p.name[: -len(".bin")]
            repo = stem.split("__", 1)[1] if "__" in stem else stem
            if repo in wanted:
                by_repo[repo] = str(p)
        ordered = [by_repo[r] for r in sorted(by_repo)]
        if len(ordered) > n:  # stride-sample to maximize diversity
            step = len(ordered) / n
            ordered = [ordered[int(i * step)] for i in range(n)]
        return ordered
    fallback = Path(corpus_dir) / "*.bin"
    import glob
    return sorted(glob.glob(str(fallback)))[:n]


def run_batch(paths: list[str], backend: str, image_full: str,
              model_dir: str | None, timeout: int) -> list[dict]:
    out_recs = []
    for i, path in enumerate(paths, 1):
        out, err = run_scan(backend, image_full, path, timeout=timeout,
                            oracle_model_dir=model_dir)
        rec = {
            "artifact": Path(path).name,
            "sha256": sha256_of(path),
            "verdict": "error" if err or out is None else out.get("verdict"),
            "exit_code": None if err or out is None else out.get("exit_code"),
            "decision_score": None if err or out is None else out.get("decision_score"),
        }
        out_recs.append(rec)
        s = f"{rec['decision_score']:+.4f}" if isinstance(rec["decision_score"], (int, float)) else "  n/a"
        print(f"  [{i}/{len(paths)}] {rec['artifact'][:56]:<56} "
              f"{str(rec['verdict']):<10} {s}")
        sys.stdout.flush()
    return out_recs


def collapse_check(recs: list[dict]) -> dict:
    scores = [r["decision_score"] for r in recs
              if isinstance(r["decision_score"], (int, float))]
    check = {"n_scored": len(scores)}
    if len(scores) >= 3:
        spread = max(scores) - min(scores)
        std = statistics.stdev(scores)
        pos = sum(1 for s in scores if s > 0)
        check.update({
            "min": round(min(scores), 6),
            "max": round(max(scores), 6),
            "spread": round(spread, 6),
            "std": round(std, 6),
            "positive_rate": round(pos / len(scores), 4),
            "collapsed_constant": spread <= COLLAPSE_SPREAD_EPS,
            "collapsed_all_negative": pos == 0,
        })
        check["verdict"] = ("COLLAPSE" if (check["collapsed_constant"] or
                                           check["collapsed_all_negative"])
                            else "HEALTHY")
    else:
        check["verdict"] = "INDETERMINATE"
    return check


def main() -> int:
    ap = argparse.ArgumentParser(prog="oracle_sanity", description=__doc__)
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help="(single mode) HF repo id to fetch")
    ap.add_argument("--model-file", default=None,
                    help="use an already-downloaded pytorch_model.bin instead of fetching")
    ap.add_argument("--batch", type=int, default=0,
                    help="score N diverse benign checkpoints instead of one")
    ap.add_argument("--corpus", default="real_benign_corpus/all")
    ap.add_argument("--split-file", default="real_benign_corpus/oracle-split.json")
    ap.add_argument("--role", choices=["train", "eval"], default="eval")
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--model-dir", default=None,
                    help="oracle model dir override (omit => image-embedded pretrained)")
    ap.add_argument("--out", default="reference/oracle-sanity.json")
    args = ap.parse_args()

    image_full = full_image(args.image.replace(":latest", ""), ":latest") \
        if ":" in args.image else args.image

    if args.batch > 0:
        paths = pick_batch(args.split_file, args.role, args.corpus, args.batch)
        if len(paths) < 3:
            print(f"[oracle-sanity] FAIL: need >=3 artifacts for a batch, got "
                  f"{len(paths)} (corpus={args.corpus})")
            return 1
        print(f"[oracle-sanity] batch={args.batch} model_dir="
              f"{args.model_dir or '<image-embedded pretrained>'}")
        recs = run_batch(paths, args.backend, image_full, args.model_dir,
                         args.timeout)
        check = collapse_check(recs)
        record = {
            "task": "oracle-sanity-batch",
            "generated_at": __import__("time").strftime(
                "%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
            "model_dir": args.model_dir,
            "image": image_full,
            "batch": args.batch,
            "check": check,
            "results": recs,
        }
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(record, f, indent=2)
        print("\n=== Oracle sanity (batch) ===")
        print(json.dumps(check, indent=2))
        if check["verdict"] == "COLLAPSE":
            print("\n[GATE] FAIL: decision-score COLLAPSE detected -- the "
                  "oracle returns a near-constant score across a diverse benign "
                  "batch. Do not trust any bypass/FP numbers until fixed.")
            return 2
        if check["verdict"] == "INDETERMINATE":
            return 1
        print("\n[GATE] PASS: oracle decision scores are discriminative.")
        return 0

    # ---- legacy single-model working-checkpoint record ----
    if args.model_file:
        bin_path = os.path.abspath(args.model_file)
        if not os.path.isfile(bin_path):
            sys.exit(f"model file not found: {bin_path}")
    else:
        try:
            from huggingface_hub import snapshot_download
            repo = snapshot_download(repo_id=args.model,
                                     allow_patterns=[BIN_FILE, "config.json"])
        except ImportError:
            sys.exit("huggingface_hub not installed (pip install huggingface_hub)")
        bin_path = os.path.join(repo, BIN_FILE)
        if not os.path.isfile(bin_path):
            sys.exit(f"model {args.model} has no {BIN_FILE}; cannot torch.load")

    sha = sha256_of(bin_path)

    with tempfile.TemporaryDirectory(prefix="dynahug-sanity-") as td:
        target = os.path.join(td, "model.pt")
        try:
            os.link(bin_path, target)
        except OSError:
            import shutil
            shutil.copyfile(bin_path, target)

        out, err = run_scan(args.backend, image_full, target, timeout=args.timeout,
                            oracle_model_dir=args.model_dir)
        if err:
            sys.exit(f"oracle run failed: {err}")
        if out is None:
            sys.exit("oracle produced no verdict")

        record = {
            "task": "T1.3",
            "model": args.model if not args.model_file else f"local:{os.path.basename(args.model_file)}",
            "file": BIN_FILE,
            "sha256": sha,
            "image": image_full,
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
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(record, f, indent=2)
        print(json.dumps(record, indent=2))

    return 0 if out.get("exit_code") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
