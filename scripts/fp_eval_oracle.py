#!/usr/bin/env python3
"""DynaHug FP evaluation on a disjoint model split (Plan Phase 4.1/4.4).

Runs the calibrated oracle over ONLY the 'eval' half of
real_benign_corpus/oracle-split.json -- models guaranteed disjoint from the
calibration trace pool -- and reports the false-positive rate plus full
decision-score distribution.

Usage:
    python3 scripts/fp_eval_oracle.py \
        --model-dir real_benign_corpus/oracle-calibrated/current \
        [--split-file real_benign_corpus/oracle-split.json] [--role eval]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from pipeline.scanners import run_scan  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--corpus", default=str(REPO / "real_benign_corpus/all"))
    ap.add_argument("--split-file", default=str(REPO / "real_benign_corpus/oracle-split.json"))
    ap.add_argument("--role", choices=["train", "eval"], default="eval")
    ap.add_argument("--image", default="regenbench/dynahug")
    ap.add_argument("--backend", default="podman")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    corpus_dir = Path(args.corpus)
    by_repo = {}
    for p in sorted(corpus_dir.glob("*.bin")):
        stem = p.name[: -len(".bin")]
        if "__" in stem:
            _, repo = stem.split("__", 1)
        else:
            repo = stem
        by_repo[repo] = p

    wanted = set(json.loads(Path(args.split_file).read_text())[args.role])
    missing = wanted - set(by_repo)
    if missing:
        print(f"[fp-eval] WARNING {len(missing)} split repos not in corpus: "
              f"{sorted(missing)[:5]} ...")
    artifacts = [str(by_repo[r]) for r in sorted(wanted) if r in by_repo]
    print(f"[fp-eval] role={args.role}: scanning {len(artifacts)} models with "
          f"oracle_model_dir={args.model_dir}")

    results = []
    t0 = time.time()
    for i, art in enumerate(artifacts, 1):
        out, err = run_scan(args.backend, f"{args.image}:latest", art,
                            timeout=args.timeout,
                            oracle_model_dir=args.model_dir)
        verdict = "error" if err or out is None else out.get("verdict")
        score = None if err or out is None else out.get("decision_score")
        repo = Path(art).name
        results.append({"artifact": repo, "verdict": verdict,
                        "decision_score": score,
                        "exit_code": None if err or out is None else out.get("exit_code")})
        s = f"{score:+.4f}" if isinstance(score, (int, float)) else "  n/a"
        print(f"  [{i}/{len(artifacts)}] {repo[:58]:<58} {verdict:<10} {s}")
        sys.stdout.flush()

    scored = [r["decision_score"] for r in results
              if isinstance(r["decision_score"], (int, float))]
    fps = sum(1 for r in results if r["verdict"] == "malicious")
    errors = sum(1 for r in results if r["verdict"] == "error")
    summary = {
        "task": "oracle-fp-eval-disjoint",
        "model_dir": args.model_dir,
        "role": args.role,
        "n": len(results),
        "false_positives": fps,
        "errors": errors,
        "fp_rate": round(fps / max(1, len(results)), 4),
        "score_stats": {
            "n": len(scored),
            "min": round(min(scored), 4) if scored else None,
            "median": round(statistics.median(scored), 4) if scored else None,
            "max": round(max(scored), 4) if scored else None,
            "mean": round(statistics.mean(scored), 4) if scored else None,
            "std": round(statistics.stdev(scored), 4) if len(scored) > 1 else None,
            "spread": round(max(scored) - min(scored), 4) if scored else None,
            "positive_rate": round(sum(1 for s in scored if s > 0) / len(scored), 4) if scored else None,
        },
        "duration_s": round(time.time() - t0, 1),
        "results": results,
    }
    print("\n=== Disjoint FP evaluation ===")
    print(f"  FP rate : {fps}/{len(results)} = {summary['fp_rate']*100:.1f}%  "
          f"(errors: {errors})")
    print(f"  scores  : {json.dumps(summary['score_stats'])}")

    out_path = Path(args.out) if args.out else \
        Path(args.model_dir) / f"fp-eval-{args.role}.json"
    out_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"[fp-eval] written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
