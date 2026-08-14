#!/usr/bin/env python3
"""Phase 2 gate — bulk DynaHug oracle validation on real benign checkpoints.

Runs the DynaHug oracle container on a set of real HuggingFace checkpoints and
records verdict + decision_score per model. This is a *formal gate*: before any
fuzzing campaign, we must establish that the pretrained OCSVM produces a
meaningful decision-score distribution (not a constant collapse to ~ -1.35).

Metrics recorded per model:
    repo_id, sha256, size_bytes, cluster, verdict, decision_score, exit_code,
    duration

Summary diagnostics written to the report:
    positive/negative rate, decision-score distribution (min/median/max, std),
    score by size bucket, score by cluster, score by architecture family.

By design this does NOT filter the corpus: every sampled checkpoint is scanned
and reported, so oracle false positives on benign models are visible.

Usage:
    PYTHONPATH=.:.pip_deps python3 scripts/validate_oracle.py \
        real_benign_corpus/all --sample 60 \
        --out real_benign_corpus/oracle-validation.json \
        --backend podman
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
import sys
import time

from pipeline.scanners import full_image, run_scan

DEFAULT_IMAGE = "regenbench/dynahug"
ORACLE_EXTS = (".pt", ".pth", ".bin")


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def size_bucket(size: int) -> str:
    mb = size / (1024 * 1024)
    if mb < 1:
        return "<1MB"
    if mb < 10:
        return "1-10MB"
    if mb < 50:
        return "10-50MB"
    if mb < 100:
        return "50-100MB"
    if mb < 500:
        return "100-500MB"
    return ">500MB"


def arch_family(repo_id: str) -> str:
    low = repo_id.lower()
    for fam in ("gpt", "bert", "roberta", "llama", "t5", "distilbert",
                "albert", "electra", "bart", "deberta", "mistral", "qwen"):
        if fam in low:
            return fam
    return "other"


def find_checkpoints(root: str, sample: int) -> list[dict]:
    files = []
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            if n.endswith(ORACLE_EXTS):
                p = os.path.join(dirpath, n)
                cluster = os.path.basename(os.path.dirname(dirpath))
                files.append({"path": p, "cluster": cluster})
    if len(files) > sample:
        files = random.sample(files, sample)
    return files


def run_oracle(backend: str, image: str, path: str, timeout: int) -> dict:
    t0 = time.time()
    out, err = run_scan(backend, image, path, timeout=timeout)
    dur = time.time() - t0
    if err:
        return {"verdict": "error", "decision_score": None, "exit_code": None,
                "error": err, "duration": round(dur, 3)}
    return {
        "verdict": out.get("verdict"),
        "decision_score": out.get("decision_score"),
        "exit_code": out.get("exit_code"),
        "error": None,
        "duration": round(dur, 3),
    }


def summarize(results: list[dict]) -> dict:
    scores = [r["decision_score"] for r in results
              if r.get("decision_score") is not None]
    verdicts = [r["verdict"] for r in results]
    pos = sum(1 for s in scores if s > 0)
    neg = sum(1 for s in scores if s < 0)
    n = len(results)
    benign_count = verdicts.count("benign")
    malicious_count = verdicts.count("malicious")

    summary = {
        "n": n,
        "scored": len(scores),
        "positive_rate": round(pos / n, 4) if n else None,
        "negative_rate": round(neg / n, 4) if n else None,
        "verdict_benign": benign_count,
        "verdict_malicious": malicious_count,
        "verdict_error": verdicts.count("error"),
        "score_distribution": None,
        "by_size_bucket": {},
        "by_cluster": {},
        "by_arch": {},
    }
    if scores:
        summary["score_distribution"] = {
            "min": round(min(scores), 4),
            "q25": round(statistics.quantiles(scores, n=4)[0], 4),
            "median": round(statistics.median(scores), 4),
            "q75": round(statistics.quantiles(scores, n=4)[2], 4),
            "max": round(max(scores), 4),
            "mean": round(statistics.mean(scores), 4),
            "std": round(statistics.stdev(scores), 4) if len(scores) > 1 else 0.0,
        }

    def group(keyfn):
        groups: dict[str, list[float]] = {}
        for r in results:
            s = r.get("decision_score")
            if s is None:
                continue
            k = keyfn(r)
            groups.setdefault(k, []).append(s)
        out = {}
        for k, vs in sorted(groups.items()):
            out[k] = {
                "n": len(vs),
                "mean": round(statistics.mean(vs), 4),
                "median": round(statistics.median(vs), 4),
                "min": round(min(vs), 4),
                "max": round(max(vs), 4),
                "positive": round(sum(1 for v in vs if v > 0) / len(vs), 4),
            }
        return out

    summary["by_size_bucket"] = group(lambda r: size_bucket(r["size_bytes"]))
    summary["by_cluster"] = group(lambda r: r["cluster"])
    summary["by_arch"] = group(lambda r: r["arch"])

    # Collapse detection: if >=95% of scored models fall in a ~0.05-wide band,
    # the OCSVM output is degenerate (e.g. everything pinned to -rho).
    if scores:
        lo = min(scores)
        hi = max(scores)
        summary["spread"] = round(hi - lo, 4)
        in_band = sum(1 for s in scores if (hi - lo) <= 0.05 or (hi - s) <= 0.05)
        summary["collapse_flag"] = (in_band / len(scores)) >= 0.95
    else:
        summary["spread"] = None
        summary["collapse_flag"] = None
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(prog="validate_oracle", description=__doc__)
    ap.add_argument("corpus_dir", help="directory of real benign checkpoints")
    ap.add_argument("--sample", type=int, default=60,
                    help="number of checkpoints to scan (default 60)")
    ap.add_argument("--seed", type=int, default=1337, help="random sampling seed")
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default="real_benign_corpus/oracle-validation.json")
    args = ap.parse_args()

    if not os.path.isdir(args.corpus_dir):
        print(f"[oracle-validation] error: no such directory: {args.corpus_dir}")
        return 1

    random.seed(args.seed)
    checkpoints = find_checkpoints(args.corpus_dir, args.sample)
    if not checkpoints:
        print(f"[oracle-validation] no torch/onnx artifacts found under {args.corpus_dir}")
        return 1

    image_full = full_image(args.image, args.tag)
    print(f"[oracle-validation] scanning {len(checkpoints)} real checkpoints "
          f"through {image_full} (backend={args.backend})")

    results = []
    for i, cp in enumerate(checkpoints, 1):
        repo_dir = os.path.basename(os.path.dirname(cp["path"]))
        size = os.path.getsize(cp["path"])
        sha = sha256_of(cp["path"])
        res = run_oracle(args.backend, image_full, cp["path"], args.timeout)
        rec = {
            "index": i,
            "repo_id": repo_dir,
            "cluster": cp["cluster"],
            "arch": arch_family(repo_dir),
            "path": cp["path"],
            "sha256": sha,
            "size_bytes": size,
            "size_bucket": size_bucket(size),
            **res,
        }
        results.append(rec)
        verdict = rec.get("verdict")
        score = rec.get("decision_score")
        score_str = f"{score:+.3f}" if score is not None else "  n/a "
        print(f"  [{i}/{len(checkpoints)}] {repo_dir:<50} {verdict:<10} {score_str} "
              f"({rec['size_bucket']}, {round(rec['duration'], 1)}s)")
        sys.stdout.flush()

    summary = summarize(results)
    report = {
        "task": "oracle-validation",
        "image": image_full,
        "backend": args.backend,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "results": results,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    print("\n=== Oracle validation summary ===")
    print(json.dumps(summary, indent=2))
    print(f"\n[oracle-validation] full report written to {args.out}")

    if summary.get("collapse_flag"):
        print("\n[GATE] WARNING: decision-score distribution appears COLLAPSED.")
        print("  The OCSVM output is degenerate; STOP and characterize DynaHug")
        print("  before running any fuzzing campaign.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
