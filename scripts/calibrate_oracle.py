#!/usr/bin/env python3
"""Phase 2b — recalibrate the DynaHug OCSVM on this environment's traces.

The pretrained upstream DynaHug OCSVM (arXiv:2604.19438 default
text-generation model) collapses in our container environment: every real
checkpoint traces ~10-100x the syscall counts of the upstream training
environment, so every input lands far outside the learned support region and
the RBF decision_function pins to exactly -rho (~ -1.3489). This makes the
oracle a constant "malicious" classifier (see reference/oracle-sanity.json and
the oracle-validation gate).

This script recalibrates the oracle: it runs the exact same sandbox
deserialization + strace count collection the wrapper uses, builds
presence+frequency features over the pinned syscall vocabulary, and fits a
fresh One-Class SVM using the upstream hyperparameters (RBF, gamma=0.1,
nu=0.01) and preprocessing (DictVectorizer + StandardScaler with_mean=False
applied to frequency columns only). This is a faithful reproduction of the
paper's own training step, calibrated to *our* environment.

Artifacts written to --out-dir:
    oneclass_svm_model.pkl, vectorizer.pkl, scaler.pkl, syscalls.txt
    calibration-report.json   (train/held-out score distribution)

Usage:
    PYTHONPATH=.:.pip_deps python3 scripts/calibrate_oracle.py \
        real_benign_corpus/all/text-generation \
        --out real_benign_corpus/oracle-calibrated/text-generation \
        --sample 120 --backend podman --image regenbench/dynahug
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

SYSCALLS_NAMES = []  # filled from the container image at startup


def parse_strace_count(content: str) -> dict:
    """Mirror of wrapper.parse_strace_count (upstream StraceAnalyzer)."""
    counts = {}
    for line in content.split("\n"):
        if (
            line.startswith("% time")
            or line.startswith("------")
            or line.startswith("100.00")
            or line.endswith("...>")
        ):
            continue
        parts = line.split()
        try:
            if len(parts) >= 5:
                calls = int(parts[3])
                counts[parts[-1]] = calls
        except (ValueError, IndexError):
            continue
    return counts


def extract_syscalls(image_full: str, backend: str) -> list[str]:
    """Pull the pinned syscall vocabulary from the container image."""
    cmd = [backend, "run", "--rm", "--entrypoint", "cat",
           image_full, "/opt/dynahug/classifier/syscalls.txt"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"failed to read syscalls.txt: {out.stderr[-400:]}")
    names = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    return names


def build_features(counts: dict) -> dict:
    """presence+frequency features over the pinned vocabulary."""
    fd = {}
    for sc in SYSCALLS_NAMES:
        v = counts.get(sc, 0)
        fd[f"presence_{sc}"] = 1 if v > 0 else 0
        fd[f"frequency_{sc}"] = v
    return fd


def collect_trace(backend: str, image_full: str, path: str,
                  timeout: int) -> dict | None:
    """Run the oracle container on `path` and return (counts, details) or None."""
    t0 = time.time()
    cmd = [
        backend, "run", "--rm",
        "-v", f"{os.path.abspath(path)}:/artifact:ro,z",
        image_full, "/artifact",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"      [timeout] {os.path.basename(path)}")
        return None
    try:
        out = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return None
    if out.get("verdict") == "error":
        return None
    raw_output = out.get("raw_output") or ""
    marker = "--- strace -c -f summary ---"
    if marker in raw_output:
        summary_text = raw_output.split(marker, 1)[1]
        summary_text = summary_text.split("--- syscalls observed ---", 1)[0]
    else:
        summary_text = raw_output
    counts = parse_strace_count(summary_text)
    if not counts:
        return None
    return {"counts": counts, "duration": time.time() - t0, "raw": out}


def score_matrix(samples: list[dict], model, vectorizer, scaler) -> list[float]:
    import numpy as np

    fnames = vectorizer.get_feature_names_out()
    freq_idx = [i for i, n in enumerate(fnames) if n.startswith("frequency_")]
    scores = []
    for s in samples:
        X = vectorizer.transform([s["features"]])
        Xs = X.copy()
        Xs[:, freq_idx] = scaler.transform(X[:, freq_idx])
        scores.append(float(model.decision_function(Xs)[0]))
    return scores


def main() -> int:
    ap = argparse.ArgumentParser(prog="calibrate_oracle", description=__doc__)
    ap.add_argument("corpus_dir", help="directory of real benign checkpoints")
    ap.add_argument("--out", default="real_benign_corpus/oracle-calibrated",
                    help="output artifact dir")
    ap.add_argument("--sample", type=int, default=120,
                    help="max checkpoints to trace")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--image", default="regenbench/dynahug")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--gamma", type=float, default=0.1)
    ap.add_argument("--nu", type=float, default=0.01)
    ap.add_argument("--holdout", type=float, default=0.2,
                    help="fraction held out for validation")
    args = ap.parse_args()

    global SYSCALLS_NAMES
    image_full = f"{args.image}{args.tag}"
    SYSCALLS_NAMES = extract_syscalls(image_full, args.backend)
    print(f"[calibrate-oracle] syscall vocabulary: {len(SYSCALLS_NAMES)} names")

    files = []
    for dirpath, _dirs, names in os.walk(args.corpus_dir):
        for n in names:
            if n.endswith((".pt", ".pth", ".bin")):
                files.append(os.path.join(dirpath, n))
    if not files:
        print(f"[calibrate-oracle] no artifacts under {args.corpus_dir}")
        return 1
    random.seed(args.seed)
    random.shuffle(files)
    files = files[: args.sample]
    print(f"[calibrate-oracle] tracing {len(files)} checkpoints ...")

    traced = []
    failed = 0
    for i, p in enumerate(files, 1):
        res = collect_trace(args.backend, image_full, p, args.timeout)
        if res is None:
            failed += 1
            continue
        res["features"] = build_features(res["counts"])
        res["path"] = p
        res["repo"] = os.path.basename(os.path.dirname(p))
        traced.append(res)
        print(f"  [{i}/{len(files)}] {res['repo']:<52} ok "
              f"({round(res['duration'], 1)}s)")
        sys.stdout.flush()

    if len(traced) < 20:
        print(f"[calibrate-oracle] only {len(traced)} usable traces "
              f"({failed} failed); need >= 20. Aborting.")
        return 1
    print(f"[calibrate-oracle] collected {len(traced)} traces "
          f"({failed} failed/timed-out)")

    import joblib
    import numpy as np
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM

    random.seed(args.seed)
    random.shuffle(traced)
    n_hold = max(1, int(len(traced) * args.holdout))
    train, hold = traced[: len(traced) - n_hold], traced[len(traced) - n_hold:]

    vectorizer = DictVectorizer(sparse=False)
    scaler = StandardScaler(with_mean=False)
    X_counts = vectorizer.fit_transform([s["features"] for s in train])
    fnames = vectorizer.get_feature_names_out()
    freq_idx = [i for i, n in enumerate(fnames) if n.startswith("frequency_")]
    X_scaled = X_counts.copy()
    if freq_idx:
        X_scaled[:, freq_idx] = scaler.fit_transform(X_counts[:, freq_idx])
    model = OneClassSVM(kernel="rbf", gamma=args.gamma, nu=args.nu)
    model.fit(X_scaled)
    print(f"[calibrate-oracle] fitted OCSVM: n_support={len(model.support_)} "
          f"rho={float(model.offset_[0]):.4f}")

    train_scores = score_matrix(train, model, vectorizer, scaler)
    hold_scores = score_matrix(hold, model, vectorizer, scaler)

    def summ(scores):
        if not scores:
            return None
        return {
            "n": len(scores),
            "min": round(min(scores), 4),
            "q25": round(statistics.quantiles(scores, n=4)[0], 4),
            "median": round(statistics.median(scores), 4),
            "q75": round(statistics.quantiles(scores, n=4)[2], 4),
            "max": round(max(scores), 4),
            "mean": round(statistics.mean(scores), 4),
            "std": round(statistics.stdev(scores), 4) if len(scores) > 1 else 0.0,
            "positive": round(sum(1 for s in scores if s > 0) / len(scores), 4),
            "spread": round(max(scores) - min(scores), 4),
        }

    os.makedirs(args.out, exist_ok=True)
    joblib.dump(model, os.path.join(args.out, "oneclass_svm_model.pkl"))
    joblib.dump(vectorizer, os.path.join(args.out, "vectorizer.pkl"))
    joblib.dump(scaler, os.path.join(args.out, "scaler.pkl"))
    with open(os.path.join(args.out, "syscalls.txt"), "w") as f:
        f.write("\n".join(SYSCALLS_NAMES) + "\n")

    report = {
        "task": "oracle-calibration",
        "image": image_full,
        "backend": args.backend,
        "gamma": args.gamma,
        "nu": args.nu,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus": args.corpus_dir,
        "traced_total": len(traced),
        "train_n": len(train),
        "holdout_n": len(hold),
        "train": summ(train_scores),
        "holdout": summ(hold_scores),
        "trace_duration_mean": round(
            statistics.mean([s["duration"] for s in traced]), 2),
        "artifacts": sorted(os.listdir(args.out)),
        "models": [s["repo"] for s in hold],
    }
    with open(os.path.join(args.out, "calibration-report.json"), "w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    print("\n=== Calibration summary ===")
    print(f"  train   : {json.dumps(report['train'])}")
    print(f"  holdout : {json.dumps(report['holdout'])}")
    print(f"\n[calibrate-oracle] artifacts written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
