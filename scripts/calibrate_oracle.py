#!/usr/bin/env python3
"""Phase 2b — recalibrate the oracles (DynaHug for PT, ggufref for GGUF) on this environment's traces.

The pretrained upstream DynaHug OCSVM (arXiv:2604.19438 default
text-generation model) collapses in our container environment: every real
checkpoint traces ~10-100x the syscall counts of the upstream training
environment, so every input lands far outside the learned support region and
the RBF decision_function pins to exactly -rho (~ -1.3489). This makes the
oracle a constant "malicious" classifier (see reference/oracle-sanity.json and
the oracle-validation gate).

For GGUF, the ggufref oracle parses GGUF files with the ggml-org reference
reader and renders chat templates through the unsandboxed Jinja2 path
(CVE-2024-34359). The strace-based execution oracle for GGUF observes
execve syscalls during Jinja2 render.

This script recalibrates the oracles: it runs the exact same sandbox
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
        real_benign_corpus/all_pt \
        --out real_benign_corpus/oracle-calibrated/pt \
        --format pt --sample 120 --backend docker --image regenbench/dynahug
    PYTHONPATH=.:.pip_deps python3 scripts/calibrate_oracle.py \
        real_benign_corpus/all_gguf \
        --out real_benign_corpus/oracle-calibrated/gguf \
        --format gguf --sample 120 --backend docker --image regenbench/gguf
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
                  timeout: int, format: str = "pt") -> dict | None:
    """Run the oracle container on `path` and return (counts, details) or None."""
    t0 = time.time()
    cmd = [
        backend, "run", "--rm",
        "-v", f"{os.path.abspath(path)}:/artifact:ro,z",
    ]
    if format == "gguf":
        cmd += ["--network", "none", "--tmpfs", "/tmp"]
    cmd += [image_full, "/artifact"]
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


def main() -> int:
    ap = argparse.ArgumentParser(prog="calibrate_oracle", description=__doc__)
    ap.add_argument("corpus_dir", help="directory of real benign checkpoints")
    ap.add_argument("--out", default="real_benign_corpus/oracle-calibrated",
                    help="output artifact dir")
    ap.add_argument("--format", choices=["pt", "gguf"], default="pt",
                    help="format to calibrate: pt (dynahug) or gguf (ggufref)")
    ap.add_argument("--sample", type=int, default=120,
                    help="max checkpoints to trace")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--image", default=None,
                    help="container image (default: regenbench/dynahug for pt, regenbench/gguf for gguf)")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--gamma", type=float, default=0.1)
    ap.add_argument("--nu", type=float, default=0.01)
    ap.add_argument("--holdout", type=float, default=0.2,
                    help="fraction held out for validation")
    ap.add_argument("--split-file", default=None,
                    help="oracle-split.json from check_oracle_disjointness.py; "
                         "restrict tracing to its 'train' or 'eval' repo list")
    ap.add_argument("--split-role", choices=["train", "eval"], default="train",
                    help="which side of --split-file to trace")
    ap.add_argument("--traces-only", action="store_true",
                    help="collect and dump traces.json, then exit without "
                         "fitting anything (use for diagnostics on eval-side "
                         "data; guarantees no model is ever fit on it)")
    args = ap.parse_args()

    # Default images per format
    if args.image is None:
        args.image = "regenbench/dynahug" if args.format == "pt" else "regenbench/gguf"

    global SYSCALLS_NAMES
    image_full = f"{args.image}{args.tag}"
    SYSCALLS_NAMES = extract_syscalls(image_full, args.backend)
    print(f"[calibrate-oracle] format={args.format}, syscall vocabulary: {len(SYSCALLS_NAMES)} names")

    # P2.2 Option A: differential trace — subtract blank load baseline
    blank_counts = None
    blank_path = "ci/corpus/torch/benign/benign.pt" if args.format == "pt" else None
    if blank_path and os.path.exists(blank_path):
        print(f"[calibrate-oracle] collecting blank baseline from {blank_path} ...")
        blank_res = collect_trace(args.backend, image_full, blank_path, args.timeout, args.format)
        if blank_res and blank_res.get("counts"):
            blank_counts = blank_res["counts"]
            print(f"[calibrate-oracle] blank baseline: {len(blank_counts)} syscalls, e.g. {list(blank_counts.items())[:3]}")
        else:
            print("[calibrate-oracle] blank baseline failed, using raw counts")

    # File extensions per format
    if args.format == "pt":
        exts = (".pt", ".pth", ".bin")
    else:
        exts = (".gguf",)

    files = []
    for dirpath, _dirs, names in os.walk(args.corpus_dir):
        for n in names:
            if n.endswith(exts):
                files.append(os.path.join(dirpath, n))
    if not files:
        print(f"[calibrate-oracle] no artifacts under {args.corpus_dir}")
        return 1

    split_repos = None
    if args.split_file:
        with open(args.split_file) as f:
            split = json.load(f)
        split_repos = set(split[args.split_role])
        # Flat layout: <cluster>__<repo>.<ext>
        def repo_of(path: str) -> str:
            stem = os.path.basename(path)
            for ext in exts:
                if stem.endswith(ext):
                    stem = stem[: -len(ext)]
                    break
            return stem.split("__", 1)[1] if "__" in stem else stem
        before = len(files)
        files = [p for p in files if repo_of(p) in split_repos]
        print(f"[calibrate-oracle] split '{args.split_role}': {before} -> "
              f"{len(files)} files ({len(split_repos)} repos listed)")
        if not files:
            print("[calibrate-oracle] no corpus files match the split role")
            return 1

    random.seed(args.seed)
    random.shuffle(files)
    files = files[: args.sample]
    print(f"[calibrate-oracle] tracing {len(files)} checkpoints ...")

    traced = []
    failed = 0
    for i, p in enumerate(files, 1):
        res = collect_trace(args.backend, image_full, p, args.timeout, args.format)
        if res is None:
            failed += 1
            continue
        # Differential: subtract blank baseline to remove Python/torch startup noise
        if blank_counts is not None:
            diff_counts = {}
            for sc, cnt in res["counts"].items():
                base = blank_counts.get(sc, 0)
                diff = cnt - base
                diff_counts[sc] = max(0, diff)
            # Also include syscalls only in blank (should be 0 diff)
            res["counts_raw"] = res["counts"]
            res["counts"] = diff_counts
            res["differential"] = True
        res["features"] = build_features(res["counts"])
        res["path"] = p
        stem = os.path.basename(p)
        for ext in exts:
            if stem.endswith(ext):
                stem = stem[: -len(ext)]
                break
        res["repo"] = stem.split("__", 1)[1] if "__" in stem else \
            os.path.basename(os.path.dirname(p))
        traced.append(res)
        print(f"  [{i}/{len(files)}] {res['repo']:<52} ok "
              f"({round(res['duration'], 1)}s)")
        sys.stdout.flush()

    if len(traced) < 10:
        print(f"[calibrate-oracle] only {len(traced)} usable traces "
              f"({failed} failed); need >= 20. Aborting.")
        return 1
    print(f"[calibrate-oracle] collected {len(traced)} traces "
          f"({failed} failed/timed-out)")

    # Persist raw traces so hyperparameter sweeps / feature diagnostics can be
    # re-run offline without re-tracing containers (Plan Phase 4.2/4.3).
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "traces.json"), "w") as f:
        json.dump([{"path": s["path"], "repo": s["repo"],
                    "counts": s["counts"], "features": s["features"]}
                   for s in traced], f)
        f.write("\n")

    if args.traces_only:
        print(f"[calibrate-oracle] --traces-only: {len(traced)} traces written; "
              f"no model fitted (out dir contains no OCSVM artifacts)")
        return 0

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
        "format": args.format,
        "image": image_full,
        "backend": args.backend,
        "gamma": args.gamma,
        "nu": args.nu,
        "split_file": args.split_file,
        "split_role": args.split_role if args.split_file else None,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus": args.corpus_dir,
        "traced_total": len(traced),
        "train_n": len(train),
        "holdout_n": len(hold),
        "train_repos": sorted(s["repo"] for s in train),
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
