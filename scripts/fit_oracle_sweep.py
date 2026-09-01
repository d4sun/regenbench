#!/usr/bin/env python3
"""Fit / sweep the DynaHug OCSVM *inside* the oracle image (Plan Phase 4.2).

Why inside the container: the dynahug image pins scikit-learn==1.7.1 /
joblib==1.5.2 (matching upstream's serialized artifacts), while the host may
run a different Python/sklearn. Fitting where the model is consumed removes
any cross-version serialization risk.

Input: traces.json written by scripts/calibrate_oracle.py (raw per-model
syscall counts + presence/frequency features). No container re-tracing is
needed for sweeps.

Modes:
  sweep   default: grid over --gamma x --nu, deterministic seeded train/holdout
          split, per-combo score statistics + recommendation table.
  export  --export with --export-dir: refit ONE combo and joblib.dump the
          model/vectorizer/scaler into a drop-in DYNAHUG_MODEL_DIR.

Usage:
    python3 scripts/fit_oracle_sweep.py \
        --traces real_benign_corpus/oracle-calibrated/text-generation-v2/traces.json \
        --gamma-grid 0.01 0.1 1.0 --nu-grid 0.005 0.01 0.05
    python3 scripts/fit_oracle_sweep.py --traces ... \
        --export --gamma 0.1 --nu 0.01 \
        --export-dir real_benign_corpus/oracle-calibrated/current
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
IMAGE = "regenbench/dynahug:latest"

# Executed inside the container (python3.13 + sklearn 1.7.1 + joblib 1.5.2).
# stdin: {"train": [feature_dict...], "eval": [...], "gamma": g, "nu": n,
#         "export": null | "/out"}
# stdout: exactly one JSON line with scores + optional export status.
INNER = r"""
import json, os, shutil, sys
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

payload = json.load(sys.stdin)
train_feats, eval_feats = payload["train"], payload["eval"]
vec = DictVectorizer(sparse=False)
Xtr = vec.fit_transform(train_feats)
fnames = vec.get_feature_names_out()
fidx = [i for i, nm in enumerate(fnames) if nm.startswith("frequency_")]
scaler = StandardScaler(with_mean=False)
Xtr_s = Xtr.copy()
if fidx:
    Xtr_s[:, fidx] = scaler.fit_transform(Xtr[:, fidx])
m = OneClassSVM(kernel="rbf", gamma=payload["gamma"], nu=payload["nu"])
m.fit(Xtr_s)

def score(feats):
    out = []
    for fd in feats:
        X = vec.transform([fd])
        Xs = X.copy()
        if fidx:
            Xs[:, fidx] = scaler.transform(X[:, fidx])
        out.append(float(m.decision_function(Xs)[0]))
    return out

export_status = None
if payload.get("export"):
    try:
        import joblib
        os.makedirs(payload["export"], exist_ok=True)
        joblib.dump(m, os.path.join(payload["export"], "oneclass_svm_model.pkl"))
        joblib.dump(vec, os.path.join(payload["export"], "vectorizer.pkl"))
        joblib.dump(scaler, os.path.join(payload["export"], "scaler.pkl"))
        shutil.copyfile("/opt/dynahug/classifier/syscalls.txt",
                        os.path.join(payload["export"], "syscalls.txt"))
        export_status = "ok"
    except Exception as e:  # noqa: BLE001
        export_status = f"failed: {e}"

print(json.dumps({
    "train_scores": score(train_feats),
    "eval_scores": score(eval_feats),
    "n_support": int(len(m.support_)),
    "rho": float(m.offset_[0]),
    "n_features": len(fnames),
    "export_status": export_status,
}))
"""


def run_in_container(payload: dict, backend: str = "podman") -> dict:
    proc = subprocess.run(
        [backend, "run", "--rm", "-i", "--entrypoint", "python3.13",
         IMAGE, "-c", INNER],
        input=json.dumps(payload), capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f"container fit failed: {proc.stderr[-800:]}")
    lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
    return json.loads(lines[-1])


def stats(scores: list[float]) -> dict:
    if not scores:
        return {"n": 0}
    q = statistics.quantiles(scores, n=4) if len(scores) >= 4 else [None] * 4
    return {
        "n": len(scores),
        "min": round(min(scores), 4),
        "median": round(statistics.median(scores), 4),
        "max": round(max(scores), 4),
        "mean": round(statistics.mean(scores), 4),
        "std": round(statistics.stdev(scores), 4) if len(scores) > 1 else 0.0,
        "spread": round(max(scores) - min(scores), 4),
        "positive_rate": round(sum(1 for s in scores if s > 0) / len(scores), 4),
    }


def main() -> int:
    global IMAGE
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traces", required=True)
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman",
                    help="container runtime for the in-image fit (docker on "
                         "hosts without podman)")
    ap.add_argument("--holdout", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--gamma-grid", type=float, nargs="+", default=[0.01, 0.05, 0.1, 0.5, 1.0])
    ap.add_argument("--nu-grid", type=float, nargs="+", default=[0.005, 0.01, 0.02, 0.05])
    ap.add_argument("--export", action="store_true")
    ap.add_argument("--gamma", type=float, default=None)
    ap.add_argument("--nu", type=float, default=None)
    ap.add_argument("--export-dir", default="real_benign_corpus/oracle-calibrated/current")
    ap.add_argument("--out", default=None, help="write sweep results JSON here")
    args = ap.parse_args()

    IMAGE = args.image
    backend = args.backend

    traces = json.loads(Path(args.traces).read_text())
    # Deterministic split mirroring calibrate_oracle.py (seeded shuffle).
    import random
    rng = random.Random(args.seed)
    idx = list(range(len(traces)))
    rng.shuffle(idx)
    n_hold = max(1, int(len(traces) * args.holdout))
    hold_idx = set(idx[:n_hold])

    train_tr = [t for i, t in enumerate(traces) if i not in hold_idx]
    hold_tr = [t for i, t in enumerate(traces) if i in hold_idx]
    train_feats = [t["features"] for t in train_tr]
    hold_feats = [t["features"] for t in hold_tr]
    print(f"[sweep] traces: {len(traces)} (train {len(train_feats)} / "
          f"holdout {len(hold_feats)}); features={len(train_feats[0])} dims")

    combos = [(args.gamma, args.nu)] if args.export else [
        (g, n) for g in args.gamma_grid for n in args.nu_grid]

    results = []
    for gamma, nu in combos:
        payload = {"train": train_feats, "eval": hold_feats,
                   "gamma": gamma, "nu": nu, "export": None}
        r = run_in_container(payload, backend)
        row = {
            "gamma": gamma, "nu": nu,
            "n_support": r["n_support"], "rho": round(r["rho"], 4),
            "train": stats(r["train_scores"]),
            "holdout": stats(r["eval_scores"]),
        }
        results.append(row)
        print(f"  gamma={gamma:<6} nu={nu:<6} "
              f"train_pos={row['train']['positive_rate']:<7} "
              f"hold_pos={row['holdout']['positive_rate']:<7} "
              f"hold_spread={row['holdout']['spread']}")

    # Rank: holdout positive-rate first, then holdout spread (a discriminative,
    # non-collapsed boundary on unseen benign data), then train positive-rate.
    def key(r):
        return (r["holdout"]["positive_rate"], r["holdout"]["spread"],
                r["train"]["positive_rate"])

    best = max(results, key=key)
    print(f"\n[sweep] recommended: gamma={best['gamma']} nu={best['nu']} "
          f"(holdout positive {best['holdout']['positive_rate']}, "
          f"spread {best['holdout']['spread']})")

    summary = {
        "task": "oracle-hyperparameter-sweep",
        "traces": args.traces,
        "seed": args.seed,
        "split": {"train_n": len(train_feats), "holdout_n": len(hold_feats)},
        "results": results,
        "recommended": best,
    }
    out_path = Path(args.out) if args.out else \
        Path(args.traces).parent / "hyperparameter-sweep.json"
    out_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"[sweep] results written to {out_path}")

    if args.export:
        assert best is not None or (args.gamma and args.nu)
        gamma = args.gamma if args.gamma is not None else best["gamma"]
        nu = args.nu if args.nu is not None else best["nu"]
        export_abs = (REPO / args.export_dir).resolve()
        export_abs.mkdir(parents=True, exist_ok=True)
        payload = {"train": train_feats, "eval": [], "gamma": gamma, "nu": nu,
                   "export": "/out"}
        cmd = [backend, "run", "--rm", "-i",
               "-v", f"{export_abs}:/out:z",
               "--entrypoint", "python3.13", IMAGE, "-c", INNER]
        proc = subprocess.run(cmd, input=json.dumps(payload),
                              capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print(f"[export] FAILED: {proc.stderr[-500:]}")
            return 1
        r = json.loads(proc.stdout.strip().splitlines()[-1])
        print(f"[export] status={r['export_status']} -> {args.export_dir} "
              f"(gamma={gamma}, nu={nu})")
        meta = {"gamma": gamma, "nu": nu, "source_traces": args.traces,
                "train_repos": sorted(t["path"] for t in train_tr)}
        (export_abs / "calibration-report.json").write_text(
            json.dumps(meta, indent=2) + "\n")
        return 0 if r["export_status"] == "ok" else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
