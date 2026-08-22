#!/usr/bin/env python3
"""Feature-space diagnostic for the recalibrated DynaHug oracle (Phase 4.3).

The original oracle failure mode: this environment traces ~10-100x the syscall
volumes of upstream's training environment, so every input landed outside a
support region learned elsewhere and decision_function pinned to -rho
(constant "malicious"). Recalibration fixes this only if the fitted boundary
now describes THIS environment's distribution -- not if it merely moved.

This tool quantifies that directly from raw traces:
  1. Train-half vs eval-half per-model total-syscall-volume distributions
     (same environment => they should overlap heavily).
  2. Top-syscall profile similarity between halves.
  3. Score-vs-volume decoupling on the eval half: if positive scores only
     occur at low volumes, the boundary is a volume threshold in disguise;
     positives should span the volume range.
  4. ASCII histograms so the distributions are inspectable without plotting
     dependencies.

Usage:
    python3 scripts/diagnose_oracle_features.py \
        --train-traces real_benign_corpus/oracle-calibrated/text-generation-v2/traces.json \
        --eval-traces real_benign_corpus/oracle-traces/eval-half/traces.json \
        [--fp-eval real_benign_corpus/oracle-calibrated/v2-disjoint/fp-eval-eval.json]
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path


def load(path: str) -> list[dict]:
    return json.loads(Path(path).read_text())


def volumes(traces: list[dict]) -> dict[str, int]:
    return {t["path"]: sum(t["counts"].values()) for t in traces}


def dist_stats(vals: list[float]) -> dict:
    q = statistics.quantiles(vals, n=4) if len(vals) >= 4 else [None] * 4
    return {
        "n": len(vals),
        "min": round(min(vals), 1),
        "p25": round(q[0], 1) if q[0] is not None else None,
        "median": round(statistics.median(vals), 1),
        "mean": round(statistics.mean(vals), 1),
        "p75": round(q[2], 1) if q[2] is not None else None,
        "max": round(max(vals), 1),
    }


def ascii_hist(vals: list[int], lo: float, hi: float, bins: int = 12,
               width: int = 46) -> list[str]:
    lines = []
    edges = [lo + (hi - lo) * i / bins for i in range(bins + 1)]
    counts = [0] * bins
    for v in vals:
        lv = math.log10(max(1, v))
        for b in range(bins):
            if edges[b] <= lv < edges[b + 1] or (b == bins - 1 and lv == edges[b + 1]):
                counts[b] += 1
                break
    peak = max(counts) or 1
    for b in range(bins):
        bar = "#" * max(round(counts[b] / peak * width), 3 if counts[b] else 0)
        lines.append(f"  10^{edges[b]:>5.2f} | {bar:<{width}} {counts[b]}")
    return lines


def spearman(xs: list[float], ys: list[float]) -> float:
    def rank(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r
    rx, ry = rank(xs), rank(ys)
    mx, my = statistics.mean(rx), statistics.mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--train-traces", required=True)
    ap.add_argument("--eval-traces", required=True)
    ap.add_argument("--fp-eval", default=None)
    ap.add_argument("--out", default="reference/oracle-feature-diagnostics.json")
    args = ap.parse_args()

    train = load(args.train_traces)
    ev = load(args.eval_traces)

    tr_vol = volumes(train)
    ev_vol = volumes(ev)
    tr_vals = list(tr_vol.values())
    ev_vals = list(ev_vol.values())
    tr_sorted = sorted(tr_vals)

    # 1. Volume distributions + overlap band.
    p05 = tr_sorted[max(0, int(0.05 * len(tr_sorted)))]
    p95 = tr_sorted[min(len(tr_sorted) - 1, int(0.95 * len(tr_sorted)))]
    in_band = sum(1 for v in ev_vals if p05 <= v <= p95)

    tr_stats = dist_stats([float(v) for v in tr_vals])
    ev_stats = dist_stats([float(v) for v in ev_vals])

    print("=== Syscall volume per model load (train-half vs eval-half) ===")
    print(f"  train: {json.dumps(tr_stats)}")
    print(f"  eval : {json.dumps(ev_stats)}")
    print(f"  train [p05,p95] band: [{p05}, {p95}]  "
          f"-> eval inside band: {in_band}/{len(ev_vals)} "
          f"({100*in_band/len(ev_vals):.0f}%)")

    hist_lo = math.log10(max(1, min(tr_vals + ev_vals)))
    hist_hi = math.log10(max(tr_vals + ev_vals)) + 1e-9
    print("\n  log10(volume) histogram -- TRAIN half")
    print("\n".join(ascii_hist(tr_vals, hist_lo, hist_hi)))
    print("\n  log10(volume) histogram -- EVAL half")
    print("\n".join(ascii_hist(ev_vals, hist_lo, hist_hi)))

    ratio = ev_stats["median"] / max(1.0, tr_stats["median"])
    print(f"\n  eval/train median volume ratio: {ratio:.2f} "
          f"(~1.0 => same domain; >>1 would mean eval drifted out)")

    # 2. Top syscalls by median count.
    def top_syscalls(traces):
        agg = {}
        for t in traces:
            for sc, n in t["counts"].items():
                agg.setdefault(sc, []).append(n)
        med = {sc: statistics.median(ns) for sc, ns in agg.items()}
        present = {sc: sum(1 for n in ns if n > 0) / len(ns)
                   for sc, ns in agg.items()}
        return sorted(med.items(), key=lambda kv: -kv[1])[:8], present

    tr_top, _ = top_syscalls(train)
    ev_top, _ = top_syscalls(ev)
    print("\n=== Top-8 syscalls by median count ===")
    print(f"  {'syscall':<16}{'train med':>10}{'eval med':>10}")
    ev_med = dict(ev_top)
    for sc, m in tr_top:
        print(f"  {sc:<16}{m:>10.0f}{ev_med.get(sc, 0):>10.0f}")

    report = {
        "task": "oracle-feature-diagnostics",
        "train_traces": args.train_traces,
        "eval_traces": args.eval_traces,
        "volume_train": tr_stats,
        "volume_eval": ev_stats,
        "train_p05_p95_band": [p05, p95],
        "eval_in_band_fraction": round(in_band / len(ev_vals), 4),
        "median_ratio_eval_over_train": round(ratio, 3),
        "top_syscalls_train": dict(tr_top),
        "top_syscalls_eval": dict(ev_top),
    }

    # 3. Score-vs-volume on the eval half.
    if args.fp_eval and Path(args.fp_eval).exists():
        fp = json.loads(Path(args.fp_eval).read_text())
        by_artifact = {}
        for r in fp["results"]:
            name = Path(r["artifact"]).name
            stem = name[: -len(".bin")] if name.endswith(".bin") else name
            repo = stem.split("__", 1)[1] if "__" in stem else stem
            by_artifact[repo] = r
        pairs = []
        for t in ev:
            stem = Path(t["path"]).name
            for ext in (".bin", ".pt", ".pth"):
                if stem.endswith(ext):
                    stem = stem[: -len(ext)]
                    break
            repo = stem.split("__", 1)[1] if "__" in stem else stem
            r = by_artifact.get(repo)
            if r and isinstance(r.get("decision_score"), (int, float)):
                pairs.append((sum(t["counts"].values()), r["decision_score"], repo))
        vols = [p[0] for p in pairs]
        scs = [p[1] for p in pairs]
        rho = spearman(vols, scs)
        pos_v = [v for v, s, _ in pairs if s > 0]
        neg_v = [v for v, s, _ in pairs if s <= 0]
        pos_span = (min(pos_v), max(pos_v)) if pos_v else None
        neg_span = (min(neg_v), max(neg_v)) if neg_v else None
        vol_sorted = sorted(vols)
        p25 = vol_sorted[max(0, int(0.25 * len(vol_sorted)) - 1)]
        pos_low_frac = sum(1 for v in pos_v if v <= p25) / max(1, len(pos_v))
        vol_min, vol_max = min(vols), max(vols)
        print("\n=== Eval-half score vs syscall volume ===")
        print(f"  paired models: {len(pairs)}; Spearman(volume, score) = {rho:+.3f}")
        print(f"  NOTE: total volume spans only {vol_min}-{vol_max} "
              f"(~{100*(vol_max-vol_min)/vol_max:.0f}% of median) -- load cost "
              f"is dominated by constant interpreter startup, so total volume "
              f"carries little discriminative signal by construction")
        print(f"  positive-score volume span: {pos_span}")
        print(f"  non-positive-score volume span: {neg_span}")
        print(f"  fraction of positives at or below true p25 ({p25}): "
              f"{pos_low_frac:.2f}")
        fp_repos = [repo for v, s, repo in pairs if s <= 0]
        print(f"  false-positive models: {fp_repos}")
        report["score_vs_volume"] = {
            "n_pairs": len(pairs),
            "spearman_volume_score": round(rho, 4),
            "volume_p25": p25,
            "positive_volume_span": pos_span,
            "nonpositive_volume_span": neg_span,
            "positives_at_or_below_p25": round(pos_low_frac, 4),
            "fp_models": fp_repos,
        }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(f"\n[diagnostics] written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
