#!/usr/bin/env python3
"""Generate per-step PNG charts from the ReGenBench artifacts.

Reads only host-side data (SQLite DBs + JSON artifacts; no docker, no
container oracle) and reuses the same query helpers as the evaluation report,
so every number in a chart matches the report exactly.

Charts are written into ``charts/<NN>_<step>/*.png`` where the folders mirror
the steps of ``docs/full-implementation-guide.md``. Any step whose source data
is missing is skipped, so the script works after a partial run.

Requires ``matplotlib`` (host-only analysis dependency):
    python3 -m pip install --user matplotlib
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def _require_pyplot():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.rcParams.update({
            "figure.dpi": 110,
            "savefig.dpi": 150,
            "font.size": 10,
            "axes.grid": True,
            "grid.alpha": 0.3,
        })
        return plt
    except ImportError:  # pragma: no cover - env guard
        print("[charts] matplotlib is required. Install it with:")
        print("  python3 -m pip install --user matplotlib")
        raise SystemExit(1)


# Reuse the evaluation-report query helpers so chart numbers match the
# generated reports (they are pure sqlite readers; no sklearn/torch needed).
try:  # pragma: no cover - same-env import
    from scripts.run_evaluation_suite import (  # noqa: F401
        query_coverage_history, query_run_evasion, query_scanner_stats,
        bootstrap_ci,
    )
    from scripts.generate_evaluation_report import (  # noqa: F401
        cross_format_summary, gguf_surface_summary,
    )
    HAS_HELPERS = True
except Exception:  # pragma: no cover - defensive fallback
    HAS_HELPERS = False


def _save(plt, fig, out_dir: str, name: str, fmt: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.{fmt}")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path


def _q(db: str, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    if not os.path.exists(db):
        return []
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Step 01 — Crawl
# ---------------------------------------------------------------------------
def chart_crawl(plt, out_dir: str, manifest_path: str, fmt: str) -> str | None:
    if not os.path.exists(manifest_path):
        return None
    manifest = json.load(open(manifest_path))
    clusters = (manifest.get("summary") or {}).get("clusters") or {}
    if not clusters:
        return None
    fig, ax = plt.subplots(figsize=(7, 4))
    names = sorted(clusters)
    counts = [clusters[n] for n in names]
    ax.bar(names, counts, color="#4c72b0")
    ax.set_ylabel("models")
    ax.set_title(f"Corpus composition ({sum(counts)} real HF checkpoints)")
    ax.tick_params(axis="x", rotation=20)
    return _save(plt, fig, out_dir, "corpus_composition", fmt)


# ---------------------------------------------------------------------------
# Step 02 — Oracle validation / views
# ---------------------------------------------------------------------------
def chart_oracle(plt, out_dir: str, validation_path: str, fmt: str) -> str | None:
    if not os.path.exists(validation_path):
        return None
    data = json.load(open(validation_path))
    results = data.get("results") or []
    by_cluster: dict[str, list[float]] = {}
    for r in results:
        score = r.get("decision_score")
        if score is None:
            continue
        by_cluster.setdefault(r.get("cluster", "?"), []).append(score)
    if not by_cluster:
        return None
    fig, ax = plt.subplots(figsize=(8, 4.5))
    clusters = sorted(by_cluster)
    ax.boxplot([by_cluster[c] for c in clusters], tick_labels=clusters)
    ax.set_ylabel("dynahug decision_score")
    ax.set_title("Oracle validation: decision-score distribution by cluster")
    ax.tick_params(axis="x", rotation=20)
    return _save(plt, fig, out_dir, "oracle_score_distribution", fmt)


# ---------------------------------------------------------------------------
# Step 03 — Recalibrate oracle
# ---------------------------------------------------------------------------
def chart_calibrate(plt, out_dir: str, fp_eval_path: str, fmt: str) -> str | None:
    if not os.path.exists(fp_eval_path):
        return None
    d = json.load(open(fp_eval_path))
    n = d.get("n", 0)
    fp = d.get("false_positives", 0)
    if not n:
        return None
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(["benign flagged", "benign clean"],
           [fp, n - fp], color=["#c44e52", "#55a868"])
    ax.set_ylabel("eval-half models")
    ax.set_title(f"Calibrated DynaHug FP on eval half (n={n}, rate={d.get('fp_rate', 0):.0%})")
    return _save(plt, fig, out_dir, "calibration_fp", fmt)


# ---------------------------------------------------------------------------
# Step 04 — Baseline + campaigns
# ---------------------------------------------------------------------------
def _per_round_yield(db: str) -> list[dict]:
    rows = _q(
        db,
        """SELECT c.run_id, c.round_num,
                  SUM(f.is_valid) AS valid,
                  SUM(CASE WHEN f.is_valid = 1 AND c.panel_verdict = 'all_benign'
                           THEN 1 ELSE 0 END) AS bypasses
           FROM candidates c
           JOIN campaign_fitness f ON f.candidate_id = c.candidate_id
           WHERE COALESCE(c.format, 'pt') = 'pt'
           GROUP BY c.run_id, c.round_num
           ORDER BY c.run_id, c.round_num""",
    )
    return [dict(r) for r in rows]


def chart_campaigns(plt, out_dir: str, db: str, fmt: str) -> list[str]:
    written: list[str] = []
    coverage = query_coverage_history(db) if HAS_HELPERS else []
    if coverage:
        runs = sorted({r["run_id"] for r in coverage})
        for metric, ylab, fname in (
            ("opcode_coverage", "opcode coverage (reachable)", "coverage_opcode"),
            ("callable_coverage", "callable coverage (reachable)", "coverage_callable"),
        ):
            fig, ax = plt.subplots(figsize=(8, 4.5))
            for run in runs:
                pts = [(r["round_num"], r[metric]) for r in coverage
                       if r["run_id"] == run and r.get(metric) is not None]
                if pts:
                    pts.sort()
                    ax.plot([p[0] for p in pts], [p[1] for p in pts],
                            marker="o", label=run)
            ax.set_xlabel("round")
            ax.set_ylabel(ylab)
            ax.set_ylim(0, 1.05)
            ax.set_title(f"Coverage growth ({metric.replace('_', ' ')})")
            ax.legend()
            written.append(_save(plt, fig, out_dir, fname, fmt))

    entropy = _q(db, "SELECT run_id, round_num, entropy FROM campaign_coverage ORDER BY run_id, round_num")
    if entropy:
        runs = sorted({r["run_id"] for r in entropy})
        fig, ax = plt.subplots(figsize=(8, 4.5))
        for run in runs:
            pts = [(r["round_num"], r["entropy"]) for r in entropy
                   if r["run_id"] == run and r["entropy"] is not None]
            if pts:
                pts.sort()
                ax.plot([p[0] for p in pts], [p[1] for p in pts],
                        marker="o", label=run)
        ax.set_xlabel("round")
        ax.set_ylabel("family entropy (nats)")
        ax.set_title("Sampling family entropy by round")
        ax.legend()
        written.append(_save(plt, fig, out_dir, "family_entropy", fmt))

    yield_rows = _per_round_yield(db)
    if yield_rows:
        runs = sorted({r["run_id"] for r in yield_rows})
        fig, ax = plt.subplots(figsize=(9, 4.5))
        for run in runs:
            pts = [(r["round_num"], r["valid"]) for r in yield_rows
                   if r["run_id"] == run]
            pts.sort()
            ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o",
                    label=f"{run} valid")
        for run in runs:
            pts = [(r["round_num"], r["bypasses"]) for r in yield_rows
                   if r["run_id"] == run]
            pts.sort()
            ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="s",
                    ls="--", label=f"{run} bypasses")
        ax.set_xlabel("round")
        ax.set_ylabel("candidates")
        ax.set_title("Valid + confirmed bypasses per round")
        ax.legend(fontsize=8)
        written.append(_save(plt, fig, out_dir, "bypass_yield_per_round", fmt))

    family = _q(
        db,
        """SELECT c.mutation_template, COUNT(*) AS n
           FROM candidates c
           JOIN campaign_fitness f ON f.candidate_id = c.candidate_id
           WHERE COALESCE(c.format, 'pt') = 'pt' AND f.is_valid = 1
             AND c.panel_verdict = 'all_benign'
           GROUP BY c.mutation_template
           ORDER BY n DESC""",
    )
    if family:
        fig, ax = plt.subplots(figsize=(8, 4.5))
        names = [r["mutation_template"] for r in family]
        counts = [r["n"] for r in family]
        ax.bar(names, counts, color="#4c72b0")
        ax.set_ylabel("confirmed bypasses")
        ax.set_title("Confirmed bypasses by attack family")
        ax.tick_params(axis="x", rotation=25)
        written.append(_save(plt, fig, out_dir, "per_family_bypasses", fmt))

    if HAS_HELPERS:
        runs = [r for r in query_run_evasion(db)
                if r["campaign_type"] in ("guided", "unguided")]
        if runs:
            fig, ax = plt.subplots(figsize=(8, 4.5))
            names = [r["run_id"] for r in runs]
            valid = [r["valid_candidates"] for r in runs]
            confirmed = [r["confirmed"] for r in runs]
            import numpy as np
            x = np.arange(len(names))
            w = 0.35
            ax.bar(x - w / 2, valid, w, label="valid", color="#4c72b0")
            ax.bar(x + w / 2, confirmed, w, label="confirmed bypasses", color="#c44e52")
            for i, r in enumerate(runs):
                yield_pct = (r["confirmed"] / max(1, r["valid_candidates"])) * 100
                ax.text(i, r["confirmed"] + 2, f"{yield_pct:.0f}%",
                        ha="center", fontsize=9)
            ax.set_xticks(x, names)
            ax.set_ylabel("candidates")
            ax.set_title("Guided vs unguided yield")
            ax.legend()
            written.append(_save(plt, fig, out_dir, "guided_vs_unguided_yield", fmt))
    return written


# ---------------------------------------------------------------------------
# Step 05 — Evaluation & reports
# ---------------------------------------------------------------------------
def chart_evaluation(plt, out_dir: str, db: str, fmt: str) -> list[str]:
    written: list[str] = []
    if HAS_HELPERS and os.path.exists(db):
        stats = query_scanner_stats(db)
        evadable = [(s, stats[s]["evaded"], stats[s]["scanned"])
                    for s in ("picklescan", "modelscan")
                    if stats.get(s, {}).get("scanned")]
        if evadable:
            fig, ax = plt.subplots(figsize=(7, 4.5))
            names = [s for s, _, _ in evadable]
            rates: list[float] = []
            low_errs: list[float] = []
            high_errs: list[float] = []
            for _, ev, sc in evadable:
                data = [1] * ev + [0] * (sc - ev)
                lo, hi = bootstrap_ci(data, seed=1337)
                rate = ev / max(1, sc) * 100
                rates.append(rate)
                low_errs.append(rate - lo * 100)
                high_errs.append(hi * 100 - rate)
            ax.bar(names, rates, yerr=[low_errs, high_errs], capsize=6,
                   color="#4c72b0")
            ax.set_ylabel("evasion rate (%)")
            ax.set_title("Per-scanner evasion (format-native pickle panel)")
            written.append(_save(plt, fig, out_dir, "per_scanner_evasion", fmt))

        xf = cross_format_summary(db)
        if xf:
            fmts = sorted(xf)
            fig, ax = plt.subplots(figsize=(7, 4.5))
            import numpy as np
            x = np.arange(len(fmts))
            w = 0.25
            ax.bar(x - w, [xf[f]["generated"] for f in fmts], w, label="candidates", color="#4c72b0")
            ax.bar(x, [xf[f]["valid"] for f in fmts], w, label="valid", color="#55a868")
            ax.bar(x + w, [xf[f]["confirmed"] for f in fmts], w, label="confirmed bypasses", color="#c44e52")
            ax.set_xticks(x, fmts)
            ax.set_ylabel("candidates")
            ax.set_title("Cross-format summary")
            ax.legend()
            written.append(_save(plt, fig, out_dir, "cross_format_summary", fmt))
    return written


# ---------------------------------------------------------------------------
# Step 06 — Defense
# ---------------------------------------------------------------------------
def chart_defense(plt, out_dir: str, fmt: str) -> str | None:
    malicious_dir = os.path.join(REPO, "ci/corpus/pkl/malicious")
    benign_dir = os.path.join(REPO, "ci/corpus/pkl/benign")
    if not (os.path.isdir(malicious_dir) and os.path.isdir(benign_dir)):
        return None
    try:
        from scripts.run_evaluation_suite import collect_repair_metrics
    except Exception:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        metrics, _rows = collect_repair_metrics(malicious_dir, benign_dir, tmp)
    keys = [k for k in ("repair_success_rate", "repair_false_negative_rate",
                        "repair_correctness_rate", "repair_overhead")
            if metrics.get(k) is not None]
    if not keys:
        return None
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(keys, [metrics[k] for k in keys], color="#4c72b0")
    ax.set_ylabel("rate / ratio")
    ax.set_ylim(0, 1.1)
    ax.set_title("Defense repair metrics (CI pickle corpus)")
    ax.tick_params(axis="x", rotation=20)
    return _save(plt, fig, out_dir, "repair_metrics", fmt)


# ---------------------------------------------------------------------------
# Step 07 — GGUF attack surface
# ---------------------------------------------------------------------------
def chart_gguf(plt, out_dir: str, db: str, fmt: str) -> str | None:
    if not HAS_HELPERS or not os.path.exists(db):
        return None
    rows = gguf_surface_summary(db)
    if not rows:
        return None
    import numpy as np
    families = [r["family"] for r in rows]
    scanners = ["ggufref", "modelscan"]
    cell = np.full((len(families), len(scanners)), np.nan)
    for i, r in enumerate(rows):
        for j, s in enumerate(scanners):
            cell[i, j] = 1.0 if r[s] == "malicious" else 0.0
    fig, ax = plt.subplots(figsize=(9, max(3, 0.4 * len(families) + 2)))
    im = ax.imshow(cell, cmap="RdYlGn_r", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(scanners)), scanners)
    ax.set_yticks(range(len(families)), families)
    ax.set_title("GGUF detection matrix (red = detected, green = benign)")
    for i in range(len(families)):
        for j in range(len(scanners)):
            v = cell[i, j]
            if not np.isnan(v):
                ax.text(j, i, "MAL" if v else "BEN",
                        ha="center", va="center", color="white" if v else "black",
                        fontsize=8)
    fig.colorbar(im, ax=ax, ticks=[0, 1], label="verdict (1=malicious)")
    return _save(plt, fig, out_dir, "gguf_detection_matrix", fmt)


# ---------------------------------------------------------------------------
# Step 08 — Shelf-life (H3)
# ---------------------------------------------------------------------------
def chart_shelf_life(plt, out_dir: str, shelf_db: str, fmt: str) -> str | None:
    rows = _q(
        shelf_db,
        """SELECT new_version AS version, COUNT(*) AS total,
                  SUM(evasion_retained) AS retained
           FROM rescans GROUP BY new_version ORDER BY new_version""",
    )
    if not rows:
        return None
    fig, ax = plt.subplots(figsize=(8, 4.5))
    versions = [r["version"] for r in rows]
    pcts = [(r["retained"] / max(1, r["total"])) * 100 for r in rows]
    ax.bar(versions, pcts, color="#55a868")
    ax.set_ylabel("retention (%)")
    ax.set_ylim(90, 101)
    ax.set_title("H3 shelf-life: bypass retention across historical versions")
    ax.tick_params(axis="x", rotation=25)
    for i, p in enumerate(pcts):
        ax.text(i, p + 0.2, f"{p:.1f}%", ha="center", fontsize=8)
    return _save(plt, fig, out_dir, "retention_by_version", fmt)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate per-step PNG charts.")
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--shelf-db", default="data/shelf_life.db")
    ap.add_argument("--out", default="charts")
    ap.add_argument("--manifest", default="data/crawled/seed_manifest.json")
    ap.add_argument("--oracle-validation",
                    default="real_benign_corpus/oracle-validation.json")
    ap.add_argument("--fp-eval",
                    default="real_benign_corpus/oracle-calibrated/current/fp-eval-eval.json")
    ap.add_argument("--format", choices=["png", "svg"], default="png")
    args = ap.parse_args(argv)

    plt = _require_pyplot()
    out_root = os.path.join(REPO, args.out)

    steps = [
        ("01_crawl", chart_crawl, (args.manifest,), {"fmt": args.format}),
        ("02_oracle", chart_oracle, (args.oracle_validation,), {"fmt": args.format}),
        ("03_calibrate", chart_calibrate, (args.fp_eval,), {"fmt": args.format}),
        ("04_campaigns", chart_campaigns, (args.db,), {"fmt": args.format}),
        ("05_evaluation", chart_evaluation, (args.db,), {"fmt": args.format}),
        ("06_defense", chart_defense, (), {"fmt": args.format}),
        ("07_gguf", chart_gguf, (args.db,), {"fmt": args.format}),
        ("08_shelf_life", chart_shelf_life, (args.shelf_db,), {"fmt": args.format}),
    ]

    produced = 0
    for step, fn, pos_args, kw in steps:
        out_dir = os.path.join(out_root, step)
        try:
            res = fn(plt, out_dir, *pos_args, **kw)
        except Exception as exc:  # never let one step kill the rest
            print(f"[charts] {step}: error ({exc}); skipped")
            continue
        files = res if isinstance(res, list) else ([res] if res else [])
        if files:
            produced += len(files)
            print(f"[charts] {step}: wrote {len(files)} chart(s)")
            for f in files:
                print(f"          {os.path.relpath(f, REPO)}")
        else:
            print(f"[charts] {step}: skipped (data not present)")
    print(f"[charts] done: {produced} chart(s) in {out_root}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())