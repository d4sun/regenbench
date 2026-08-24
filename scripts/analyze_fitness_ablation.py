#!/usr/bin/env python3
"""Analyze fitness ablation experiment results.

Compares 4 configurations:
  - Current (guided)
  - Oracle-aware (guided)
  - Oracle-dominant (guided)
  - Unguided (baseline)

Run after completing 5×5 replication experiment.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any

try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


@dataclass
class CampaignMetrics:
    run_id: str
    campaign_type: str
    fitness_mode: str
    replicate: int
    total_candidates: int
    valid_candidates: int
    confirmed_bypasses: int
    panel_evasions: int
    q_first: int | None
    censored: bool
    opcode_coverage: float
    callable_coverage: float
    validity_rate: float
    confirmed_bypass_rate: float
    panel_evasion_rate: float


def query_campaign_metrics(db_path: str) -> list[CampaignMetrics]:
    """Extract per-campaign metrics for fitness ablation analysis."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Get all campaign runs with their configs
        # Only include runs that have fitness_mode in run_id (new experiment runs)
        # Old runs like "guided-r1" don't have fitness mode info
        runs = cursor.execute("""
            SELECT run_id, campaign_type, replicate_num, total_candidates,
                   CASE 
                       WHEN run_id LIKE '%-current-r%' THEN 'current'
                       WHEN run_id LIKE '%-oracle_aware-r%' THEN 'oracle_aware'
                       WHEN run_id LIKE '%-oracle_dominant-r%' THEN 'oracle_dominant'
                       ELSE NULL
                   END as fitness_mode
            FROM campaign_runs
            WHERE campaign_type IN ('guided', 'unguided')
              AND (run_id LIKE '%-current-r%' 
                   OR run_id LIKE '%-oracle_aware-r%' 
                   OR run_id LIKE '%-oracle_dominant-r%'
                   OR campaign_type = 'unguided')
            ORDER BY campaign_type, replicate_num
        """).fetchall()

        results = []
        for run in runs:
            run_id = run["run_id"]
            total = run["total_candidates"] or 0

            # Valid candidates
            valid = cursor.execute("""
                SELECT COUNT(*) FROM campaign_fitness f
                JOIN candidates c ON c.candidate_id = f.candidate_id
                WHERE c.run_id = ? AND f.is_valid = 1
            """, (run_id,)).fetchone()[0] or 0

            # Confirmed bypasses
            confirmed = cursor.execute("""
                SELECT COUNT(*)
                FROM oracle_results o
                JOIN candidates c ON c.candidate_id = o.candidate_id
                JOIN campaign_fitness f ON f.candidate_id = o.candidate_id
                WHERE c.run_id = ?
                  AND o.verdict = 'malicious' AND o.pre_filtered = 0
                  AND f.is_valid = 1
                  AND EXISTS (
                      SELECT 1 FROM panel_results p
                      WHERE p.candidate_id = o.candidate_id AND p.verdict = 'benign'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM panel_results p
                      WHERE p.candidate_id = o.candidate_id
                        AND p.verdict IN ('malicious', 'error')
                  )
            """, (run_id,)).fetchone()[0] or 0

            # Panel evasions (valid candidates that evaded all panel scanners)
            panel_evasions = cursor.execute("""
                SELECT COUNT(DISTINCT f.candidate_id)
                FROM campaign_fitness f
                JOIN candidates c ON c.candidate_id = f.candidate_id
                WHERE c.run_id = ? AND f.is_valid = 1
                  AND EXISTS (SELECT 1 FROM panel_results p
                              WHERE p.candidate_id = f.candidate_id
                                AND p.verdict = 'benign')
                  AND NOT EXISTS (SELECT 1 FROM panel_results p
                                  WHERE p.candidate_id = f.candidate_id
                                    AND p.verdict IN ('malicious', 'error'))
            """, (run_id,)).fetchone()[0] or 0

            # Queries to first confirmed bypass
            rows = cursor.execute("""
                SELECT c.candidate_id, c.created_at, c.round_num
                FROM candidates c
                JOIN campaign_fitness f ON f.candidate_id = c.candidate_id
                WHERE c.run_id = ? AND f.is_valid = 1
                ORDER BY c.round_num ASC, c.created_at ASC, c.candidate_id ASC
            """, (run_id,)).fetchall()

            first_bypass = None
            q = 0
            for row in rows:
                q += 1
                cand = cursor.execute("""
                    SELECT o.verdict AS ov
                    FROM oracle_results o
                    WHERE o.candidate_id = ? AND o.pre_filtered = 0
                """, (row["candidate_id"],)).fetchone()
                if not cand or cand["ov"] != "malicious":
                    continue
                panel = cursor.execute("""
                    SELECT
                        COUNT(*) FILTER (WHERE verdict = 'benign') AS benign_n,
                        COUNT(*) FILTER (WHERE verdict = 'malicious') AS malicious_n,
                        COUNT(*) FILTER (WHERE verdict = 'error') AS error_n
                    FROM panel_results
                    WHERE candidate_id = ?
                """, (row["candidate_id"],)).fetchone()
                if panel and panel["benign_n"] > 0 and panel["malicious_n"] == 0 and panel["error_n"] == 0:
                    first_bypass = q
                    break

            censored = first_bypass is None
            if first_bypass is None:
                first_bypass = total + 1

            # Coverage
            cov = cursor.execute("""
                SELECT opcode_coverage, callable_coverage
                FROM campaign_coverage
                WHERE run_id = ?
                ORDER BY round_num DESC LIMIT 1
            """, (run_id,)).fetchone()
            opcode_cov = cov["opcode_coverage"] if cov else 0.0
            callable_cov = cov["callable_coverage"] if cov else 0.0

            results.append(CampaignMetrics(
                run_id=run_id,
                campaign_type=run["campaign_type"],
                fitness_mode=run["fitness_mode"],
                replicate=run["replicate_num"],
                total_candidates=total,
                valid_candidates=valid,
                confirmed_bypasses=confirmed,
                panel_evasions=panel_evasions,
                q_first=first_bypass,
                censored=censored,
                opcode_coverage=opcode_cov,
                callable_coverage=callable_cov,
                validity_rate=valid / max(1, total),
                confirmed_bypass_rate=confirmed / max(1, valid),
                panel_evasion_rate=panel_evasions / max(1, valid),
            ))

        return results

    finally:
        conn.close()


def query_strategy_effectiveness(db_path: str) -> list[dict]:
    """Per-strategy effectiveness breakdown."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT 
                mutation_strategy,
                COUNT(*) as generated,
                SUM(CASE WHEN is_valid = 1 THEN 1 ELSE 0 END) as valid,
                SUM(CASE WHEN is_valid = 1 AND panel_evaded = 1 THEN 1 ELSE 0 END) as panel_evasion,
                SUM(CASE WHEN is_valid = 1 AND confirmed_bypass = 1 THEN 1 ELSE 0 END) as confirmed_bypass
            FROM (
                SELECT 
                    c.candidate_id,
                    c.mutation_strategy,
                    f.is_valid,
                    CASE 
                        WHEN EXISTS (
                            SELECT 1 FROM panel_results p 
                            WHERE p.candidate_id = c.candidate_id AND p.verdict = 'benign'
                        )
                        AND NOT EXISTS (
                            SELECT 1 FROM panel_results p 
                            WHERE p.candidate_id = c.candidate_id AND p.verdict IN ('malicious', 'error')
                        )
                        THEN 1 ELSE 0 END as panel_evaded,
                    CASE 
                        WHEN EXISTS (
                            SELECT 1 FROM panel_results p 
                            WHERE p.candidate_id = c.candidate_id AND p.verdict = 'benign'
                        )
                        AND NOT EXISTS (
                            SELECT 1 FROM panel_results p 
                            WHERE p.candidate_id = c.candidate_id AND p.verdict IN ('malicious', 'error')
                        )
                        AND EXISTS (
                            SELECT 1 FROM oracle_results o 
                            WHERE o.candidate_id = c.candidate_id 
                              AND o.verdict = 'malicious' AND o.pre_filtered = 0
                        )
                        THEN 1 ELSE 0 END as confirmed_bypass
                FROM candidates c
                JOIN campaign_fitness f ON f.candidate_id = c.candidate_id
                WHERE c.mutation_strategy IS NOT NULL AND c.mutation_strategy != ''
            )
            GROUP BY mutation_strategy
            ORDER BY confirmed_bypass DESC, generated DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def query_scanner_bypasses(db_path: str) -> list[dict]:
    """Per-scanner bypass rates by fitness mode."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT 
                CASE 
                    WHEN cr.run_id LIKE '%-current-r%' THEN 'current'
                    WHEN cr.run_id LIKE '%-oracle_aware-r%' THEN 'oracle_aware'
                    WHEN cr.run_id LIKE '%-oracle_dominant-r%' THEN 'oracle_dominant'
                    ELSE 'unknown'
                END as fitness_mode,
                p.scanner,
                SUM(CASE WHEN f.is_valid = 1 AND p.verdict = 'benign' THEN 1 ELSE 0 END) as evaded,
                SUM(CASE WHEN f.is_valid = 1 THEN 1 ELSE 0 END) as admitted
            FROM candidates c
            JOIN campaign_runs cr ON cr.run_id = c.run_id
            JOIN campaign_fitness f ON f.candidate_id = c.candidate_id
            JOIN panel_results p ON p.candidate_id = c.candidate_id
            WHERE c.campaign_type = 'guided'
              AND cr.fitness_mode IN ('current', 'oracle_aware', 'oracle_dominant')
            GROUP BY fitness_mode, p.scanner
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def mann_whitney_u(group_a: list[float], group_b: list[float]) -> dict:
    """Mann-Whitney U test (independent samples)."""
    if not HAS_SCIPY:
        return {"note": "scipy not available", "u": None, "p": None}
    if len(group_a) < 2 or len(group_b) < 2:
        return {"note": "insufficient samples", "u": None, "p": None}
    u, p = stats.mannwhitneyu(group_a, group_b, alternative="two-sided")
    return {"u": float(u), "p": float(p), "method": "Mann-Whitney U"}


def kaplan_meier_qfirst(qfirst_a: list[int], censored_a: list[bool],
                        qfirst_b: list[int], censored_b: list[bool]) -> dict:
    """Compare Q_first using Kaplan-Meier + log-rank test."""
    if not HAS_SCIPY:
        return {"note": "scipy not available"}
    # Simple comparison for now - full survival analysis would need lifelines
    return {"note": "Kaplan-Meier not fully implemented; use Mann-Whitney on uncensored"}


def print_comparison_table(metrics: list[CampaignMetrics]) -> None:
    """Print formatted comparison table."""
    print("\n" + "=" * 120)
    print("FITNESS ABLATION EXPERIMENT RESULTS")
    print("=" * 120)

    # Group by config
    configs = {}
    for m in metrics:
        key = f"{m.campaign_type}:{m.fitness_mode}" if m.campaign_type == "guided" else "unguided:baseline"
        if key not in configs:
            configs[key] = []
        configs[key].append(m)

    # Header
    print(f"{'Config':<25} {'Rep':>3} {'Total':>6} {'Valid':>6} {'Bypass':>6} {'PanelEv':>6} "
          f"{'Q1st':>5} {'Cens':>4} {'Valid%':>6} {'Bypass%':>7} {'Panel%':>6} {'OpCov%':>6} {'CalCov%':>7}")
    print("-" * 120)

    for config_name, runs in sorted(configs.items()):
        for m in sorted(runs, key=lambda x: x.replicate):
            q_str = str(m.q_first) if m.q_first else "N/A"
            print(f"{config_name:<25} {m.replicate:>3} {m.total_candidates:>6} {m.valid_candidates:>6} "
                  f"{m.confirmed_bypasses:>6} {m.panel_evasions:>6} {q_str:>5} "
                  f"{'Y' if m.censored else 'N':>4} {m.validity_rate*100:>5.1f}% "
                  f"{m.confirmed_bypass_rate*100:>6.1f}% {m.panel_evasion_rate*100:>5.1f}% "
                  f"{m.opcode_coverage*100:>5.1f}% {m.callable_coverage*100:>6.1f}%")

    # Summary statistics
    print("\n" + "=" * 120)
    print("SUMMARY STATISTICS (mean ± std across 5 replicates)")
    print("=" * 120)
    print(f"{'Config':<25} {'Valid%':<12} {'ConfBypass%':<14} {'PanelEv%':<12} {'Q1st(med)':<12} {'Censored':<10} {'OpCov%':<10} {'CalCov%':<10}")
    print("-" * 120)

    for config_name, runs in sorted(configs.items()):
        valid_rates = [m.validity_rate * 100 for m in runs]
        bypass_rates = [m.confirmed_bypass_rate * 100 for m in runs]
        panel_rates = [m.panel_evasion_rate * 100 for m in runs]
        qfirst_vals = [m.q_first for m in runs if not m.censored]
        censored_counts = sum(1 for m in runs if m.censored)
        opcode_covs = [m.opcode_coverage * 100 for m in runs]
        callable_covs = [m.callable_coverage * 100 for m in runs]

        def fmt(vals):
            if not vals:
                return "N/A"
            import statistics
            return f"{statistics.mean(vals):.1f}±{statistics.stdev(vals):.1f}" if len(vals) > 1 else f"{vals[0]:.1f}"

        qfirst_med = "N/A"
        if qfirst_vals:
            import statistics
            qfirst_med = f"{statistics.median(qfirst_vals):.0f}"

        print(f"{config_name:<25} {fmt(valid_rates):<12} {fmt(bypass_rates):<14} {fmt(panel_rates):<12} "
              f"{qfirst_med:<12} {censored_counts}/5{'':<5} {fmt(opcode_covs):<10} {fmt(callable_covs):<10}")

    # Statistical tests
    print("\n" + "=" * 120)
    print("STATISTICAL TESTS (Mann-Whitney U, two-sided)")
    print("=" * 120)

    guided_configs = ["guided:current", "guided:oracle_aware", "guided:oracle_dominant"]
    unguided_runs = configs.get("unguided:baseline", [])

    for g_name in guided_configs:
        g_runs = configs.get(g_name, [])
        if not g_runs or not unguided_runs:
            continue

        g_bypass = [m.confirmed_bypass_rate for m in g_runs]
        u_bypass = [m.confirmed_bypass_rate for m in unguided_runs]
        g_qfirst = [m.q_first for m in g_runs if not m.censored]
        u_qfirst = [m.q_first for m in unguided_runs if not m.censored]
        g_valid = [m.validity_rate for m in g_runs]
        u_valid = [m.validity_rate for m in unguided_runs]

        test_bypass = mann_whitney_u(g_bypass, u_bypass)
        test_qfirst = mann_whitney_u(g_qfirst, u_qfirst) if g_qfirst and u_qfirst else {"note": "insufficient uncensored"}
        test_valid = mann_whitney_u(g_valid, u_valid)

        print(f"\n{g_name} vs unguided:")
        print(f"  Confirmed bypass rate: U={test_bypass.get('u')}, p={test_bypass.get('p')}")
        print(f"  Q_first (uncensored):  U={test_qfirst.get('u')}, p={test_qfirst.get('p')}")
        print(f"  Validity rate:         U={test_valid.get('u')}, p={test_valid.get('p')}")


def print_strategy_table(db_path: str) -> None:
    """Print per-strategy effectiveness."""
    results = query_strategy_effectiveness(db_path)
    if not results:
        print("\nNo strategy data available.")
        return

    print("\n" + "=" * 80)
    print("PER-STRATEGY EFFECTIVENESS")
    print("=" * 80)
    print(f"{'Strategy':<30} {'Gen':>6} {'Valid':>6} {'PanEv':>6} {'ConfByp':>7} "
          f"{'Val%':>6} {'PanEv%':>7} {'ConfByp%':>8}")
    print("-" * 80)
    for r in results:
        gen = r["generated"]
        val = r["valid"]
        pan = r["panel_evasion"]
        conf = r["confirmed_bypass"]
        print(f"{r['mutation_strategy']:<30} {gen:>6} {val:>6} {pan:>6} {conf:>7} "
              f"{val/max(1,gen)*100:>5.1f}% {pan/max(1,val)*100:>6.1f}% {conf/max(1,val)*100:>7.1f}%")


def print_scanner_table(db_path: str) -> None:
    """Print per-scanner bypass rates by fitness mode."""
    results = query_scanner_bypasses(db_path)
    if not results:
        print("\nNo scanner data available.")
        return

    print("\n" + "=" * 80)
    print("PER-SCANNER BYPASS RATES BY FITNESS MODE")
    print("=" * 80)
    print(f"{'Fitness Mode':<18} {'Scanner':<15} {'Evaded':>8} {'Admitted':>8} {'Rate':>8}")
    print("-" * 80)
    for r in results:
        rate = r["evaded"] / max(1, r["admitted"]) * 100
        print(f"{r['fitness_mode']:<18} {r['scanner']:<15} {r['evaded']:>8} {r['admitted']:>8} {rate:>7.1f}%")


def main():
    ap = argparse.ArgumentParser(description="Analyze fitness ablation experiment")
    ap.add_argument("--db", default="data/regenbench_campaign.db", help="campaign SQLite DB")
    ap.add_argument("--json", help="output JSON summary to file")
    args = ap.parse_args()

    metrics = query_campaign_metrics(args.db)

    if not metrics:
        print("No campaign data found in database.")
        return 1

    print_comparison_table(metrics)
    print_strategy_table(args.db)
    print_scanner_table(args.db)

    # JSON output
    if args.json:
        output = {
            "campaigns": [
                {
                    "run_id": m.run_id,
                    "campaign_type": m.campaign_type,
                    "fitness_mode": m.fitness_mode,
                    "replicate": m.replicate,
                    "total_candidates": m.total_candidates,
                    "valid_candidates": m.valid_candidates,
                    "confirmed_bypasses": m.confirmed_bypasses,
                    "panel_evasions": m.panel_evasions,
                    "q_first": m.q_first,
                    "censored": m.censored,
                    "opcode_coverage": m.opcode_coverage,
                    "callable_coverage": m.callable_coverage,
                    "validity_rate": m.validity_rate,
                    "confirmed_bypass_rate": m.confirmed_bypass_rate,
                    "panel_evasion_rate": m.panel_evasion_rate,
                }
                for m in metrics
            ],
            "strategies": query_strategy_effectiveness(args.db),
            "scanners": query_scanner_bypasses(args.db),
        }
        with open(args.json, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nJSON summary written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())