#!/usr/bin/env python3
"""Capture a full ReGenBench run's results into results/<timestamp>/.

Copies the campaign DB, generated reports, exported bypasses, corpus metadata,
and oracle validation summary, then writes a human-readable results.md and a
machine-readable results.json summarizing the key quantitative findings.

Usage:
    python3 scripts/save_results.py [--db data/regenbench_campaign.db] \
        [--out results] [--corpus-dir real_benign_corpus/all]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import time

REPORTS = [
    "docs/evaluation-report.md",
    "docs/perf-report.md",
    "docs/triage-report.md",
    "docs/comparison-methodology.md",
]


def _runs(conn: sqlite3.Connection) -> list[dict]:
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT run_id, campaign_type, replicate_num, base_checkpoint, "
        "       total_candidates, total_rounds, started_at, completed_at "
        "FROM campaign_runs ORDER BY started_at"
    ).fetchall()
    out = []
    for r in rows:
        cid = r[0]
        valid = cur.execute(
            "SELECT COUNT(*) FROM campaign_fitness f "
            "JOIN candidates c ON c.candidate_id = f.candidate_id "
            "WHERE c.run_id = ? AND f.is_valid = 1", (cid,)
        ).fetchone()[0]
        confirmed = cur.execute(
            "SELECT COUNT(*) FROM candidates c "
            "WHERE c.run_id = ? AND c.confirmed_bypass = 1", (cid,)
        ).fetchone()[0] if "confirmed_bypass" in [
            x[1] for x in cur.execute("PRAGMA table_info(candidates)")] else 0
        out.append({
            "run_id": r[0], "campaign_type": r[1], "replicate_num": r[2],
            "total_candidates": r[4], "total_rounds": r[5],
            "started_at": r[6], "completed_at": r[7],
            "valid_candidates": valid, "confirmed_bypasses": confirmed,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--out", default="results")
    ap.add_argument("--corpus-dir", default="real_benign_corpus/all")
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(args.out, stamp)
    os.makedirs(out_dir, exist_ok=True)

    saved = []

    def copy(src: str, dest_name: str | None = None) -> None:
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(out_dir, dest_name or os.path.basename(src)))
            saved.append(src)

    # Core artifacts
    copy(args.db, "regenbench_campaign.db")
    copy("data/crawled/seed_manifest.json")
    copy("real_benign_corpus/oracle-validation.json")
    for rep in REPORTS:
        copy(rep)
    for fz in sorted(os.listdir("docs")):
        if fz.startswith("fuzzing-report-") and fz.endswith(".md"):
            copy(os.path.join("docs", fz))
    # Exported bypasses (if any)
    if os.path.isdir("data/bypasses"):
        shutil.copytree("data/bypasses", os.path.join(out_dir, "bypasses"),
                        dirs_exist_ok=True)

    # Corpus inventory
    corpus_count = 0
    if os.path.isdir(args.corpus_dir):
        corpus_count = len([n for n in os.listdir(args.corpus_dir)
                            if n.endswith((".pt", ".pth", ".bin"))])

    # Structured summary
    summary: dict = {"generated_at": stamp, "corpus": {"files": corpus_count}}
    if os.path.isfile(args.db):
        conn = sqlite3.connect(args.db)
        cur = conn.cursor()
        summary["runs"] = _runs(conn)
        for tbl in ("candidates", "panel_results", "oracle_results",
                    "campaign_fitness", "campaign_coverage"):
            summary.setdefault("tables", {})[tbl] = \
                cur.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        # Aggregate panel verdicts per scanner (all runs)
        panel = {}
        for row in cur.execute(
                "SELECT scanner, verdict, COUNT(*) FROM panel_results "
                "GROUP BY scanner, verdict").fetchall():
            panel.setdefault(row[0], {})[row[1]] = row[2]
        summary["panel_verdicts"] = panel
        oracle = {}
        for row in cur.execute(
                "SELECT verdict, COUNT(*) FROM oracle_results GROUP BY verdict").fetchall():
            oracle[row[0]] = row[1]
        summary["oracle_verdicts"] = oracle
        conn.close()

    # Oracle validation summary (from the JSON if present)
    ovalid = os.path.join(out_dir, "oracle-validation.json")
    if os.path.isfile(ovalid):
        try:
            with open(ovalid) as f:
                summary["oracle_validation"] = json.load(f).get("summary")
        except Exception:
            pass

    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    # Human-readable markdown
    lines = [
        "# ReGenBench Results", "",
        f"- Generated: {stamp}",
        f"- Campaign DB: `{args.db}`",
        f"- Benign corpus files: {corpus_count}",
        "",
        "## Campaigns", "",
        "| Run | Type | Replicate | Candidates | Valid | Confirmed Bypasses |",
        "| :--- | :--- | :---: | :---: | :---: | :---: |",
    ]
    for r in summary.get("runs", []):
        lines.append(
            f"| {r['run_id'][:28]} | {r['campaign_type']} | {r['replicate_num']} "
            f"| {r['total_candidates']} | {r['valid_candidates']} | "
            f"{r['confirmed_bypasses']} |"
        )
    lines += ["", "## Panel verdicts (all runs)", ""]
    for scanner in sorted(summary.get("panel_verdicts", {})):
        v = summary["panel_verdicts"][scanner]
        lines.append(f"- **{scanner}**: malicious={v.get('malicious', 0)}, "
                     f"benign={v.get('benign', 0)}, error={v.get('error', 0)}")
    lines += ["", "## Oracle verdicts (all runs)", ""]
    for verdict, n in sorted(summary.get("oracle_verdicts", {}).items()):
        lines.append(f"- {verdict}: {n}")
    with open(os.path.join(out_dir, "results.md"), "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[save_results] saved {len(saved)} artifacts to {out_dir}")
    print(f"[save_results] summary written to {os.path.join(out_dir, 'results.md')}")
    print(f"[save_results] machine-readable summary at {os.path.join(out_dir, 'results.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
