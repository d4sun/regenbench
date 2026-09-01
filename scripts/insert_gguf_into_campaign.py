#!/usr/bin/env python3
"""Phase 6 (quick-win unification) — bulk-insert the GGUF demo surface into the
unified campaign DB as ``format='gguf'`` candidates.

This makes GGUF a first-class format in the same SQLite database the pickle
campaigns write to, so the cross-format report (`generate_evaluation_report.py`)
can query ``GROUP BY format``. The 7 GGUF attack families + a synthetic benign +
the crawled real benign GGUFs are scanned through the shared
``pipeline.scanners.run_scan`` path (ggufref + modelscan) and inserted with:

    format              = 'gguf'
    attack_primitives   = JSON list of GGUF family tags (unified primitive space)
    format_specific     = JSON detail (header, ssti signals, triggered)

Idempotent: candidate ids are sha256 of the artifact name, so re-running
replaces rows in place.

Usage:
    python3 scripts/insert_gguf_into_campaign.py [--db data/regenbench_campaign.db]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.db import init_db  # noqa: E402
from pipeline.gguf_tools import (  # noqa: E402
    GGUF_ATTACKS,
    GGUF_ATTACK_LABELS,
    benign_gguf,
    generate_candidate_gguf,
)
from pipeline.scanners import SCANNERS, build_images, run_scan  # noqa: E402

RUN_ID = "gguf-demo"

# Unified attack-primitive types for the GGUF surface (see PRESENTATION.md /
# IMPLEMENTATION.md §8): header_field / ssti_vector / tensor_meta.
GGUF_PRIMITIVE_TYPE = {
    "ssti_chat_template": "ssti_vector",
    "ssti_obfuscated_1": "ssti_vector",
    "ssti_obfuscated_2": "ssti_vector",
    "ssti_obfuscated_3": "ssti_vector",
    "nkv_overflow": "header_field",
    "ntensors_overflow": "header_field",
    "string_overflow": "header_field",
    "path_traversal": "tensor_meta",
    "negative_dims": "tensor_meta",
    "version_zero": "header_field",
}


def build_artifacts(out_dir: str, corpus_dir: str) -> list[tuple[str, str, str, bool]]:
    """Return [(name, path, family, is_benign)] for the full GGUF surface."""
    os.makedirs(out_dir, exist_ok=True)
    items: list[tuple[str, str, str, bool]] = []
    for fam in GGUF_ATTACKS:
        name = GGUF_ATTACK_LABELS[fam] + ".gguf"
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(generate_candidate_gguf(fam))
        items.append((name, path, fam, False))
    synth_name = "benign-synth.gguf"
    synth_path = os.path.join(out_dir, synth_name)
    with open(synth_path, "wb") as f:
        f.write(benign_gguf())
    items.append((synth_name, synth_path, "benign-synth", True))
    if os.path.isdir(corpus_dir):
        for root, _dirs, names in os.walk(corpus_dir):
            for n in sorted(names):
                if n.endswith(".gguf"):
                    items.append((n, os.path.join(root, n), "real-benign", True))
    return items


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--backend", default="docker")
    ap.add_argument("--corpus", default="data/gguf_benign_corpus",
                    help="real benign GGUF corpus (scripts/crawl_gguf.py)")
    ap.add_argument("--workdir", default="demo-artifacts/gguf")
    args = ap.parse_args(argv)

    init_db(args.db)
    items = build_artifacts(args.workdir, args.corpus)
    print(f"[insert-gguf] {len(items)} GGUF artifacts "
          f"({len([i for i in items if not i[3]])} attacks + synth, "
          f"{len([i for i in items if i[3] and i[2] == 'real-benign'])} real benign)")

    images = build_images(SCANNERS, ":latest")
    db = sqlite3.connect(args.db)
    cur = db.cursor()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Idempotent full replace of the previous gguf-demo run.
    cur.execute("DELETE FROM panel_results WHERE candidate_id IN "
                "(SELECT candidate_id FROM candidates WHERE run_id=?)", (RUN_ID,))
    cur.execute("DELETE FROM campaign_fitness WHERE candidate_id IN "
                "(SELECT candidate_id FROM candidates WHERE run_id=?)", (RUN_ID,))
    cur.execute("DELETE FROM candidates WHERE run_id=?", (RUN_ID,))
    cur.execute("DELETE FROM campaign_runs WHERE run_id=?", (RUN_ID,))
    db.commit()

    inserted = 0
    for name, path, family, is_benign in items:
        candidate_id = hashlib.sha256(f"gguf:{name}".encode()).hexdigest()

        out_ref, err_ref = run_scan(args.backend, images["ggufref"], path,
                                    timeout=180, gguf_ref=True)
        out_ms, err_ms = run_scan(args.backend, images["modelscan"], path, timeout=120)
        ref_v = (out_ref or {}).get("verdict") or "error"
        ms_v = (out_ms or {}).get("verdict") or "error"
        triggered = bool((out_ref or {}).get("triggered"))
        load_ok = bool(((out_ref or {}).get("summary") or {}).get("load_ok"))
        # GGUF execution confirmation: strace-observed process spawn, decoupled
        # from static detection (SSTI_SIGNALS / trigger polling).
        strace_executed = bool(((out_ref or {}).get("summary") or {}).get("strace_executed"))
        # Valid = loadable (benign) OR strace-executed (attack that ran).
        is_valid = 1 if (load_ok or strace_executed) else 0

        primitives = [] if is_benign else [family]
        fmt_spec = {
            "header": (out_ref or {}).get("header"),
            "malformed": (out_ref or {}).get("malformed"),
            "ssti": (out_ref or {}).get("ssti_suspicious"),
            "triggered": triggered,
            "strace_executed": strace_executed,
        }
        panel_verdict = "all_benign" if ref_v == "benign" and ms_v == "benign" else "flagged"
        oracle_verdict = "malicious" if (triggered or strace_executed) else "benign"

        cur.execute(
            """INSERT OR REPLACE INTO candidates
               (candidate_id, filepath, source, created_at, round_num, seed_model,
                mutation_template, mutation_depth, callables_used, campaign_type,
                run_id, oracle_verdict, panel_verdict, format, attack_primitives,
                format_specific)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (candidate_id, path, "gguf-demo", now, 0, "gguf",
             family, 0, json.dumps(primitives), "gguf-demo", RUN_ID,
             oracle_verdict, panel_verdict, "gguf",
             json.dumps(primitives), json.dumps(fmt_spec)))
        cur.execute(
            "INSERT OR REPLACE INTO panel_results (candidate_id, scanner, verdict, exit_code, findings, duration)"
            " VALUES (?,?,?,?,?,?)",
            (candidate_id, "ggufref", ref_v, (out_ref or {}).get("exit_code") or 2,
             json.dumps((out_ref or {}).get("findings") or []), 0.0))
        cur.execute(
            "INSERT OR REPLACE INTO panel_results (candidate_id, scanner, verdict, exit_code, findings, duration)"
            " VALUES (?,?,?,?,?,?)",
            (candidate_id, "modelscan", ms_v, (out_ms or {}).get("exit_code") or 2,
             json.dumps((out_ms or {}).get("findings") or []), 0.0))
        cur.execute(
            "INSERT OR REPLACE INTO campaign_fitness (candidate_id, fitness_score, is_valid)"
            " VALUES (?,?,?)",
            (candidate_id, 0.0, is_valid))
        inserted += 1
        print(f"  {name:44s} ggufref={ref_v:9s} modelscan={ms_v:9s} panel={panel_verdict}",
              flush=True)

    cur.execute(
        "INSERT OR REPLACE INTO campaign_runs "
        "(run_id, campaign_type, replicate_num, total_candidates, total_rounds, started_at, completed_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (RUN_ID, "gguf-demo", 1, inserted, 1, now, now))
    db.commit()
    db.close()
    print(f"[insert-gguf] inserted {inserted} format='gguf' candidates into {args.db} (run_id={RUN_ID})")
    return 0


if __name__ == "__main__":
    sys.exit(main())