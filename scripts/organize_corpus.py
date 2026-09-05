#!/usr/bin/env python3
"""Phase 1 — organize the real benign corpus into population directories (PT + GGUF).

The experiment maintains format-specific populations:
    real_benign_corpus/all_pt/           every downloaded PT checkpoint
    real_benign_corpus/all_gguf/         every downloaded GGUF checkpoint
    real_benign_corpus/oracle_positive/  checkpoints where oracle scores > 0 (PT) or load_ok (GGUF)
    real_benign_corpus/oracle_negative/  checkpoints where oracle scores < 0 (PT) or load failed (GGUF)

This script builds the positive/negative views as hard links (no data copy)
from an oracle-validation JSON report. Every checkpoint stays in `all_*/`; the
views are only for *seed selection*, never for filtering the RQ3 FP study.

Usage:
    PYTHONPATH=.:.pip_deps python3 scripts/organize_corpus.py \
        --corpus-pt real_benign_corpus/all_pt \
        --corpus-gguf real_benign_corpus/all_gguf \
        --report real_benign_corpus/oracle-validation.json \
        --out real_benign_corpus
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys


def safe_name(repo_id: str) -> str:
    return repo_id.replace("/", "_").replace(":", "_")


def build_views(corpus_pt: str, corpus_gguf: str, report_path: str, out_dir: str) -> int:
    if not os.path.isfile(report_path):
        print(f"[organize] error: no oracle validation report at {report_path}")
        print("           run scripts/validate_oracle.py first")
        return 1

    with open(report_path) as f:
        report = json.load(f)

    pos_dir = os.path.join(out_dir, "oracle_positive")
    neg_dir = os.path.join(out_dir, "oracle_negative")
    os.makedirs(pos_dir, exist_ok=True)
    os.makedirs(neg_dir, exist_ok=True)

    n_pos = n_neg = n_err = 0
    for rec in report.get("results", []):
        score = rec.get("decision_score")
        fmt = rec.get("format", "pt")
        src = rec.get("path")
        if not src or not os.path.isfile(src):
            continue
        repo = rec.get("repo_id") or os.path.basename(os.path.dirname(src))
        cluster = rec.get("cluster", "unknown")
        dest_dir = None
        
        if fmt == "pt":
            # PT uses DynaHug decision_score
            if score is None:
                n_err += 1
                continue
            dest_dir = pos_dir if score > 0 else neg_dir
            ext = ".bin"
        else:
            # GGUF uses ggufref: load_ok = positive, else negative. Reports from
            # the current validate_oracle carry load_ok directly; fall back to
            # the verdict heuristic for legacy reports.
            load_ok = rec.get("load_ok")
            if load_ok is None:
                if rec.get("verdict") == "benign":
                    load_ok = True
                elif rec.get("verdict") == "malicious":
                    load_ok = False
                else:
                    n_err += 1
                    continue
            dest_dir = pos_dir if load_ok else neg_dir
            ext = ".gguf"
        
        target = os.path.join(dest_dir, cluster, safe_name(repo))
        os.makedirs(target, exist_ok=True)
        dest = os.path.join(target, f"pytorch_model{ext}")
        if not os.path.exists(dest):
            try:
                os.link(src, dest)  # hard link, no extra disk
            except OSError:
                shutil.copyfile(src, dest)
        if (fmt == "pt" and score > 0) or (fmt == "gguf" and load_ok):
            n_pos += 1
        else:
            n_neg += 1

    print(f"[organize] oracle_positive/  : {n_pos} models")
    print(f"[organize] oracle_negative/  : {n_neg} models")
    print(f"[organize] unscored (error)  : {n_err} models")
    print(f"[organize] every model remains in {corpus_pt} and {corpus_gguf} (unchanged)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="organize_corpus", description=__doc__)
    ap.add_argument("--corpus-pt", default="real_benign_corpus/all_pt",
                    help="directory of real downloaded PT checkpoints")
    ap.add_argument("--corpus-gguf", default="real_benign_corpus/all_gguf",
                    help="directory of real downloaded GGUF checkpoints")
    ap.add_argument("--report", default="real_benign_corpus/oracle-validation.json",
                    help="oracle validation report (from validate_oracle.py)")
    ap.add_argument("--out", default="real_benign_corpus",
                    help="directory to create oracle_positive/ and oracle_negative/ under")
    args = ap.parse_args()
    return build_views(args.corpus_pt, args.corpus_gguf, args.report, args.out)


if __name__ == "__main__":
    sys.exit(main())
