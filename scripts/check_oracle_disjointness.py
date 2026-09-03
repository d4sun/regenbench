#!/usr/bin/env python3
"""Oracle corpus disjointness check + deterministic resplit (Plan Phase 4.1).

The RQ3 false-positive study evaluates DynaHug on the PT benign corpus,
and ggufref on the GGUF corpus, while calibration fits OCSVM on models drawn
from the same pools. Any model scored by the oracle that also shaped its
decision boundary inflates apparent benignity ("the oracle was graded on its
own homework").

This tool:
  1. CHECK: programmatically diffs every recorded calibration identity
     (holdout repo list, legacy oracle-validation sha256 set) against the
     FP corpus. Any overlap -> exit 1 with evidence.
  2. RESPLIT: writes strictly-disjoint, cluster- AND format-stratified 50/50
     partitions of the current flat corpora to --split-out for recalibration.

Usage:
    python3 scripts/check_oracle_disjointness.py            # check + report
    python3 scripts/check_oracle_disjointness.py --resplit  # also write split
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CALIBRATION_REPORT_PT = REPO / "real_benign_corpus/oracle-calibrated/pt/calibration-report.json"
CALIBRATION_REPORT_GGUF = REPO / "real_benign_corpus/oracle-calibrated/gguf/calibration-report.json"
LEGACY_VALIDATION = REPO / "real_benign_corpus/oracle-validation.json"
SPLIT_OUT = REPO / "real_benign_corpus/oracle-split.json"


def corpus_models(corpus_dir: Path, format_ext: str = "bin") -> dict[str, dict]:
    """Flat layout <cluster>__<repo>.<ext> -> {repo_id: {path, cluster, format}}."""
    out = {}
    for p in sorted(corpus_dir.glob(f"*.{format_ext}")):
        stem = p.name[: -len(f".{format_ext}")]
        if "__" in stem:
            cluster, repo = stem.split("__", 1)
        else:
            cluster, repo = "?", stem
        out[repo] = {"path": str(p), "cluster": cluster, "format": format_ext}
    return out


def load_corpus_all() -> dict[str, dict]:
    """Load both PT and GGUF corpora."""
    corpus = {}
    for fmt, ext in [("pt", "bin"), ("gguf", "gguf")]:
        corpus_dir = REPO / f"real_benign_corpus/all_{fmt}"
        if corpus_dir.exists():
            for repo, meta in corpus_models(corpus_dir, ext).items():
                key = f"{fmt}:{repo}"
                meta["format"] = fmt
                corpus[key] = meta
    return corpus


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check(calib_report: dict, corpus: dict[str, dict], format: str) -> list[dict]:
    """Return list of overlap evidence records for a specific format."""
    evidence = []

    holdout = calib_report.get("models") or []
    for repo in holdout:
        key = f"{format}:{repo}"
        if key in corpus:
            evidence.append({
                "kind": "calibration-holdout-in-fp-corpus",
                "format": format,
                "repo": repo,
                "note": f"model scored by the FP study was part of the "
                        f"{format} calibration trace pool (recorded holdout list)",
            })

    legacy = LEGACY_VALIDATION
    if legacy.exists():
        val = json.loads(legacy.read_text())
        by_sha = {sha256_of(m["path"]): m for m in corpus.values()}
        for r in val.get("results", []):
            if r.get("format") != format:
                continue
            sha = r.get("sha256")
            if sha and sha in by_sha:
                evidence.append({
                    "kind": "legacy-validation-sha-in-fp-corpus",
                    "format": format,
                    "repo": r.get("repo_id"),
                    "sha256": sha,
                    "note": f"same file bytes were traced by the legacy "
                            f"oracle validation and appear in the {format} FP corpus",
                })
    return evidence


def resplit(corpus: dict[str, dict], seed: int = 20260822) -> dict:
    """Cluster- AND format-stratified disjoint 50/50 split of the corpus repos."""
    rng = random.Random(seed)
    by_cluster_format: dict[tuple[str, str], list[str]] = {}
    for key, meta in corpus.items():
        fmt = meta.get("format", "pt")
        cluster = meta["cluster"]
        by_cluster_format.setdefault((fmt, cluster), []).append(key)

    train, ev = [], []
    for (fmt, cluster) in sorted(by_cluster_format):
        repos = sorted(by_cluster_format[(fmt, cluster)])
        rng.shuffle(repos)
        half = len(repos) // 2
        train.extend(repos[:half])
        ev.extend(repos[half:])
    assert not (set(train) & set(ev))
    return {"seed": seed, "train": sorted(train), "eval": sorted(ev),
            "train_clusters": {}, "eval_clusters": {}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus-pt", default=str(REPO / "real_benign_corpus/all_pt"))
    ap.add_argument("--corpus-gguf", default=str(REPO / "real_benign_corpus/all_gguf"))
    ap.add_argument("--resplit", action="store_true")
    ap.add_argument("--split-out", default=str(SPLIT_OUT))
    args = ap.parse_args()

    corpus = load_corpus_all()
    pt_count = sum(1 for m in corpus.values() if m.get("format") == "pt")
    gguf_count = sum(1 for m in corpus.values() if m.get("format") == "gguf")
    print(f"[disjointness] FP corpus: {len(corpus)} models (pt={pt_count}, gguf={gguf_count})")

    all_evidence = []
    for fmt, calib_path in [("pt", CALIBRATION_REPORT_PT), ("gguf", CALIBRATION_REPORT_GGUF)]:
        if not calib_path.exists():
            print(f"[disjointness] no calibration report at {calib_path}")
            continue
        calib = json.loads(calib_path.read_text())
        print(f"[disjointness] {fmt} calibration: traced_total={calib.get('traced_total')} "
              f"train_n={calib.get('train_n')} holdout_n={calib.get('holdout_n')}")
        evidence = check(calib, corpus, fmt)
        all_evidence.extend(evidence)

    report = {
        "task": "oracle-corpus-disjointness",
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "fp_corpus_n": len(corpus),
        "fp_corpus_pt_n": pt_count,
        "fp_corpus_gguf_n": gguf_count,
        "overlap_evidence_count": len(all_evidence),
        "overlap_evidence": all_evidence,
        "verdict": "OVERLAP" if all_evidence else "DISJOINT",
    }
    out = REPO / "reference/oracle-disjointness-report.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[disjointness] report written to {out.relative_to(REPO)}")

    if all_evidence:
        kinds = {}
        for e in all_evidence:
            kinds[f"{e['format']}:{e['kind']}"] = kinds.get(f"{e['format']}:{e['kind']}", 0) + 1
        print(f"\nFAIL: oracle calibration data overlaps FP evaluation corpus:")
        for k, n in sorted(kinds.items()):
            print(f"  {n:3d} x {k}")
        for e in all_evidence[:12]:
            print(f"    e.g. {e['format']}:{e['repo']}")
    else:
        print("\nOK: no overlap between calibration identities and FP corpus.")

    if args.resplit:
        split = resplit(corpus)
        for m in split["train"]:
            fmt, repo = m.split(":", 1)
            cluster = corpus[m]["cluster"]
            split["train_clusters"].setdefault(f"{fmt}:{cluster}", 0)
            split["train_clusters"][f"{fmt}:{cluster}"] += 1
        for m in split["eval"]:
            fmt, repo = m.split(":", 1)
            cluster = corpus[m]["cluster"]
            split["eval_clusters"].setdefault(f"{fmt}:{cluster}", 0)
            split["eval_clusters"][f"{fmt}:{cluster}"] += 1
        Path(args.split_out).write_text(json.dumps(split, indent=2) + "\n")
        print(f"\n[resplit] wrote {args.split_out}")
        print(f"  train: {len(split['train'])} models {split['train_clusters']}")
        print(f"  eval : {len(split['eval'])} models {split['eval_clusters']}")
        if all_evidence:
            print("  NOTE: split written despite OVERLAP verdict; re-run "
                  "calibration restricted to 'train' before trusting FP numbers.")
        return 0

    return 1 if all_evidence else 0


if __name__ == "__main__":
    sys.exit(main())
