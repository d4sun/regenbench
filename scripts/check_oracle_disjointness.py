#!/usr/bin/env python3
"""Oracle corpus disjointness check + deterministic resplit (Plan Phase 4.1).

The RQ3 false-positive study evaluates DynaHug on the 96-model benign corpus,
while scripts/calibrate_oracle.py fit the replacement OCSVM on models drawn
from the same pool. Any model scored by the oracle that also shaped its
decision boundary inflates apparent benignity ("the oracle was graded on its
own homework").

This tool:
  1. CHECK: programmatically diffs every recorded calibration identity
     (holdout repo list, legacy oracle-validation sha256 set) against the
     96-model FP corpus. Any overlap -> exit 1 with evidence.
  2. RESPLIT: writes a strictly-disjoint, cluster-stratified, seeded 48/48
     partition of the current flat corpus to --split-out for recalibration.

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
CALIBRATION_REPORT = REPO / "real_benign_corpus/oracle-calibrated/text-generation/calibration-report.json"
LEGACY_VALIDATION = REPO / "real_benign_corpus/oracle-validation.json"
SPLIT_OUT = REPO / "real_benign_corpus/oracle-split.json"


def corpus_models(corpus_dir: Path) -> dict[str, dict]:
    """Flat layout <cluster>__<repo>.bin -> {repo_id: {path, cluster}}."""
    out = {}
    for p in sorted(corpus_dir.glob("*.bin")):
        stem = p.name[: -len(".bin")]
        if "__" in stem:
            cluster, repo = stem.split("__", 1)
        else:
            cluster, repo = "?", stem
        out[repo] = {"path": str(p), "cluster": cluster}
    return out


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check(calib_report: dict, corpus: dict[str, dict]) -> list[dict]:
    """Return list of overlap evidence records."""
    evidence = []

    holdout = calib_report.get("models") or []
    for repo in holdout:
        if repo in corpus:
            evidence.append({
                "kind": "calibration-holdout-in-fp-corpus",
                "repo": repo,
                "note": "model scored by the FP study was part of the "
                        "calibration trace pool (recorded holdout list)",
            })

    legacy = LEGACY_VALIDATION
    if legacy.exists():
        val = json.loads(legacy.read_text())
        by_sha = {sha256_of(m["path"]): m for m in corpus.values()}
        for r in val.get("results", []):
            sha = r.get("sha256")
            if sha and sha in by_sha:
                evidence.append({
                    "kind": "legacy-validation-sha-in-fp-corpus",
                    "repo": r.get("repo_id"),
                    "sha256": sha,
                    "note": "same file bytes were traced by the legacy "
                            "oracle validation and appear in the FP corpus",
                })
    return evidence


def resplit(corpus: dict[str, dict], seed: int = 20260822) -> dict:
    """Cluster-stratified disjoint 50/50 split of the corpus repos."""
    rng = random.Random(seed)
    by_cluster: dict[str, list[str]] = {}
    for repo, meta in corpus.items():
        by_cluster.setdefault(meta["cluster"], []).append(repo)

    train, ev = [], []
    for cluster in sorted(by_cluster):
        repos = sorted(by_cluster[cluster])
        rng.shuffle(repos)
        half = len(repos) // 2
        train.extend(repos[:half])
        ev.extend(repos[half:])
    assert not (set(train) & set(ev))
    return {"seed": seed, "train": sorted(train), "eval": sorted(ev),
            "train_clusters": {}, "eval_clusters": {}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(REPO / "real_benign_corpus/all"))
    ap.add_argument("--resplit", action="store_true")
    ap.add_argument("--split-out", default=str(SPLIT_OUT))
    args = ap.parse_args()

    corpus = corpus_models(Path(args.corpus))
    print(f"[disjointness] FP corpus: {len(corpus)} models")

    calib = json.loads(CALIBRATION_REPORT.read_text()) if CALIBRATION_REPORT.exists() else {}
    if not calib:
        print(f"[disjointness] no calibration report at {CALIBRATION_REPORT}")
        return 1

    print(f"[disjointness] calibration: traced_total={calib.get('traced_total')} "
          f"train_n={calib.get('train_n')} holdout_n={calib.get('holdout_n')} "
          f"(fit-set membership beyond the recorded holdout is not recoverable "
          f"from artifacts; overlap below is a lower bound)")

    evidence = check(calib, corpus)

    report = {
        "task": "oracle-corpus-disjointness",
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "fp_corpus_n": len(corpus),
        "calibration_traced_total": calib.get("traced_total"),
        "calibration_holdout_n": calib.get("holdout_n"),
        "overlap_evidence_count": len(evidence),
        "overlap_evidence": evidence,
        "verdict": "OVERLAP" if evidence else "DISJOINT",
    }
    out = REPO / "reference/oracle-disjointness-report.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[disjointness] report written to {out.relative_to(REPO)}")

    if evidence:
        kinds = {}
        for e in evidence:
            kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        print(f"\nFAIL: oracle calibration data overlaps FP evaluation corpus:")
        for k, n in sorted(kinds.items()):
            print(f"  {n:3d} x {k}")
        for e in evidence[:12]:
            print(f"    e.g. {e['repo']}")
    else:
        print("\nOK: no overlap between calibration identities and FP corpus.")

    if args.resplit:
        split = resplit(corpus)
        for m in split["train"]:
            split["train_clusters"].setdefault(corpus[m]["cluster"], 0)
            split["train_clusters"][corpus[m]["cluster"]] += 1
        for m in split["eval"]:
            split["eval_clusters"].setdefault(corpus[m]["cluster"], 0)
            split["eval_clusters"][corpus[m]["cluster"]] += 1
        Path(args.split_out).write_text(json.dumps(split, indent=2) + "\n")
        t_c = split["train_clusters"]
        e_c = split["eval_clusters"]
        print(f"\n[resplit] wrote {args.split_out}")
        print(f"  train: {len(split['train'])} models {t_c}")
        print(f"  eval : {len(split['eval'])} models {e_c}")
        if evidence:
            print("  NOTE: split written despite OVERLAP verdict; re-run "
                  "calibration restricted to 'train' before trusting FP numbers.")
        return 0

    return 1 if evidence else 0


if __name__ == "__main__":
    sys.exit(main())
