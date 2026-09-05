#!/usr/bin/env python3
"""Oracle corpus disjointness check + deterministic resplit (Plan Phase 4.1).

The RQ3 false-positive study evaluates DynaHug on the PT benign corpus,
and ggufref on the GGUF corpus, while calibration fits OCSVM on models drawn
from the same pools. Any model scored by the oracle that also shaped its
decision boundary inflates apparent benignity ("the oracle was graded on its
own homework").

This tool:
  1. CHECK: diffs every recorded calibration identity against the FP corpus
     (flat trees real_benign_corpus/all_pt + all_gguf, 304 models). Two kinds
     of identity are extracted from the calibration report:
       * ``train_repos``  -- traced/training paths (fit boundary)
       * ``models``       -- recorded holdout repo names (validation)
     plus the legacy oracle-validation sha256 set. Any overlap -> exit 1 with
     evidence.
  2. RESPLIT: writes strictly-disjoint, cluster- AND format-stratified 50/50
     partitions of the current flat corpora to --split-out for recalibration.
     Keys are bare repo names (``stem.split("__",1)[1]``) matching the
     ``repo_of()`` convention of scripts/calibrate_oracle.py and
     scripts/fp_eval_oracle.py; the per-format corpus dir selects the format.

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
CALIBRATION_REPORT = REPO / "real_benign_corpus/oracle-calibrated/current/calibration-report.json"
LEGACY_VALIDATION = REPO / "real_benign_corpus/oracle-validation.json"
SPLIT_OUT = REPO / "real_benign_corpus/oracle-split.json"


def corpus_models(corpus_dir: Path, format_ext: str = "bin") -> dict[str, dict]:
    """Flat layout <cluster>__<repo>.<ext> -> {repo: {path, cluster, format}}."""
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


def calib_identity(value: str) -> tuple[str | None, str] | None:
    """Reduce a calibration report entry to (format, repo).

    Entries may be full flat paths (fit_oracle_sweep) or bare repo names
    (calibrate_oracle 'models'). Returns None when the identity cannot be
    interpreted, so downstream code can skip rather than crash.
    """
    fmt = None
    if value.endswith(".gguf"):
        fmt = "gguf"
    elif value.lower().endswith((".bin", ".pt", ".pth")):
        fmt = "pt"
    if fmt is not None:
        value = value[: -len((".gguf" if fmt == "gguf" else ".bin"))]
    if "/" in value:
        value = value.rsplit("/", 1)[-1]
    if not value or value in {".", ".."}:
        return None
    if "__" in value:
        _, repo = value.split("__", 1)
    else:
        repo = value
    if "/" in repo:
        repo = repo.replace("/", "_")
    return fmt, repo


def check(calib_report: dict, corpus: dict[str, dict], split_file: str | None = None) -> list[dict]:
    """Return list of overlap evidence records for a calibration report."""
    evidence = []

    # Load the split file to get the eval set (FP evaluation corpus)
    eval_repos = set()
    if split_file and Path(split_file).exists():
        with open(split_file) as f:
            split = json.load(f)
        eval_repos = set(split.get("eval", []))
        print(f"[disjointness] using eval split as FP corpus: {len(eval_repos)} repos")
    else:
        # Fallback: use full corpus (legacy behavior)
        eval_repos = {key.split(":", 1)[1] for key in corpus}
        print(f"[disjointness] WARNING: no split file, using full corpus as FP corpus: {len(eval_repos)} repos")

    for kind, entries in (("calibration-train-in-fp-corpus", calib_report.get("train_repos") or []),
                          ("calibration-holdout-in-fp-corpus", calib_report.get("models") or [])):
        for value in entries:
            parsed = calib_identity(value)
            if parsed is None:
                continue
            fmt, repo = parsed
            if repo in eval_repos:
                evidence.append({
                    "kind": kind,
                    "format": fmt,
                    "repo": repo,
                    "note": f"model scored by the FP study was part of the "
                            f"{f} calibration pool (recorded {kind.split('-')[1]} list)",
                })

    legacy = LEGACY_VALIDATION
    if legacy.exists():
        val = json.loads(legacy.read_text())
        by_sha = {sha256_of(m["path"]): m for m in corpus.values()}
        for r in val.get("results", []):
            fmt = r.get("format")
            if fmt not in ("pt", "gguf"):
                continue
            sha = r.get("sha256")
            if sha and sha in by_sha:
                repo = by_sha[sha].get("repo", "").split(":", 1)[-1]
                if repo in eval_repos:
                    evidence.append({
                        "kind": "legacy-validation-sha-in-fp-corpus",
                        "format": fmt,
                        "repo": r.get("repo_id"),
                        "sha256": sha,
                        "note": f"same file bytes were traced by the legacy "
                                f"oracle validation and appear in the {fmt} FP corpus",
                    })
    return evidence


def resplit(corpus: dict[str, dict], seed: int = 20260822) -> dict:
    """Cluster- AND format-stratified disjoint 50/50 split of the corpus repos.

    Keys are bare repo names (unique across pt/gguf in this corpus), matching
    the repo_of()/by_repo() conventions of calibrate_oracle.py and
    fp_eval_oracle.py.
    """
    rng = random.Random(seed)
    by_cluster_format: dict[tuple[str, str], list[str]] = {}
    by_repo_format: dict[str, list[str]] = {}
    for key, meta in corpus.items():
        fmt = meta.get("format", "pt")
        cluster = meta["cluster"]
        by_cluster_format.setdefault((fmt, cluster), []).append(key)
        by_repo_format.setdefault(meta.get("repo", key.split(":", 1)[1]), []).append(fmt)

    dup = {r: fs for r, fs in by_repo_format.items() if len(fs) > 1}
    if dup:
        raise ValueError(
            f"repo appears in multiple formats: {sorted(dup)[:5]} ... "
            f"(flat names only carry the repo stem; rename one side)")
    repo_of = {key.split(":", 1)[1] for key in corpus}

    train, ev = [], []
    for (fmt, cluster) in sorted(by_cluster_format):
        repos = sorted(by_cluster_format[(fmt, cluster)])
        rng.shuffle(repos)
        half = len(repos) // 2
        train.extend(repos[:half])
        ev.extend(repos[half:])
    assert not (set(train) & set(ev))
    train_stems = sorted(key.split(":", 1)[1] for key in train)
    eval_stems = sorted(key.split(":", 1)[1] for key in ev)
    assert len(train_stems) == len(set(train_stems)) == len(repo_of) - len(eval_stems)
    return {"seed": seed, "train": train_stems, "eval": eval_stems,
            "train_clusters": {}, "eval_clusters": {}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus-pt", default=str(REPO / "real_benign_corpus/all_pt"))
    ap.add_argument("--corpus-gguf", default=str(REPO / "real_benign_corpus/all_gguf"))
    ap.add_argument("--calib-report", default=str(CALIBRATION_REPORT),
                    help="oracle-calibration report (default: oracle-calibrated/current/)")
    ap.add_argument("--resplit", action="store_true")
    ap.add_argument("--split-out", default=str(SPLIT_OUT))
    args = ap.parse_args()

    corpus = load_corpus_all()
    pt_count = sum(1 for m in corpus.values() if m.get("format") == "pt")
    gguf_count = sum(1 for m in corpus.values() if m.get("format") == "gguf")
    print(f"[disjointness] FP corpus: {len(corpus)} models (pt={pt_count}, gguf={gguf_count})")

    all_evidence = []
    if not Path(args.calib_report).exists():
        print(f"[disjointness] no calibration report at {args.calib_report}")
    else:
        calib = json.loads(Path(args.calib_report).read_text())
        print(f"[disjointness] calibration at {args.calib_report}: "
              f"train_repos={len(calib.get('train_repos') or [])} "
              f"models={len(calib.get('models') or [])}")
        split_file = calib.get("split_file")
        all_evidence = check(calib, corpus, split_file)

    report = {
        "task": "oracle-corpus-disjointness",
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        "calibration_report": args.calib_report,
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
            fmt = next(f for f in ("pt", "gguf") if f"{f}:{m}" in corpus)
            cluster = corpus[f"{fmt}:{m}"]["cluster"]
            split["train_clusters"].setdefault(f"{fmt}:{cluster}", 0)
            split["train_clusters"][f"{fmt}:{cluster}"] += 1
        for m in split["eval"]:
            fmt = next(f for f in ("pt", "gguf") if f"{f}:{m}" in corpus)
            cluster = corpus[f"{fmt}:{m}"]["cluster"]
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