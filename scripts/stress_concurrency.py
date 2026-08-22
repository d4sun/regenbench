#!/usr/bin/env python3
"""Concurrency stress test (Plan Phase 3.2).

The Section 7b bug was a silent race: under concurrency >= 2 with private
SELinux relabel mounts (uppercase-Z flag, since corrected to the shared
lowercase form), scanners emitted 'error' verdicts nondeterministically
(9.4%-43.8% across runs). This harness establishes a sequential reference
verdict distribution over a fixed corpus, then re-runs the same scans under
increasing concurrency and fails if ANY verdict diverges.

The default trial budget is >= 50 concurrent scans, per the correctness plan's
requirement that "8/8 deterministic" small samples are insufficient evidence.

Usage:
    python3 scripts/stress_concurrency.py [--scanners picklescan fickling]
        [--concurrencies 2 4 8] [--trials-per-config 18] [--tag :latest]
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from pipeline.scanners import run_scan  # noqa: E402


def build_corpus() -> list[str]:
    pkl_ben = sorted((REPO / "ci/corpus/pkl/benign").glob("*.pkl"))
    pkl_mal = sorted((REPO / "ci/corpus/pkl/malicious").glob("*.pkl"))
    torch = sorted((REPO / "ci/corpus/torch/benign").glob("*.pt")) + \
        sorted((REPO / "ci/corpus/torch/malicious").glob("*.pt"))
    return [str(p) for p in (torch + pkl_mal[:4] + pkl_ben[:4])]


def scan_once(backend: str, image: str, src: str, timeout: int) -> tuple[str, str]:
    out, err = run_scan(backend, image, src, timeout)
    if err or out is None:
        return src, f"ERROR:{(err or 'no output')[:60]}"
    return src, str(out.get("verdict"))


def run_batch(jobs, backend: str, image: str, timeout: int,
              workers: int) -> list[tuple[str, str]]:
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(scan_once, backend, image, s, timeout) for s in jobs]
        for f in as_completed(futs):
            results.append(f.result())
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="podman")
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--scanner", action="append", default=None,
                    help="scanner image base name (repeatable; default "
                         "regenbench/picklescan)")
    ap.add_argument("--concurrency", action="append", type=int, default=None,
                    help="worker counts to stress (repeatable; default 2 4 8)")
    ap.add_argument("--trials", type=int, default=18,
                    help="scan invocations per concurrency config")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    scanners = args.scanner or ["regenbench/picklescan"]
    concurrencies = args.concurrency or [2, 4, 8]
    corpus = build_corpus()
    total_concurrent_trials = 0
    failed = False

    print(f"corpus: {len(corpus)} artifacts x {len(scanners)} scanner(s)")

    for scanner in scanners:
        image = f"{scanner}{args.tag}"
        ref_jobs = corpus * 2  # sequential reference: 2 passes over corpus
        t0 = time.time()
        ref = dict(run_batch(ref_jobs, args.backend, image, args.timeout, workers=1))
        print(f"\n[{scanner}] sequential reference established "
              f"({len(ref_jobs)} scans, {time.time()-t0:.0f}s)")

        # Reference verdicts must themselves be internally consistent.
        ref_verdicts = {}
        for src, verdict in run_batch(ref_jobs, args.backend, image, args.timeout, 1):
            prev = ref_verdicts.setdefault(src, verdict)
            if prev != verdict:
                print(f"FAIL {src}: sequential reference itself unstable "
                      f"({prev} vs {verdict}) -- environment nondeterminism")
                failed = True

        for c in concurrencies:
            jobs = []
            while len(jobs) < args.trials:
                jobs.extend(corpus)
            jobs = jobs[:args.trials]
            t0 = time.time()
            batch = run_batch(jobs, args.backend, image, args.timeout, workers=c)
            total_concurrent_trials += len(batch)

            dist = Counter()
            diverged = []
            for src, verdict in batch:
                dist[(src, verdict)] += 1
                if ref_verdicts.get(src) != verdict:
                    diverged.append((src, verdict))
            status = "OK" if not diverged else "FAIL"
            print(f"[{scanner}] concurrency={c:<2} trials={len(batch)} "
                  f"({time.time()-t0:.0f}s) distinct-verdict-slots={len(dist)} {status}")
            for src, verdict in diverged[:10]:
                print(f"    DIVERGENT {Path(src).name}: got {verdict}, "
                      f"expected {ref_verdicts.get(src)}")
            if diverged:
                failed = True

    print(f"\nTotal concurrent trials: {total_concurrent_trials}")
    if total_concurrent_trials < 50:
        print("NOTE: fewer than 50 concurrent trials; plan requires >= 50 "
              "(raise --trials).")
    if failed:
        print("RESULT: FAIL - verdict divergence detected; a race remains.")
        return 1
    print("RESULT: PASS - concurrent distributions identical to sequential "
          "reference.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
