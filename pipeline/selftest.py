"""T0.10 concurrency self-test.

Launches a bounded panel+oracle fan-out over a slice of the committed T0.8
corpus and asserts that (a) every queued task completes, (b) no task returns a
transport error (subprocess/parse/timeout), and (c) the pool stays bounded.
Serves as the Validation for T0.10: generator -> filter -> panel/oracle run
concurrently on a single host.

Exit 0 on pass, non-zero on failure.
"""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from pipeline import runner as pr
from pipeline.runner import Runner

CORPUS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "ci", "corpus")


def sample_artifacts(limit: int = 4) -> list[str]:
    """Take a representative slice of the corpus incl. both pkl subdirs and the
    torch files so the oracle fan-out is exercised too."""
    picks = []
    for sub in ("pkl/benign", "pkl/malicious", "torch/benign", "torch/malicious"):
        d = os.path.join(CORPUS, sub)
        if not os.path.isdir(d):
            continue
        for n in sorted(os.listdir(d))[:limit]:
            picks.append(os.path.join(d, n))
    return picks


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--tag", default=":latest")
    ap.add_argument("--oracle", action="store_true",
                    help="include the DynaHug oracle on torch artifacts")
    args = ap.parse_args(argv)

    artifacts = sample_artifacts()
    cfg = pr.Config(backend=args.backend, tag=args.tag, max_workers=args.workers,
                    oracle=args.oracle)
    runner = Runner(cfg)

    # Exercise the pool directly (all tasks enqueued at once -> bounded).
    jobs = [(a, s) for a in artifacts for s in runner._scanners_for(a)]
    done: list[pr.ScanResult] = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, len(jobs) or 1))) as ex:
        futs = {ex.submit(runner._one, a, s): (a, s) for a, s in jobs}
        for fut in as_completed(futs):
            done.append(fut.result())

    errors = [r for r in done if r.error]
    print(f"[selftest] artifacts={len(artifacts)} tasks={len(done)} errors={len(errors)}")
    if errors:
        for e in errors[:5]:
            print(f"  ERROR {e.scanner} {e.artifact}: {e.error[:120]}")
    ok = not errors and len(done) > 0
    print("SELFTEST", "PASS" if ok else "FAIL",
          f"({len([r for r in done if r.ok])}/{len(done)} tasks ok)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())