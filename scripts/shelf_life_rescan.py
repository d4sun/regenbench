#!/usr/bin/env python3
"""H3 Shelf-Life Re-Scanning CLI.

Re-scans confirmed bypasses against updated scanner versions to measure
evasion shelf-life decay (H3).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import subprocess
from datetime import datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.shelf_life import ShelfLifeTracker, RescanResult
from pipeline.runner import Runner, Config


def rescan_bypasses(
    shelf_tracker: ShelfLifeTracker,
    scanners: list[str],
    image_overrides: dict[str, str],
    backend: str = "podman",
) -> list[RescanResult]:
    """Re-scan all tracked bypasses against explicitly supplied images."""
    bypasses = shelf_tracker.get_bypasses_for_rescan()
    print(f"[shelf-life] Re-scanning {len(bypasses)} bypasses...")
    all_results: list[RescanResult] = []
    for record in bypasses:
        print(f"  Re-scanning {record.candidate_id[:12]}...")
        results = shelf_tracker.rescan_bypass(
            record, scanners, image_overrides, backend=backend)
        all_results.extend(results)
    return all_results


def main():
    ap = argparse.ArgumentParser(prog="shelf_life_rescan", description=__doc__)
    ap.add_argument("--scanners", default="picklescan,modelscan,fickling",
                    help="comma-separated scanners to re-scan with")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--image", action="append", default=[],
                    help="scanner=image:tag (required for every selected scanner)")
    args = ap.parse_args()

    scanners = [s.strip() for s in args.scanners.split(",")]
    overrides = {}
    for item in args.image:
        scanner, sep, image = item.partition("=")
        if not sep or scanner not in scanners or not image:
            ap.error(f"--image must be scanner=image:tag for selected scanners: {item!r}")
        overrides[scanner] = image
    missing = [s for s in scanners if s not in overrides]
    if missing:
        ap.error("explicit --image is required for: " + ", ".join(missing))

    shelf = ShelfLifeTracker(db_path=args.db)
    rescan_bypasses(shelf, scanners, overrides, args.backend)
    
    # Print decay curve
    decay = shelf.compute_decay_curve()
    print(json.dumps(decay, indent=2))


if __name__ == "__main__":
    import argparse
    import json
    main()