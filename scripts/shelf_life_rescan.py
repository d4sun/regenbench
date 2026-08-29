#!/usr/bin/env python3
"""H3 Shelf-Life Re-Scanning CLI.

Re-scans confirmed bypasses against updated scanner versions to measure
evasion shelf-life decay (H3).

Usage:
    # Pull latest images and rescan all bypasses
    python scripts/shelf_life_rescan.py --scanners picklescan,modelscan,fickling --backend docker

    # Rescan with specific image versions
    python scripts/shelf_life_rescan.py --scanners picklescan,modelscan --image picklescan=regenbench/picklescan:v2.1.0 --image modelscan=regenbench/modelscan:v3.0.0

    # Just compute decay curve from existing rescan data
    python scripts/shelf_life_rescan.py --decay-only
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
from pipeline.scanners import get_scanner_version, pull_scanner_image


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
    ap.add_argument("--backend", choices=["podman", "docker"], default="docker")
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--image", action="append", default=[],
                    help="scanner=image:tag override (if omitted, pulls :latest)")
    ap.add_argument("--pull", action="store_true",
                    help="pull latest images before re-scanning")
    ap.add_argument("--decay-only", action="store_true",
                    help="only compute decay curve from existing rescans, don't re-scan")
    args = ap.parse_args()

    scanners = [s.strip() for s in args.scanners.split(",")]
    
    # Resolve image overrides
    from pipeline.scanners import SCANNERS
    overrides = {}
    for s in scanners:
        if s in SCANNERS:
            overrides[s] = SCANNERS[s]["image"]
    
    for item in args.image:
        scanner, sep, image = item.partition("=")
        if not sep or scanner not in scanners or not image:
            ap.error(f"--image must be scanner=image:tag for selected scanners: {item!r}")
        overrides[scanner] = image

    if args.pull and not args.decay_only:
        print(f"[shelf-life] Pulling latest images for {len(scanners)} scanner(s)...")
        versions = {}
        for scanner in scanners:
            image = overrides.get(scanner)
            if image:
                success, version = pull_scanner_image(args.backend, image)
                versions[scanner] = version
            else:
                versions[scanner] = "unknown"
        print(f"  Pulled versions: {versions}")

    if args.decay_only:
        shelf = ShelfLifeTracker(db_path=args.db)
        decay = shelf.compute_decay_curve()
        print(json.dumps(decay, indent=2))
        return

    # Build full image:tag strings for the runner
    from pipeline.scanners import full_image
    image_overrides = {}
    for scanner, image in overrides.items():
        if ":" not in image:
            image = full_image(image, ":latest")
        image_overrides[scanner] = image

    shelf = ShelfLifeTracker(db_path=args.db)
    rescan_bypasses(shelf, scanners, image_overrides, args.backend)
    
    # Print decay curve
    decay = shelf.compute_decay_curve()
    print(json.dumps(decay, indent=2))


if __name__ == "__main__":
    main()