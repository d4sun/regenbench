#!/usr/bin/env python3
"""Train syscall anomaly detector from oracle calibration traces."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.oracle_ensemble import SyscallAnomalyDetector


def main() -> int:
    # Use traces from the latest oracle calibration
    traces_path = Path("real_benign_corpus/oracle-calibrated/current/traces.json")
    if not traces_path.exists():
        print(f"[train-anomaly] Error: traces not found at {traces_path}")
        return 1

    with open(traces_path) as f:
        traces = json.load(f)

    print(f"[train-anomaly] Loaded {len(traces)} benign traces")

    # Filter valid traces
    benign_traces = [t for t in traces if t.get("counts")]
    print(f"[train-anomaly] {len(benign_traces)} traces with syscall counts")

    # Train anomaly detector
    detector = SyscallAnomalyDetector(contamination=0.01, random_state=1337)
    report = detector.train(benign_traces)

    print("[train-anomaly] Training complete:")
    print(f"  n_samples: {report['n_samples']}")
    print(f"  n_features: {report['n_features']}")
    print(f"  train_scores: {json.dumps(report['train_scores'], indent=2)}")

    # Save model
    out_dir = "real_benign_corpus/oracle-calibrated/current/anomaly"
    detector.save(out_dir)
    print(f"[train-anomaly] Model saved to {out_dir}")

    # Quick validation: check that benign traces score above threshold
    scores = []
    for t in benign_traces[:10]:
        score = detector.predict(t["counts"])
        scores.append(score)
    print(f"[train-anomaly] Sample benign scores: {[round(s, 4) for s in scores]}")
    print(f"  mean: {sum(scores)/len(scores):.4f}, min: {min(scores):.4f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())