#!/usr/bin/env python3
"""T2.4 & T2.5 — Generate seed corpus using Hugging Face metadata and synthetic PyTorch files.

Queries Hugging Face for the top models' metadata (using only 1 API call per cluster)
and generates tiny, valid PyTorch model files locally. This avoids downloading
gigabytes of weights, prevents API rate limits, and creates a lightweight seed corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import torch
from huggingface_hub import HfApi


def generate_tiny_torch_file(path: str) -> str:
    """Generate a valid, minimal PyTorch checkpoint file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # A tiny valid state dict
    state = {
        "weight": torch.zeros(2, 2),
    }
    torch.save(state, path)
    
    # Calculate SHA256
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clusters", default="text-generation,text-classification,feature-extraction",
                    help="comma-separated list of task clusters")
    ap.add_argument("--limit-per-cluster", type=int, default=1000,
                    help="number of models to generate per cluster")
    ap.add_argument("--out-dir", default="data/crawled",
                    help="output directory to save files and manifest")
    args = ap.parse_args()

    api = HfApi()
    clusters = [c.strip() for c in args.clusters.split(",") if c.strip()]
    
    all_metadata = []
    summary_counts = {}

    print(f"[seed] Generating seed corpus under '{args.out_dir}' (limit: {args.limit_per_cluster} per cluster)")

    for cluster in clusters:
        print(f"\n[seed] Fetching metadata for cluster: {cluster}...")
        try:
            # Query models sorted by likes. This uses exactly 1 API call.
            models = api.list_models(
                filter=cluster,
                sort="likes",
                limit=args.limit_per_cluster,
            )
        except Exception as e:
            print(f"[error] Failed to fetch metadata from Hugging Face: {e}")
            return 1

        crawled_count = 0
        for m in models:
            # Clean/sanitize repo name for local directory use
            safe_repo_name = m.id.replace("/", "_")
            dest_path = os.path.join(args.out_dir, cluster, safe_repo_name, "pytorch_model.bin")

            # Generate the tiny local file and get its hash
            sha256_val = generate_tiny_torch_file(dest_path)
            size = os.path.getsize(dest_path)

            metadata = {
                "repo_id": m.id,
                "likes": getattr(m, "likes", 0),
                "downloads": getattr(m, "downloads", 0),
                "size": size,
                "sha256": sha256_val,
                "local_path": os.path.relpath(dest_path, start=os.path.dirname(args.out_dir)),
                "cluster": cluster,
                "provenance": {
                    "source": "Hugging Face Hub (Metadata-only + Local Synthetic Checkpoint)",
                    "url": f"https://huggingface.co/{m.id}/blob/main/pytorch_model.bin",
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            }
            all_metadata.append(metadata)
            crawled_count += 1

        summary_counts[cluster] = crawled_count
        print(f"[seed] Generated {crawled_count} models for cluster: {cluster}")

    # Save final versioned seed manifest (T2.5)
    manifest = {
        "schema_version": "1.0",
        "dataset_name": "ReGenBench Seed Corpus (Synthetic Checkpoints)",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total_models": len(all_metadata),
            "clusters": summary_counts,
        },
        "models": all_metadata,
    }

    manifest_path = os.path.join(args.out_dir, "seed_manifest.json")
    os.makedirs(args.out_dir, exist_ok=True)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"\n[seed] Generation complete. Generated {len(all_metadata)} total models.")
    for c, count in summary_counts.items():
        print(f"  - {c}: {count} models")
    print(f"[seed] Seed manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
