#!/usr/bin/env python3
"""Register the 125 on-disk GGUF files in data/crawled/seed_manifest.json.

The GGUF files are downloaded by scripts/download_gguf_models.py, which does NOT
write into the seed manifest. This script reconciles the manifest against the
GGUF_MODELS list (accurate repo_id/filename/cluster) and the on-disk files,
adding a versioned provenance entry for every GGUF that is present on disk but
missing from the manifest. It then rebuilds the per-cluster summary.

Usage:
    python3 scripts/register_gguf_manifest.py [--manifest data/crawled/seed_manifest.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

from download_gguf_models import GGUF_MODELS


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="data/crawled/seed_manifest.json")
    args = ap.parse_args()

    manifest_path = args.manifest
    with open(manifest_path) as f:
        manifest = json.load(f)

    models = manifest.get("models", [])
    # Map on-disk local_path -> existing manifest entry.
    by_local = {m.get("local_path"): m for m in models if m.get("local_path")}

    # Build lookup: (cluster, repo_id, filename) -> local_path on disk.
    # The manifest lives at data/crawled/seed_manifest.json and the GGUF files
    # at data/crawled/<cluster>/...; local_path is relative to the repo root so it
    # is written as "crawled/<cluster>/...".
    out_dir = os.path.dirname(manifest_path)
    online_root = os.path.dirname(out_dir)
    disk_entries: list[dict] = []
    for repo, fn, cluster, disp in GGUF_MODELS:
        dest = os.path.join(out_dir, cluster, repo.replace("/", "_"))
        target = os.path.join(dest, fn)
        if not (os.path.exists(target) and os.path.getsize(target) > 0):
            print(f"[missing] {repo}/{fn} not on disk; skipping")
            continue
        local = os.path.relpath(target, online_root)
        disk_entries.append({
            "repo_id": repo,
            "filename": fn,
            "cluster": cluster,
            "local_path": local,
        })

    added = 0
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for e in disk_entries:
        local = e["local_path"]
        if local in by_local:
            continue
        target = os.path.join(out_dir, e["cluster"], e["repo_id"].replace("/", "_"), e["filename"])
        sha = hashlib.sha256()
        with open(target, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                sha.update(chunk)
        entry = {
            "cluster": e["cluster"],
            "downloads": 0,
            "format": "gguf",
            "gguf_filename": e["filename"],
            "likes": 0,
            "local_path": local,
            "provenance": {
                "crawled_at": now,
                "source": "Hugging Face Hub",
                "url": f"https://huggingface.co/{e['repo_id']}/blob/main/{e['filename']}",
            },
            "repo_id": e["repo_id"],
            "sha256": sha.hexdigest(),
            "size": os.path.getsize(target),
        }
        models.append(entry)
        by_local[local] = entry
        added += 1
        print(f"[+]{local}  {entry['size']:,} bytes  sha256={entry['sha256'][:12]}")

    # Rebuild summary from the full model list.
    clusters = sorted({m.get("cluster") for m in models})
    summary_counts: dict[str, dict] = {}
    format_counts = {"pt": 0, "gguf": 0}
    for c in clusters:
        pt_count = sum(1 for m in models if m.get("cluster") == c and m.get("format", "pt") == "pt")
        gguf_count = sum(1 for m in models if m.get("cluster") == c and m.get("format") == "gguf")
        summary_counts[c] = {"pt": pt_count, "gguf": gguf_count, "total": pt_count + gguf_count}
        format_counts["pt"] += pt_count
        format_counts["gguf"] += gguf_count

    manifest["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["summary"] = {
        "total_models": len(models),
        "formats": format_counts,
        "clusters": summary_counts,
    }
    manifest["models"] = models

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"\nRegistered {added} new GGUF file(s).")
    print(f"Total models now: {len(models)}")
    print("Summary:")
    for c in clusters:
        s = summary_counts[c]
        print(f"  {c:<24} pt={s['pt']:<3} gguf={s['gguf']:<3} total={s['total']}")
    print(f"  {'TOTAL':<24} pt={format_counts['pt']:<3} gguf={format_counts['gguf']:<3} total={len(models)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())