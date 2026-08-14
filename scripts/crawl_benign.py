#!/usr/bin/env python3
"""T2.4 & T2.5 — Crawl benign Hugging Face corpus, deduplicate, and build versioned seed manifest.

Downloads pytorch_model.bin files from Hugging Face for three task clusters:
- text-generation
- text-classification
- feature-extraction

Filters by likes, enforces size safety, handles rate limits, deduplicates by SHA256,
balances clusters, and records provenance tracking inside data/crawled/seed_manifest.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any

from huggingface_hub import HfApi, hf_hub_download
from huggingface_hub.utils import HfHubHTTPError


def call_api_with_retry(func, *args, **kwargs):
    """Robust API call wrapper that automatically handles 429 Rate Limits and retries."""
    retries = 5
    for attempt in range(retries):
        try:
            return func(*args, **kwargs)
        except HfHubHTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 60))
                print(f"\n[rate-limit] Hit 429 Too Many Requests. Sleeping for {retry_after + 5}s (attempt {attempt + 1}/{retries})...")
                time.sleep(retry_after + 5)
            else:
                raise
        except Exception as e:
            if attempt == retries - 1:
                raise
            print(f"[warning] API call failed: {e}. Retrying in 5 seconds...")
            time.sleep(5)
    raise RuntimeError("API retries exhausted")


def get_model_file_info(api: HfApi, repo_id: str, filename: str) -> dict[str, Any] | None:
    """Query repository file metadata safely with retries and rate limit pacing.

    Uses repo_info(files_metadata=True) which returns sizes in a single call,
    plus securityStatus=True so T2.4's "exclude known-unsafe models" filter can
    be enforced without an extra API round-trip.
    """
    # Small delay before call to reduce API pressure
    time.sleep(0.5)
    try:
        info = call_api_with_retry(api.repo_info, repo_id, files_metadata=True, securityStatus=True)
        for sib in (info.siblings or []):
            if getattr(sib, "rfilename", None) == filename:
                return {
                    "path": sib.rfilename,
                    "size": getattr(sib, "size", None),
                    "lfs": getattr(sib, "lfs", None),
                    "security": getattr(info, "security", None),
                }
    except Exception as e:
        print(f"  [info] Could not get file tree for {repo_id}: {e}")
    return None


def is_security_unsafe(security) -> bool:
    """True when HuggingFace flags any pickle/torch artifact in the repo.

    T2.4 requires excluding models whose checkpoints are known-unsafe, so the
    crawled corpus is a trustworthy *benign* baseline. `security` is the
    SecurityInfo object returned by repo_info(securityStatus=True): when HF
    flagged a pickle/torch/unsafe artifact, `security.repository` is non-empty
    and `security.downloadable` is False.
    """
    if security is None:
        return False
    if getattr(security, "downloadable", True) is False:
        return True
    repository = getattr(security, "repository", None) or {}
    if not isinstance(repository, dict):
        return False
    for category in ("pickle", "torch", "unsafe"):
        flagged = repository.get(category)
        if flagged:
            return True
    return False


def has_pytorch_model_bin(model) -> bool:
    """True if the model's sibling list advertises a pytorch_model.bin."""
    for sib in (getattr(model, "siblings", None) or []):
        if getattr(sib, "rfilename", None) == "pytorch_model.bin":
            return True
    return False


def crawl_cluster(
    api: HfApi,
    cluster: str,
    limit: int,
    max_size: int,
    out_dir: str,
    seen_hashes: set[str],
    scan_cap: int = 10000,
) -> list[dict[str, Any]]:
    """Crawl benign models for a specific task cluster, deduplicating by SHA256 hash."""
    print(f"\n[crawl] Starting crawl for cluster: {cluster} (target limit: {limit}, max_size: {max_size} bytes, scan_cap: {scan_cap})")
    
    crawled = []
    # Iterate lazily; list_models paginates internally. We stop once we have
    # collected `limit` non-duplicate downloads or scanned `scan_cap` models.
    try:
        models = call_api_with_retry(
            api.list_models,
            filter=cluster,
            sort="likes",
            limit=scan_cap,
            full=True,
        )
    except Exception as e:
        print(f"[error] Failed to list models for {cluster}: {e}")
        return []

    for m in models:
        if len(crawled) >= limit:
            break

        # Filter out private, gated, or disabled models
        if getattr(m, "private", False) or getattr(m, "gated", False) or getattr(m, "disabled", None):
            continue

        # Skip models that do not advertise a pytorch_model.bin in their file tree.
        # list_models(full=True) returns siblings, so this avoids a per-model API call.
        if not has_pytorch_model_bin(m):
            continue

        # Look up file info for pytorch_model.bin
        finfo = get_model_file_info(api, m.id, "pytorch_model.bin")
        if not finfo:
            continue

        # T2.4: exclude models HuggingFace flags as security-unsafe (known
        # pickle/torch malware), so the corpus stays a genuine benign baseline.
        if is_security_unsafe(finfo.get("security")):
            print(f"  [skip] {m.id} flagged security-unsafe by HuggingFace; excluding")
            continue

        # Memory-safety size check
        size = finfo["size"]
        if size is None and finfo["lfs"]:
            size = finfo["lfs"].size
            
        if size is None:
            continue
            
        if size > max_size:
            continue

        # Clean/sanitize repo name for local directory use
        safe_repo_name = m.id.replace("/", "_")
        dest_dir = os.path.join(out_dir, cluster, safe_repo_name)
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, "pytorch_model.bin")

        print(f"[crawl] Downloading {m.id} ({size / (1024*1024):.2f} MB)...")
        try:
            # Paced download
            time.sleep(0.5)
            downloaded_path = call_api_with_retry(
                hf_hub_download,
                repo_id=m.id,
                filename="pytorch_model.bin",
                local_dir=dest_dir,
                local_dir_use_symlinks=False,
            )
        except Exception as e:
            print(f"  [warning] Failed to download {m.id}: {e}")
            continue

        # Calculate SHA256 of the downloaded file
        sha = hashlib.sha256()
        try:
            with open(downloaded_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    sha.update(chunk)
        except OSError as e:
            print(f"  [warning] Failed to hash {downloaded_path}: {e}")
            continue

        sha256_val = sha.hexdigest()
        
        # Deduplication check
        if sha256_val in seen_hashes:
            print(f"  [skip] {m.id} is a duplicate (SHA256 already exists in seed corpus)")
            # Clean up duplicate file to save disk space
            try:
                os.remove(downloaded_path)
            except OSError:
                pass
            continue

        seen_hashes.add(sha256_val)
        metadata = {
            "repo_id": m.id,
            "likes": getattr(m, "likes", 0),
            "downloads": getattr(m, "downloads", 0),
            "size": size,
            "sha256": sha256_val,
            "local_path": os.path.relpath(downloaded_path, start=os.path.dirname(out_dir)),
            "cluster": cluster,
            "provenance": {
                "source": "Hugging Face Hub",
                "url": f"https://huggingface.co/{m.id}/blob/main/pytorch_model.bin",
                "crawled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        }
        crawled.append(metadata)
        print(f"  [success] Saved to {metadata['local_path']} | SHA256: {metadata['sha256'][:16]}...")

    return crawled


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clusters", default="text-generation,text-classification,feature-extraction",
                    help="comma-separated list of task clusters to crawl")
    ap.add_argument("--limit-per-cluster", type=int, default=1000,
                    help="maximum number of models to crawl per cluster")
    ap.add_argument("--max-size", type=int, default=15 * 1024 * 1024,
                    help="maximum size of pytorch_model.bin in bytes")
    ap.add_argument("--out-dir", default="data/crawled",
                    help="output directory to save files and manifest")
    ap.add_argument("--scan-cap", type=int, default=10000,
                    help="maximum number of models to scan per cluster before giving up")
    args = ap.parse_args()

    api = HfApi()
    clusters = [c.strip() for c in args.clusters.split(",") if c.strip()]
    
    seen_hashes = set()
    all_metadata = []
    
    for cluster in clusters:
        cluster_metadata = crawl_cluster(
            api,
            cluster=cluster,
            limit=args.limit_per_cluster,
            max_size=args.max_size,
            out_dir=args.out_dir,
            seen_hashes=seen_hashes,
            scan_cap=args.scan_cap,
        )
        all_metadata.extend(cluster_metadata)

    # Balance counts check
    summary_counts = {}
    for c in clusters:
        summary_counts[c] = sum(1 for m in all_metadata if m["cluster"] == c)

    # Save final versioned seed manifest (T2.5)
    manifest = {
        "schema_version": "1.0",
        "dataset_name": "ReGenBench Seed Corpus",
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

    print(f"\n[crawl] Crawl complete. Downloaded {len(all_metadata)} total models.")
    for c, count in summary_counts.items():
        print(f"  - {c}: {count} models")
    print(f"[crawl] Seed manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
