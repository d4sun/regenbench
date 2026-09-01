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
import threading
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

    Uses model_info(files_metadata=True, securityStatus=True) which returns
    per-file sizes and the repository security status in a single call, so
    T2.4's "exclude known-unsafe models" filter can be enforced without an
    extra API round-trip.
    """
    # Small delay before call to reduce API pressure
    time.sleep(0.5)
    try:
        info = call_api_with_retry(api.model_info, repo_id, files_metadata=True,
                                   securityStatus=True)
        for sib in (info.siblings or []):
            if getattr(sib, "rfilename", None) == filename:
                return {
                    "path": sib.rfilename,
                    "size": getattr(sib, "size", None),
                    "lfs": getattr(sib, "lfs", None),
                    "security": getattr(info, "security_repo_status", None),
                }
    except Exception as e:
        print(f"  [info] Could not get file tree for {repo_id}: {e}")
    return None


def is_security_unsafe(security) -> bool:
    """True when HuggingFace flags a *dangerous* artifact in the repo.

    T2.4 requires excluding models whose checkpoints are known-unsafe, so the
    crawled corpus stays a trustworthy *benign* baseline. `security` is the
    ``security_repo_status`` dict returned by model_info(securityStatus=True):
    ``{"scansDone": bool, "filesWithIssues": [{"path": str, "level": str}]}``.

    Only ``danger``/``blocked`` levels are excluded: HF stamps every pickle
    file (pytorch_model.bin included) with ``caution`` by construction, so
    treating caution as unsafe would reject the entire pickle-based corpus we
    are deliberately crawling. Unknown/unscanned repos pass through
    (fail-open — we cannot prove them unsafe).
    """
    if security is None:
        return False
    issues = security.get("filesWithIssues") if isinstance(security, dict) else None
    if not issues:
        return False
    for issue in issues:
        if isinstance(issue, dict) and issue.get("level") in ("danger", "blocked"):
            return True
        if isinstance(issue, str):  # older API shape: bare filename list
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
    workers: int = 6,
) -> list[dict[str, Any]]:
    """Crawl benign models for a specific task cluster, deduplicating by SHA256 hash.

    The scan order (likes-sorted) stays sequential; the per-candidate work
    (file metadata, security filter, download, hash, dedup) is fanned out to a
    thread pool so network round-trips and downloads overlap instead of
    serializing. `seen_hashes` is shared across threads (guarded by a lock)
    and across clusters within one process.
    """
    print(f"\n[crawl] Starting crawl for cluster: {cluster} "
          f"(target limit: {limit}, max_size: {max_size} bytes, "
          f"scan_cap: {scan_cap}, workers: {workers})")

    crawled: list[dict[str, Any]] = []
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

    lock = threading.Lock()

    def _process(m) -> dict[str, Any] | None:
        # Filter out private, gated, or disabled models
        if getattr(m, "private", False) or getattr(m, "gated", False) or getattr(m, "disabled", None):
            return None

        # Skip models that do not advertise a pytorch_model.bin in their file tree.
        if not has_pytorch_model_bin(m):
            return None

        # Look up file info for pytorch_model.bin (paced, thread-safe)
        finfo = get_model_file_info(api, m.id, "pytorch_model.bin")
        if not finfo:
            return None

        # T2.4: exclude models HuggingFace flags as security-unsafe (known
        # pickle/torch malware), so the corpus stays a genuine benign baseline.
        if is_security_unsafe(finfo.get("security")):
            print(f"  [skip] {m.id} flagged security-unsafe by HuggingFace; excluding")
            return None

        # Memory-safety size check
        size = finfo["size"]
        if size is None and finfo["lfs"]:
            size = finfo["lfs"].size
        if size is None or size > max_size:
            return None

        # Clean/sanitize repo name for local directory use
        safe_repo_name = m.id.replace("/", "_")
        dest_dir = os.path.join(out_dir, cluster, safe_repo_name)
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, "pytorch_model.bin")
        likes = getattr(m, "likes", 0)
        downloads = getattr(m, "downloads", 0)

        if os.path.exists(dest_path):
            sha = hashlib.sha256()
            with open(dest_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    sha.update(chunk)
            sha256_val = sha.hexdigest()
            with lock:
                if sha256_val in seen_hashes:
                    return None
                # Backfill: the file predates this manifest (resumed crawl) but
                # was never recorded. Record it so seed_manifest.json reflects
                # every downloaded model, not just this run's fresh downloads.
                seen_hashes.add(sha256_val)
                crawled.append({
                    "repo_id": m.id,
                    "likes": likes,
                    "downloads": downloads,
                    "size": os.path.getsize(dest_path),
                    "sha256": sha256_val,
                    "local_path": os.path.relpath(dest_path, start=os.path.dirname(out_dir)),
                    "cluster": cluster,
                    "provenance": {
                        "source": "Hugging Face Hub",
                        "url": f"https://huggingface.co/{m.id}/blob/main/pytorch_model.bin",
                        "crawled_at": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(dest_path))),
                    },
                })
            print(f"  [backfill] {m.id} recorded from existing download "
                  f"({os.path.getsize(dest_path)} bytes)")
            return None

        print(f"[crawl] Downloading {m.id} ({size / (1024*1024):.2f} MB)...")
        try:
            # Paced download
            time.sleep(0.5)
            downloaded_path = call_api_with_retry(
                hf_hub_download,
                repo_id=m.id,
                filename="pytorch_model.bin",
                local_dir=dest_dir,
            )
        except Exception as e:
            print(f"  [warning] Failed to download {m.id}: {e}")
            return None

        # Calculate SHA256 of the downloaded file
        sha = hashlib.sha256()
        try:
            with open(downloaded_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    sha.update(chunk)
        except OSError as e:
            print(f"  [warning] Failed to hash {downloaded_path}: {e}")
            return None

        sha256_val = sha.hexdigest()

        # Deduplication check
        with lock:
            if sha256_val in seen_hashes:
                duplicate = True
            else:
                seen_hashes.add(sha256_val)
                duplicate = False
        if duplicate:
            print(f"  [skip] {m.id} is a duplicate (SHA256 already exists in seed corpus)")
            # Clean up duplicate file to save disk space
            try:
                os.remove(downloaded_path)
            except OSError:
                pass
            return None

        metadata = {
            "repo_id": m.id,
            "likes": likes,
            "downloads": downloads,
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
        with lock:
            crawled.append(metadata)
        print(f"  [success] Saved to {metadata['local_path']} | SHA256: {metadata['sha256'][:16]}...")
        return metadata

    import concurrent.futures
    import itertools

    # Process the scan in small batches so we stop as soon as `limit` unique
    # models are collected instead of queueing the whole scan (scan_cap) into
    # the pool — which would download far more than `limit`. Batch size bounds
    # the worst-case overshoot; skipped candidates (no pytorch_model.bin,
    # too large, flagged) drain in milliseconds, so only genuine downloads
    # occupy the pool.
    batch_size = max(2 * workers, 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        it = iter(models)
        while True:
            batch = list(itertools.islice(it, batch_size))
            if not batch:
                break
            futures: dict[concurrent.futures.Future, str] = {
                ex.submit(_process, m): m.id for m in batch
            }
            for fut in concurrent.futures.as_completed(futures):
                fut.result()  # exceptions are swallowed inside _process
            with lock:
                if len(crawled) >= limit:
                    break

    # Preserve the highest-likes-first preference (scan order), cap at limit.
    crawled.sort(key=lambda r: r["likes"], reverse=True)
    crawled = crawled[:limit]
    print(f"[crawl] Cluster {cluster} complete: {len(crawled)} models (capped at {limit})")
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
    ap.add_argument("--workers", type=int, default=6,
                    help="parallel worker threads for per-model processing "
                         "(metadata lookup + download + hash); scans stay sequential")
    args = ap.parse_args()

    api = HfApi()
    clusters = [c.strip() for c in args.clusters.split(",") if c.strip()]

    seen_hashes = set()
    all_metadata = []
    manifest_path = os.path.join(args.out_dir, "seed_manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path) as f:
                existing = json.load(f)
            for m in existing.get("models", []):
                if m.get("sha256"):
                    seen_hashes.add(m["sha256"])
            all_metadata = existing.get("models", [])
            print(f"[crawl] Resuming: {len(all_metadata)} models already in manifest, "
                  f"{len(seen_hashes)} known hashes")
        except Exception as e:
            print(f"[warning] Could not read existing manifest {manifest_path}: {e}")
    
    for cluster in clusters:
        cluster_metadata = crawl_cluster(
            api,
            cluster=cluster,
            limit=args.limit_per_cluster,
            max_size=args.max_size,
            out_dir=args.out_dir,
            seen_hashes=seen_hashes,
            scan_cap=args.scan_cap,
            workers=args.workers,
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

    # Prune parallel-overshoot / dedup-loser checkpoints so the on-disk corpus
    # matches the manifest exactly (the parallel crawl may have downloaded more
    # than `limit` per cluster before the truncation took effect).
    kept_local = {m.get("local_path") for m in all_metadata if m.get("local_path")}
    pruned = 0
    for dirpath, _dirs, names in os.walk(args.out_dir):
        for n in names:
            if n != "pytorch_model.bin":
                continue
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, start=os.path.dirname(args.out_dir))
            if rel in kept_local:
                continue
            try:
                os.remove(p)
                pruned += 1
            except OSError:
                pass
    if pruned:
        print(f"[crawl] Pruned {pruned} overshoot/dedup checkpoint(s) not in the manifest.")

    print(f"\n[crawl] Crawl complete. Downloaded {len(all_metadata)} total models.")
    for c, count in summary_counts.items():
        print(f"  - {c}: {count} models")
    print(f"[crawl] Seed manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
