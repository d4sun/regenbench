#!/usr/bin/env python3
"""Crawl real malicious models identified by the MalHug study (ASE 2024).

Fetches the model metadata from security-pride/MalHug/malhug_result_info.csv
and downloads the real malicious model artifacts (~39 repositories) from Hugging Face
into data/malhug (or specified --out-dir).

Writes a versioned manifest.json with provenance and behavior metadata.

Usage:
    python3 scripts/crawl_malhug.py [--out data/malhug] [--max-size-mb 100]
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import urllib.request

CSV_URL = "https://raw.githubusercontent.com/security-pride/MalHug/main/malhug_result_info.csv"


def mine_opcode_distributions(malhug_dir: str) -> dict:
    """Extract opcode frequency distributions from real malicious models.

    Returns a dict mapping opcode names to normalized frequencies, suitable
    for seeding PickleMutator.sample_strings / sample_ints with real-world
    malicious patterns (Phase 3c).
    """
    import zipfile
    from collections import Counter
    from pipeline.opcodes import parse_pickle, OPCODES_BY_BYTE

    opcode_counter = Counter()
    total_opcodes = 0

    for fname in os.listdir(malhug_dir):
        fpath = os.path.join(malhug_dir, fname)
        if not os.path.isfile(fpath) or not zipfile.is_zipfile(fpath):
            continue
        try:
            with zipfile.ZipFile(fpath) as z:
                pkl_names = [n for n in z.namelist() if n.endswith(".pkl") or n.endswith("data.pkl")]
                for pkl_name in pkl_names:
                    pkl_bytes = z.read(pkl_name)
                    try:
                        parsed = parse_pickle(pkl_bytes)
                        for op, _ in parsed:
                            opcode_counter[op.name] += 1
                            total_opcodes += 1
                    except Exception:
                        continue
        except Exception:
            continue

    if total_opcodes == 0:
        return {}

    # Normalize to frequencies
    return {op: count / total_opcodes for op, count in opcode_counter.items()}


def seed_mutator_from_malhug(mutator, malhug_dir: str) -> None:
    """Seed a PickleMutator's sample strings/ints from MalHug opcode distributions."""
    dist = mine_opcode_distributions(malhug_dir)
    if not dist:
        return

    # Top opcodes become more likely mutation targets
    # This is a placeholder for future enhancement
    pass


def fetch_csv() -> list[dict]:
    req = urllib.request.Request(CSV_URL, headers={"User-Agent": "regenbench-malhug-crawl"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    return list(reader)


def download_file(url: str, dest: str, max_size_bytes: int) -> tuple[str, int]:
    if os.path.exists(dest):
        return "exists", os.path.getsize(dest)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "regenbench-malhug-crawl"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        content_len = resp.headers.get("Content-Length")
        if content_len and int(content_len) > max_size_bytes:
            return "too-large", int(content_len)
        downloaded = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > max_size_bytes:
                    f.close()
                    os.remove(dest)
                    return "too-large", downloaded
                f.write(chunk)
    return "downloaded", downloaded


def main() -> int:
    ap = argparse.ArgumentParser(description="Crawl MalHug real malicious models.")
    ap.add_argument("--out", default="data/malhug", help="output directory")
    ap.add_argument("--max-size-mb", type=int, default=100, help="max file size in MB")
    ap.add_argument("--limit", type=int, default=0, help="limit number of files (0=all)")
    args = ap.parse_args()

    max_size_bytes = args.max_size_mb * 1024 * 1024
    os.makedirs(args.out, exist_ok=True)

    print("Fetching MalHug metadata index...")
    try:
        rows = fetch_csv()
    except Exception as e:
        print(f"Failed to fetch MalHug CSV: {e}", file=sys.stderr)
        return 1

    model_rows = [r for r in rows if r.get("type") == "model"]
    print(f"Indexed {len(model_rows)} model records from MalHug.")

    manifest = []
    success_count = 0
    total_bytes = 0

    for r in model_rows:
        if args.limit and success_count >= args.limit:
            break
        mid = r.get("model_id/dataset_id", "").strip()
        files_str = r.get("files", "")
        if not mid or not files_str:
            continue

        for f_entry in files_str.split(","):
            fname = f_entry.split(":")[0].strip()
            if not fname:
                continue

            clean_repo = mid.replace("/", "__")
            clean_fname = fname.replace("/", "_")
            local_rel = f"{clean_repo}__{clean_fname}"
            dest_path = os.path.join(args.out, local_rel)
            url = f"https://huggingface.co/{mid}/resolve/main/{fname}"

            try:
                status, size = download_file(url, dest_path, max_size_bytes)
            except Exception as e:
                # print(f"  [skip] {mid}/{fname}: {e}")
                continue

            if status in ("downloaded", "exists"):
                success_count += 1
                total_bytes += size
                manifest.append({
                    "repo_id": mid,
                    "remote_file": fname,
                    "local_file": local_rel,
                    "size_bytes": size,
                    "model_type": r.get("model_type"),
                    "malicious_behaviors": r.get("malicious_behaviors"),
                    "libraries_and_apis": r.get("libraries_and_apis"),
                    "code_segment": r.get("code_segment1"),
                    "sha": r.get("sha"),
                })
                print(f"  [{status:10s}] {mid:35s} -> {local_rel:35s} ({size/1e6:6.2f} MB)")

    manifest_path = os.path.join(args.out, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump({
            "source": "https://github.com/security-pride/MalHug",
            "paper": "Models Are Codes: Towards Measuring Malicious Code Poisoning Attacks on Pre-trained Model Hubs (ASE 2024)",
            "count": len(manifest),
            "total_size_mb": round(total_bytes / (1024 * 1024), 2),
            "artifacts": manifest,
        }, f, indent=2)

    print("=" * 60)
    print(f"MalHug crawl complete: {len(manifest)} artifacts ({total_bytes/1e6:.1f} MB) saved to {args.out}")
    print(f"Manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
