"""T6.3 — Bypass Corpus Manager.

Manages, deduplicates, and versions confirmed scanner bypasses with metadata.
"""

from __future__ import annotations

import os
import shutil
import hashlib
import json
import sqlite3
from typing import Any

from pipeline.db import get_candidate_summary


def export_bypasses(db_path: str, output_dir: str) -> int:
    """Find all confirmed bypasses in the DB, deduplicate them, and export to output_dir."""
    if not os.path.exists(db_path):
        return 0

    os.makedirs(output_dir, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Confirmed bypass: oracle labeled it malicious, the panel has at least one
    # benign row, and no panel row is malicious or errored (an errored scanner
    # is never "evaded", matching pipeline.comparator.check_bypass). The
    # candidate must also be valid (loaded + sentinel fired) per the driver.
    query = """
        SELECT c.candidate_id, c.filepath FROM candidates c
        JOIN oracle_results o ON c.candidate_id = o.candidate_id
        JOIN campaign_fitness f ON f.candidate_id = c.candidate_id
        WHERE o.verdict = 'malicious' AND o.pre_filtered = 0
        AND f.is_valid = 1
        AND EXISTS (
            SELECT 1 FROM panel_results p
            WHERE p.candidate_id = c.candidate_id AND p.verdict = 'benign'
        )
        AND NOT EXISTS (
            SELECT 1 FROM panel_results p
            WHERE p.candidate_id = c.candidate_id
              AND p.verdict IN ('malicious', 'error')
        )
    """
    
    try:
        cursor.execute(query)
        candidates = cursor.fetchall()
    except sqlite3.OperationalError:
        conn.close()
        return 0
        
    conn.close()
    
    export_count = 0
    seen_hashes: set[str] = set()
    
    for cand_id, filepath in candidates:
        if not os.path.exists(filepath):
            continue
            
        # Read content to compute deduplication hash
        try:
            with open(filepath, "rb") as f:
                content = f.read()
        except OSError:
            continue
            
        sha256 = hashlib.sha256(content).hexdigest()
        
        # Deduplicate
        if sha256 in seen_hashes:
            continue
        seen_hashes.add(sha256)
        
        # Get metadata from DB
        summary = get_candidate_summary(db_path, cand_id)
        if not summary:
            continue
            
        # Determine extension
        ext = os.path.splitext(filepath)[1].lower()
        if not ext:
            ext = ".pt"
            
        dest_file = os.path.join(output_dir, f"{sha256}{ext}")
        dest_meta = os.path.join(output_dir, f"{sha256}.json")
        
        # Save checkpoint and metadata
        try:
            shutil.copy(filepath, dest_file)
            
            # Enrich metadata
            metadata = {
                "sha256": sha256,
                "candidate_id": cand_id,
                "original_filepath": filepath,
                "scanner_results": summary.get("scanner_results", []),
                "oracle_result": summary.get("oracle_result", {}),
                "fitness": summary.get("fitness", {})
            }
            with open(dest_meta, "w") as fm:
                json.dump(metadata, fm, indent=2)
                
            export_count += 1
        except OSError:
            pass
            
    return export_count
