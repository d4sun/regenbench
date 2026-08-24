"""T7.9 — Bypass Shelf-Life Tracking.

Implements version-delta re-scanning of confirmed bypasses against scanner
version updates to measure evasion shelf-life decay (H3).

Tracks:
- Bypass artifact metadata (scanner versions at discovery)
- Re-scan results against updated scanner versions
- Decay curve: evasion retention rate over version deltas
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = "data/regenbench_campaign.db"


@dataclass
class BypassRecord:
    """Metadata for a confirmed bypass artifact."""
    candidate_id: str
    run_id: str
    family: str
    callable: str
    transport: str
    strategies: list[str]
    artifact_path: str
    discovered_at: str
    scanner_versions: dict[str, str]
    panel_verdicts: dict[str, str]
    oracle_verdict: str
    decision_score: float

@dataclass
class RescanResult:
    """Result of re-scanning a bypass against updated scanner versions."""
    candidate_id: str
    rescanned_at: str
    scanner: str
    old_version: str
    new_version: str
    old_verdict: str
    new_verdict: str
    evasion_retained: bool


class ShelfLifeTracker:
    """Tracks bypass shelf-life across scanner version updates."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH, shelf_db_path: str | None = None):
        self.db_path = db_path
        self.shelf_db_path = shelf_db_path or os.path.join(
            os.path.dirname(db_path), "shelf_life.db"
        )
        self._init_shelf_db()

    def _init_shelf_db(self) -> None:
        """Initialize the shelf-life tracking database."""
        conn = sqlite3.connect(self.shelf_db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bypass_records (
                candidate_id TEXT PRIMARY KEY,
                run_id TEXT,
                family TEXT,
                callable TEXT,
                transport TEXT,
                strategies TEXT,
                artifact_path TEXT,
                discovered_at TEXT,
                scanner_versions TEXT,
                panel_verdicts TEXT,
                oracle_verdict TEXT,
                decision_score REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rescans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_id TEXT,
                rescanned_at TEXT,
                scanner TEXT,
                old_version TEXT,
                new_version TEXT,
                old_verdict TEXT,
                new_verdict TEXT,
                evasion_retained INTEGER,
                FOREIGN KEY(candidate_id) REFERENCES bypass_records(candidate_id)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rescans_candidate ON rescans(candidate_id)
        """)
        conn.commit()
        conn.close()

    def record_bypass(self, record: BypassRecord) -> None:
        """Store a confirmed bypass for future re-scanning."""
        conn = sqlite3.connect(self.shelf_db_path)
        conn.execute("""
            INSERT OR REPLACE INTO bypass_records
            (candidate_id, run_id, family, callable, transport, strategies,
             artifact_path, discovered_at, scanner_versions, panel_verdicts,
             oracle_verdict, decision_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.candidate_id, record.run_id, record.family, record.callable,
            record.transport, json.dumps(record.strategies), record.artifact_path,
            record.discovered_at, json.dumps(record.scanner_versions),
            json.dumps(record.panel_verdicts), record.oracle_verdict,
            record.decision_score
        ))
        conn.commit()
        conn.close()

    def get_bypasses_for_rescan(self, scanner: str | None = None) -> list[BypassRecord]:
        """Get all confirmed bypasses, optionally filtered by scanner."""
        conn = sqlite3.connect(self.shelf_db_path)
        conn.row_factory = sqlite3.Row
        query = "SELECT * FROM bypass_records"
        params = []
        if scanner:
            query += " WHERE json_extract(scanner_versions, '$.' || ?) IS NOT NULL"
            params.append(scanner)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        
        return [
            BypassRecord(
                candidate_id=row["candidate_id"],
                run_id=row["run_id"],
                family=row["family"],
                callable=row["callable"],
                transport=row["transport"],
                strategies=json.loads(row["strategies"]),
                artifact_path=row["artifact_path"],
                discovered_at=row["discovered_at"],
                scanner_versions=json.loads(row["scanner_versions"]),
                panel_verdicts=json.loads(row["panel_verdicts"]),
                oracle_verdict=row["oracle_verdict"],
                decision_score=row["decision_score"]
            )
            for row in rows
        ]

    def rescan_bypass(self, record: BypassRecord, scanners: list[str],
                      new_versions: dict[str, str],
                      backend: str = "podman") -> list[RescanResult]:
        """Re-scan a bypass artifact against updated scanner versions."""
        from pipeline.runner import Runner, Config
        
        results = []
        if not os.path.isfile(record.artifact_path):
            raise FileNotFoundError(f"bypass artifact not found: {record.artifact_path}")
        missing = [s for s in scanners if s not in new_versions]
        if missing:
            raise ValueError(f"missing image override for scanner(s): {', '.join(missing)}")
        runner = Runner(
            Config(backend=backend, timeout=180, oracle=False, pre_filter=False),
            scanners=scanners,
            overrides=[f"{s}={new_versions[s]}" for s in scanners],
        )
        results_list = runner.run([record.artifact_path])
        
        for res in results_list:
            old_ver = record.scanner_versions.get(res.scanner, "unknown")
            new_ver = runner.images.get(res.scanner, new_versions[res.scanner])
            old_verdict = record.panel_verdicts.get(res.scanner, "unknown")
            new_verdict = res.verdict or "error"
            retained = (old_verdict == "benign" and new_verdict == "benign")
            
            result = RescanResult(
                candidate_id=record.candidate_id,
                rescanned_at=datetime.utcnow().isoformat(),
                scanner=res.scanner,
                old_version=old_ver,
                new_version=new_ver,
                old_verdict=old_verdict,
                new_verdict=new_verdict,
                evasion_retained=retained
            )
            results.append(result)
            
            # Store rescan result
            self._store_rescan(result)
        
        return results

    def _store_rescan(self, result: RescanResult) -> None:
        conn = sqlite3.connect(self.shelf_db_path)
        conn.execute("""
            INSERT INTO rescans
            (candidate_id, rescanned_at, scanner, old_version, new_version,
             old_verdict, new_verdict, evasion_retained)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.candidate_id, result.rescanned_at, result.scanner,
            result.old_version, result.new_version,
            result.old_verdict, result.new_verdict,
            int(result.evasion_retained)
        ))
        conn.commit()
        conn.close()

    def compute_decay_curve(self, scanner: str | None = None) -> dict:
        """Compute evasion retention rate over version deltas."""
        conn = sqlite3.connect(self.shelf_db_path)
        conn.row_factory = sqlite3.Row
        
        query = """
            SELECT r.new_version, r.evasion_retained
            FROM rescans r
            JOIN bypass_records b ON r.candidate_id = b.candidate_id
            WHERE 1=1
        """
        params = []
        if scanner:
            query += " AND r.scanner = ?"
            params.append(scanner)
        query += " ORDER BY r.new_version"
        
        rows = conn.execute(query, params).fetchall()
        conn.close()
        
        # Group by version and compute retention rate
        from collections import defaultdict
        version_stats = defaultdict(lambda: {"total": 0, "retained": 0})
        
        for row in rows:
            version_stats[row["new_version"]]["total"] += 1
            if row["evasion_retained"]:
                version_stats[row["new_version"]]["retained"] += 1
        
        decay = {}
        for version, stats in sorted(version_stats.items()):
            decay[version] = {
                "total": stats["total"],
                "retained": stats["retained"],
                "retention_rate": stats["retained"] / stats["total"] if stats["total"] > 0 else 0.0
            }
        
        return decay


def register_confirmed_bypass(
    candidate_id: str,
    run_id: str,
    family: str,
    callable: str,
    transport: str,
    strategies: list[str],
    artifact_path: str,
    scanner_versions: dict[str, str],
    panel_verdicts: dict[str, str],
    oracle_verdict: str,
    decision_score: float,
    db_path: str = DEFAULT_DB_PATH
) -> None:
    """Convenience function to record a confirmed bypass for shelf-life tracking."""
    tracker = ShelfLifeTracker(db_path=db_path)
    record = BypassRecord(
        candidate_id=candidate_id,
        run_id=run_id,
        family=family,
        callable=callable,
        transport=transport,
        strategies=strategies,
        artifact_path=artifact_path,
        discovered_at=datetime.utcnow().isoformat(),
        scanner_versions=scanner_versions,
        panel_verdicts=panel_verdicts,
        oracle_verdict=oracle_verdict,
        decision_score=decision_score
    )
    tracker.record_bypass(record)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(prog="shelf_life", description="Shelf-life tracking and re-scanning for H3")
    ap.add_argument("--rescan", action="store_true", help="Re-scan tracked bypasses against updated scanner versions")
    ap.add_argument("--scanners", default="picklescan,modelscan,fickling", help="Comma-separated scanners to use for re-scanning")
    ap.add_argument("--backend", choices=["podman", "docker"], default="podman")
    args = ap.parse_args()
    
    if args.rescan:
        scanners = [s.strip() for s in args.scanners.split(",")]
        # Pull updated images
        import subprocess
        versions = {}
        for scanner in args.scanners.split(","):
            scanner = scanner.strip()
            image = f"regenbench/{scanner}:latest"
            print(f"[shelf-life] Pulling {image}...")
            result = subprocess.run(["podman", "pull", image], capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                inspect = subprocess.run(["podman", "inspect", image, "--format", "{{.Id}}"], capture_output=True, text=True, timeout=30)
                if inspect.returncode == 0:
                    version = inspect.stdout.strip()[:12]
                else:
                    version = "unknown"
            else:
                version = "error"
            print(f"  {scanner}: {version}")
        tracker = ShelfLifeTracker()
        decay = tracker.compute_decay_curve()
        print(json.dumps(decay, indent=2))
    else:
        tracker = ShelfLifeTracker()
        print("ShelfLifeTracker initialized")
        print(f"DB: {tracker.shelf_db_path}")