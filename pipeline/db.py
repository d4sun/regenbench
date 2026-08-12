"""T4.4 — Unified Candidate Schema Database.

Creates and populates SQLite database tables linking candidate_id to panel and oracle results.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any


def init_db(db_path: str) -> None:
    """Initialize the SQLite tables for unified result tracking."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Candidates table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            candidate_id TEXT PRIMARY KEY,
            filepath TEXT,
            source TEXT,
            created_at TEXT
        )
    """)
    
    # 2. Panel results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS panel_results (
            candidate_id TEXT,
            scanner TEXT,
            verdict TEXT,
            exit_code INTEGER,
            findings TEXT,
            duration REAL,
            PRIMARY KEY (candidate_id, scanner),
            FOREIGN KEY (candidate_id) REFERENCES candidates(candidate_id)
        )
    """)
    
    # 3. Oracle results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS oracle_results (
            candidate_id TEXT PRIMARY KEY,
            verdict TEXT,
            decision_score REAL,
            duration REAL,
            pre_filtered INTEGER,
            FOREIGN KEY (candidate_id) REFERENCES candidates(candidate_id)
        )
    """)
    
    # 4. Fitness score table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campaign_fitness (
            candidate_id TEXT PRIMARY KEY,
            fitness_score REAL,
            is_valid INTEGER,
            FOREIGN KEY (candidate_id) REFERENCES candidates(candidate_id)
        )
    """)

    # 5. Campaign coverage table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campaign_coverage (
            round_num INTEGER PRIMARY KEY,
            opcode_coverage REAL,
            callable_coverage REAL,
            timestamp TEXT
        )
    """)
    
    conn.commit()
    conn.close()


def log_candidate(db_path: str, candidate_id: str, filepath: str, source: str) -> None:
    """Insert or ignore a candidate in the candidates table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO candidates (candidate_id, filepath, source, created_at) VALUES (?, ?, ?, ?)",
        (candidate_id, filepath, source, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
    )
    conn.commit()
    conn.close()


def log_panel_result(
    db_path: str,
    candidate_id: str,
    scanner: str,
    verdict: str,
    exit_code: int | None,
    findings: list[Any] | dict[str, Any] | None,
    duration: float,
) -> None:
    """Insert or replace a scanner panel result."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    findings_str = json.dumps(findings) if findings is not None else "[]"
    cursor.execute(
        """INSERT OR REPLACE INTO panel_results 
        (candidate_id, scanner, verdict, exit_code, findings, duration) 
        VALUES (?, ?, ?, ?, ?, ?)""",
        (candidate_id, scanner, verdict, exit_code, findings_str, duration),
    )
    conn.commit()
    conn.close()


def log_oracle_result(
    db_path: str,
    candidate_id: str,
    verdict: str,
    decision_score: float | None,
    duration: float,
    pre_filtered: bool,
) -> None:
    """Insert or replace an oracle result."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO oracle_results 
        (candidate_id, verdict, decision_score, duration, pre_filtered) 
        VALUES (?, ?, ?, ?, ?)""",
        (candidate_id, verdict, decision_score, duration, 1 if pre_filtered else 0),
    )
    conn.commit()
    conn.close()


def log_fitness(db_path: str, candidate_id: str, fitness_score: float, is_valid: bool) -> None:
    """Insert or replace fitness evaluation."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO campaign_fitness 
        (candidate_id, fitness_score, is_valid) 
        VALUES (?, ?, ?)""",
        (candidate_id, fitness_score, 1 if is_valid else 0),
    )
    conn.commit()
    conn.close()


def get_candidate_summary(db_path: str, candidate_id: str) -> dict[str, Any] | None:
    """Retrieve full database record linking all tables for a given candidate_id."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if candidate exists
    cand = cursor.execute("SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
    if not cand:
        conn.close()
        return None
        
    summary = dict(cand)
    
    # Get panel results
    panels = cursor.execute("SELECT * FROM panel_results WHERE candidate_id = ?", (candidate_id,)).fetchall()
    summary["scanner_results"] = [dict(p) for p in panels]
    
    # Get oracle results
    oracle = cursor.execute("SELECT * FROM oracle_results WHERE candidate_id = ?", (candidate_id,)).fetchone()
    summary["oracle_result"] = dict(oracle) if oracle else {}
    
    # Get fitness
    fit = cursor.execute("SELECT * FROM campaign_fitness WHERE candidate_id = ?", (candidate_id,)).fetchone()
    summary["fitness"] = dict(fit) if fit else {}
    
    conn.close()
    return summary


def log_coverage(db_path: str, round_num: int, opcode_cov: float, callable_cov: float) -> None:
    """Insert or replace round coverage statistics."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO campaign_coverage 
        (round_num, opcode_coverage, callable_coverage, timestamp) 
        VALUES (?, ?, ?, ?)""",
        (round_num, opcode_cov, callable_cov, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
    )
    conn.commit()
    conn.close()
