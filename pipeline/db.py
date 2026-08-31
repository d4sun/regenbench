"""T4.4 — Unified Candidate Schema Database.

Creates and populates SQLite database tables linking candidate_id to panel and oracle results.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any


def _connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with foreign-key enforcement enabled."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def _session(db_path: str) -> Any:
    """Yield a cursor with guaranteed commit/close (and rollback on error)."""
    conn = _connect(db_path)
    try:
        cursor = conn.cursor()
        yield cursor, conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str) -> None:
    """Initialize the SQLite tables for unified result tracking."""
    with _session(db_path) as (cursor, conn):
        # 1. Candidates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS candidates (
                candidate_id TEXT PRIMARY KEY,
                filepath TEXT,
                source TEXT,
                created_at TEXT,
                round_num INTEGER,
                seed_model TEXT,
                mutation_template TEXT,
                mutation_depth INTEGER,
                callables_used TEXT,
                campaign_type TEXT,
                run_id TEXT,
                mutation_strategy TEXT,
                parent_id TEXT,
                generation INTEGER,
                oracle_verdict TEXT,
                panel_verdict TEXT,
                coverage_delta REAL,
                novelty_score REAL
            )
        """)

        # 6. Campaign run (replicate) tracking table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_runs (
                run_id TEXT PRIMARY KEY,
                campaign_type TEXT,
                replicate_num INTEGER,
                base_checkpoint TEXT,
                total_candidates INTEGER,
                total_rounds INTEGER,
                started_at TEXT,
                completed_at TEXT
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

        # 5. Campaign coverage table (keyed per run so replicates/campaigns
        #    do not overwrite each other's per-round coverage rows).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_coverage (
                run_id TEXT NOT NULL DEFAULT '',
                round_num INTEGER,
                opcode_coverage REAL,
                callable_coverage REAL,
                family_coverage REAL,
                family_bypass_coverage REAL,
                entropy REAL,
                timestamp TEXT,
                PRIMARY KEY (run_id, round_num)
            )
        """)

        # Migration: add run_id to candidates for pre-existing databases.
        cols = {row[1] for row in cursor.execute("PRAGMA table_info(candidates)").fetchall()}
        if "run_id" not in cols:
            cursor.execute("ALTER TABLE candidates ADD COLUMN run_id TEXT")

        # Migration: add run_id to campaign_coverage for pre-existing databases.
        cov_cols = {row[1] for row in cursor.execute("PRAGMA table_info(campaign_coverage)").fetchall()}
        if "run_id" not in cov_cols:
            cursor.execute("ALTER TABLE campaign_coverage ADD COLUMN run_id TEXT DEFAULT ''")

        # Migration: add fitness_mode to campaign_runs for pre-existing databases
        run_cols = {row[1] for row in cursor.execute("PRAGMA table_info(campaign_runs)").fetchall()}
        if "fitness_mode" not in run_cols:
            cursor.execute("ALTER TABLE campaign_runs ADD COLUMN fitness_mode TEXT DEFAULT ''")

        # Migration: add instrumentation columns to candidates table
        cand_cols = {row[1] for row in cursor.execute("PRAGMA table_info(candidates)").fetchall()}
        for col_name, col_type in [
            ("mutation_strategy", "TEXT"),
            ("parent_id", "TEXT"),
            ("generation", "INTEGER"),
            ("oracle_verdict", "TEXT"),
            ("panel_verdict", "TEXT"),
            ("coverage_delta", "REAL"),
            ("novelty_score", "REAL"),
        ]:
            if col_name not in cand_cols:
                cursor.execute(f"ALTER TABLE candidates ADD COLUMN {col_name} {col_type}")

        # Migration: add RQ2 combo columns (transport / strategies) to
        # campaign_fitness so analyses can group combo effectiveness.
        fit_cols = {row[1] for row in cursor.execute("PRAGMA table_info(campaign_fitness)").fetchall()}
        for col_name, col_type in [
            ("transport", "TEXT"),
            ("strategies", "TEXT"),
        ]:
            if col_name not in fit_cols:
                cursor.execute(f"ALTER TABLE campaign_fitness ADD COLUMN {col_name} {col_type}")

        # Migration: P1.4 family coverage + entropy
        cov_cols2 = {row[1] for row in cursor.execute("PRAGMA table_info(campaign_coverage)").fetchall()}
        for col_name, col_type in [
            ("family_coverage", "REAL"),
            ("family_bypass_coverage", "REAL"),
            ("entropy", "REAL"),
        ]:
            if col_name not in cov_cols2:
                cursor.execute(f"ALTER TABLE campaign_coverage ADD COLUMN {col_name} {col_type}")

        # Migration: P2.3 consensus tier
        cand_cols2 = {row[1] for row in cursor.execute("PRAGMA table_info(candidates)").fetchall()}
        if "consensus_tier" not in cand_cols2:
            cursor.execute("ALTER TABLE candidates ADD COLUMN consensus_tier TEXT")
        fit_cols2 = {row[1] for row in cursor.execute("PRAGMA table_info(campaign_fitness)").fetchall()}
        if "consensus_tier" not in fit_cols2:
            cursor.execute("ALTER TABLE campaign_fitness ADD COLUMN consensus_tier TEXT")
    # _session() commits and closes on exit.


def log_candidate(
    db_path: str,
    candidate_id: str,
    filepath: str,
    source: str,
    round_num: int | None = None,
    seed_model: str | None = None,
    mutation_template: str | None = None,
    mutation_depth: int | None = None,
    callables_used: str | None = None,
    campaign_type: str | None = None,
    run_id: str | None = None,
    mutation_strategy: str | None = None,
    parent_id: str | None = None,
    generation: int | None = None,
    oracle_verdict: str | None = None,
    panel_verdict: str | None = None,
    coverage_delta: float | None = None,
    novelty_score: float | None = None,
    consensus_tier: str | None = None,
) -> None:
    """Insert a candidate; on conflict, fill in any newly-provided metadata fields.

    Runner.run() inserts candidates with basic fields before the campaign layers
    on experiment metadata (seed model, template, etc.). Because the row may
    already exist, metadata columns are updated only when a non-None value is
    provided, so earlier calls never clobber later richer records.
    """
    with _session(db_path) as (cursor, _):
        cursor.execute(
            """INSERT INTO candidates 
            (candidate_id, filepath, source, created_at, round_num, seed_model, 
             mutation_template, mutation_depth, callables_used, campaign_type, run_id,
             mutation_strategy, parent_id, generation, oracle_verdict, panel_verdict,
             coverage_delta, novelty_score, consensus_tier) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(candidate_id) DO UPDATE SET
                filepath = COALESCE(excluded.filepath, candidates.filepath),
                source = COALESCE(excluded.source, candidates.source),
                round_num = COALESCE(excluded.round_num, candidates.round_num),
                seed_model = COALESCE(excluded.seed_model, candidates.seed_model),
                mutation_template = COALESCE(excluded.mutation_template, candidates.mutation_template),
                mutation_depth = COALESCE(excluded.mutation_depth, candidates.mutation_depth),
                callables_used = COALESCE(excluded.callables_used, candidates.callables_used),
                campaign_type = COALESCE(excluded.campaign_type, candidates.campaign_type),
                run_id = COALESCE(excluded.run_id, candidates.run_id),
                mutation_strategy = COALESCE(excluded.mutation_strategy, candidates.mutation_strategy),
                parent_id = COALESCE(excluded.parent_id, candidates.parent_id),
                generation = COALESCE(excluded.generation, candidates.generation),
                oracle_verdict = COALESCE(excluded.oracle_verdict, candidates.oracle_verdict),
                panel_verdict = COALESCE(excluded.panel_verdict, candidates.panel_verdict),
                coverage_delta = COALESCE(excluded.coverage_delta, candidates.coverage_delta),
                novelty_score = COALESCE(excluded.novelty_score, candidates.novelty_score),
                consensus_tier = COALESCE(excluded.consensus_tier, candidates.consensus_tier)
            """,
            (
                candidate_id,
                filepath,
                source,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                round_num,
                seed_model,
                mutation_template,
                mutation_depth,
                callables_used,
                campaign_type,
                run_id,
                mutation_strategy,
                parent_id,
                generation,
                oracle_verdict,
                panel_verdict,
                coverage_delta,
                novelty_score,
                consensus_tier,
            ),
        )


def log_campaign_run(
    db_path: str,
    run_id: str,
    campaign_type: str,
    replicate_num: int,
    base_checkpoint: str,
    total_candidates: int,
    total_rounds: int,
    fitness_mode: str = "",
) -> None:
    """Insert or replace a campaign replicate record."""
    with _session(db_path) as (cursor, _):
        cursor.execute(
            """INSERT OR REPLACE INTO campaign_runs 
            (run_id, campaign_type, replicate_num, base_checkpoint, total_candidates, 
             total_rounds, started_at, fitness_mode) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                campaign_type,
                replicate_num,
                base_checkpoint,
                total_candidates,
                total_rounds,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                fitness_mode,
            ),
        )


def complete_campaign_run(db_path: str, run_id: str) -> None:
    """Mark a campaign replicate as completed."""
    with _session(db_path) as (cursor, _):
        cursor.execute(
            "UPDATE campaign_runs SET completed_at = ? WHERE run_id = ?",
            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), run_id),
        )


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
    with _session(db_path) as (cursor, _):
        findings_str = json.dumps(findings) if findings is not None else "[]"
        cursor.execute(
            """INSERT OR REPLACE INTO panel_results 
            (candidate_id, scanner, verdict, exit_code, findings, duration) 
            VALUES (?, ?, ?, ?, ?, ?)""",
            (candidate_id, scanner, verdict, exit_code, findings_str, duration),
        )


def log_oracle_result(
    db_path: str,
    candidate_id: str,
    verdict: str,
    decision_score: float | None,
    duration: float,
    pre_filtered: bool,
) -> None:
    """Insert or replace an oracle result."""
    with _session(db_path) as (cursor, _):
        cursor.execute(
            """INSERT OR REPLACE INTO oracle_results 
            (candidate_id, verdict, decision_score, duration, pre_filtered) 
            VALUES (?, ?, ?, ?, ?)""",
            (candidate_id, verdict, decision_score, duration, 1 if pre_filtered else 0),
        )


def log_fitness(db_path: str, candidate_id: str, fitness_score: float, is_valid: bool,
                 transport: str | None = None, strategies: str | None = None,
                 consensus_tier: str | None = None) -> None:
    """Insert or replace fitness evaluation.

    ``transport`` / ``strategies`` are the RQ2 combo dimensions recorded so
    analysis scripts can group fitness/bypass outcomes by configuration.
    ``consensus_tier`` is P2.3 tier 1/2/3 (or None).
    """
    with _session(db_path) as (cursor, _):
        cursor.execute(
            """INSERT OR REPLACE INTO campaign_fitness
            (candidate_id, fitness_score, is_valid, transport, strategies, consensus_tier)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (candidate_id, fitness_score, 1 if is_valid else 0,
             transport, strategies, consensus_tier),
        )


def get_candidate_summary(db_path: str, candidate_id: str) -> dict[str, Any] | None:
    """Retrieve full database record linking all tables for a given candidate_id."""
    conn = _connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        # Check if candidate exists
        cand = cursor.execute("SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
        if not cand:
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

        return summary
    finally:
        conn.close()


def log_coverage(db_path: str, round_num: int, opcode_cov: float, callable_cov: float,
                 run_id: str = "", family_cov: float = 0.0,
                 family_bypass_cov: float = 0.0, entropy: float = 0.0) -> None:
    """Insert or replace round coverage statistics for a campaign run."""
    with _session(db_path) as (cursor, _):
        cursor.execute(
            """INSERT OR REPLACE INTO campaign_coverage 
            (run_id, round_num, opcode_coverage, callable_coverage,
             family_coverage, family_bypass_coverage, entropy, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, round_num, opcode_cov, callable_cov,
             family_cov, family_bypass_cov, entropy,
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        )
