"""Phase 2 correctness tests for pipeline/db.py (T4.4).

Covers schema idempotence + migrations, the COALESCE upsert semantics of
log_candidate, foreign-key enforcement, verdict replacement semantics,
JSON round-tripping of findings, and per-run coverage keying.
"""

from __future__ import annotations

import sqlite3
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline import db  # noqa: E402


class DbTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = str(Path(self._tmp.name) / "test.db")
        db.init_db(self.db_path)

    def _row(self, sql, args=()):
        conn = db._connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            return conn.execute(sql, args).fetchone()
        finally:
            conn.close()


class TestSchema(DbTestBase):
    def test_init_is_idempotent(self):
        db.init_db(self.db_path)
        db.init_db(self.db_path)
        conn = db._connect(self.db_path)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        finally:
            conn.close()
        self.assertEqual(
            {"candidates", "campaign_runs", "panel_results", "oracle_results",
             "campaign_fitness", "campaign_coverage"},
            tables,
        )

    def test_migrations_add_run_id_columns_to_legacy_db(self):
        # Simulate a v1.0 database without run_id columns.
        conn = sqlite3.connect(self.db_path)
        conn.execute("DROP TABLE candidates")
        conn.execute("DROP TABLE campaign_coverage")
        conn.execute("""CREATE TABLE candidates (
            candidate_id TEXT PRIMARY KEY, filepath TEXT, source TEXT,
            created_at TEXT, round_num INTEGER, seed_model TEXT,
            mutation_template TEXT, mutation_depth INTEGER,
            callables_used TEXT, campaign_type TEXT)""")
        conn.execute("""CREATE TABLE campaign_coverage (
            round_num INTEGER, opcode_coverage REAL, callable_coverage REAL,
            timestamp TEXT, PRIMARY KEY (round_num))""")
        conn.commit()
        conn.close()

        db.init_db(self.db_path)
        cand_cols = {r[1] for r in db._connect(self.db_path).execute(
            "PRAGMA table_info(candidates)").fetchall()}
        cov_cols = {r[1] for r in db._connect(self.db_path).execute(
            "PRAGMA table_info(campaign_coverage)").fetchall()}
        self.assertIn("run_id", cand_cols)
        self.assertIn("run_id", cov_cols)


class TestCandidateUpsert(DbTestBase):
    def test_rich_update_never_clobbers_existing_fields_with_none(self):
        # First write carries metadata; second write omits it.
        db.log_candidate(self.db_path, "c1", "/tmp/c1.pkl", source="seed",
                         seed_model="distilgpt2", campaign_type="evasion")
        # Later call knows more but omits seed_model/campaign_type ->
        # COALESCE upsert must preserve them, not null them out.
        db.log_candidate(self.db_path, "c1", "/tmp/c1.pkl", source="mutant",
                         round_num=3, mutation_template="overwritten",
                         mutation_depth=2)
        row = self._row("SELECT * FROM candidates WHERE candidate_id='c1'")
        self.assertEqual(row["source"], "mutant")          # updated
        self.assertEqual(row["seed_model"], "distilgpt2")  # preserved
        self.assertEqual(row["campaign_type"], "evasion")  # preserved
        self.assertEqual(row["round_num"], 3)              # filled
        self.assertEqual(row["mutation_template"], "overwritten")

    def test_explicit_null_reinsert_does_not_lose_filepath(self):
        # Runner-style first insert, then metadata layering on top.
        db.log_candidate(self.db_path, "c2", "/tmp/c2.pt", source="seed")
        db.log_candidate(self.db_path, "c2", "/tmp/c2.pt", source="mutant",
                         run_id="runZ", seed_model="tinyllama")
        row = self._row("SELECT * FROM candidates WHERE candidate_id='c2'")
        self.assertEqual(row["filepath"], "/tmp/c2.pt")  # never clobbered
        self.assertEqual(row["run_id"], "runZ")
        self.assertEqual(row["seed_model"], "tinyllama")

    def test_get_summary_of_unknown_candidate_returns_none(self):
        self.assertIsNone(db.get_candidate_summary(self.db_path, "ghost"))


class TestForeignKeys(DbTestBase):
    def test_panel_result_requires_existing_candidate(self):
        with self.assertRaises(sqlite3.IntegrityError):
            db.log_panel_result(self.db_path, "nope", "picklescan",
                                "malicious", 1, [], 0.5)

    def test_oracle_and_fitness_require_existing_candidate(self):
        with self.assertRaises(sqlite3.IntegrityError):
            db.log_oracle_result(self.db_path, "nope", "benign", None, 1.0, False)
        with self.assertRaises(sqlite3.IntegrityError):
            db.log_fitness(self.db_path, "nope", 1.5, True)


class TestResultRoundTrip(DbTestBase):
    def test_full_lifecycle_summary_shape(self):
        db.log_candidate(self.db_path, "c9", "/tmp/c9.pt", source="mutant",
                         round_num=1, seed_model="tinyllama",
                         mutation_template="shadowpickle_external", run_id="runA")
        findings = [{"rule": "suspicious.pickle", "score": 0.83}]
        db.log_panel_result(self.db_path, "c9", "modelscan", "malicious",
                            1, findings, 1.25)
        db.log_panel_result(self.db_path, "c9", "fickling", "error",
                            2, None, 0.01)
        db.log_oracle_result(self.db_path, "c9", "malicious", -0.031, 4.2,
                             pre_filtered=False)
        db.log_fitness(self.db_path, "c9", 3.97, True)

        summary = db.get_candidate_summary(self.db_path, "c9")
        self.assertEqual(summary["candidate_id"], "c9")
        self.assertEqual(summary["run_id"], "runA")
        self.assertEqual(len(summary["scanner_results"]), 2)
        by_scanner = {r["scanner"]: r for r in summary["scanner_results"]}
        # findings are persisted as JSON *strings*; consumers must decode.
        self.assertEqual(json.loads(by_scanner["modelscan"]["findings"]), findings)
        self.assertEqual(by_scanner["modelscan"]["verdict"], "malicious")
        # missing findings serialize as the JSON string "[]"
        self.assertEqual(by_scanner["fickling"]["findings"], "[]")
        oracle = summary["oracle_result"]
        self.assertAlmostEqual(oracle["decision_score"], -0.031)
        self.assertEqual(oracle["pre_filtered"], 0)
        self.assertEqual(summary["fitness"]["is_valid"], 1)

    def test_panel_verdict_replace_semantics(self):
        db.log_candidate(self.db_path, "cX", "/x.pkl", source="t")
        db.log_panel_result(self.db_path, "cX", "picklescan", "benign", 0, [], 0.1)
        db.log_panel_result(self.db_path, "cX", "picklescan", "malicious", 1,
                            ["hit"], 0.2)
        rows = db.get_candidate_summary(self.db_path, "cX")["scanner_results"]
        self.assertEqual(len(rows), 1, "PK (candidate_id, scanner) must dedupe")
        self.assertEqual(rows[0]["verdict"], "malicious")


class TestCampaignRunsAndCoverage(DbTestBase):
    def test_run_lifecycle(self):
        db.log_campaign_run(self.db_path, "r1", "evasion", replicate_num=2,
                            base_checkpoint="/models/tiny.pt",
                            total_candidates=100, total_rounds=10)
        row = self._row("SELECT * FROM campaign_runs WHERE run_id='r1'")
        self.assertIsNone(row["completed_at"])
        db.complete_campaign_run(self.db_path, "r1")
        row = self._row("SELECT * FROM campaign_runs WHERE run_id='r1'")
        self.assertIsNotNone(row["completed_at"])

    def test_log_campaign_run_replaces_same_run_id(self):
        db.log_campaign_run(self.db_path, "r1", "evasion", 1, "a.pt", 50, 5)
        db.log_campaign_run(self.db_path, "r1", "robustness", 3, "b.pt", 70, 7)
        n = self._row("SELECT COUNT(*) FROM campaign_runs")[0]
        self.assertEqual(n, 1)
        row = self._row("SELECT * FROM campaign_runs WHERE run_id='r1'")
        self.assertEqual(row["campaign_type"], "robustness")

    def test_coverage_keyed_per_run_not_per_round_globally(self):
        db.log_coverage(self.db_path, 1, 0.5, 0.25, run_id="runA")
        db.log_coverage(self.db_path, 1, 0.6, 0.30, run_id="runB")
        db.log_coverage(self.db_path, 1, 0.55, 0.28, run_id="runA")  # upsert
        with db._session(self.db_path) as (cur, _):
            rows = cur.execute(
                "SELECT run_id, round_num, opcode_coverage FROM campaign_coverage "
                "ORDER BY run_id").fetchall()
        self.assertEqual(len(rows), 2)
        by_run = dict((r[0], r[2]) for r in rows)
        self.assertAlmostEqual(by_run["runA"], 0.55)
        self.assertAlmostEqual(by_run["runB"], 0.60)

    def test_default_empty_run_id_bucket(self):
        db.log_coverage(self.db_path, 0, 0.1, 0.1)
        db.log_coverage(self.db_path, 0, 0.2, 0.2)
        n = self._row("SELECT COUNT(*) FROM campaign_coverage")[0]
        self.assertEqual(n, 1, "default bucket must still dedupe on round_num")


class TestSessionAtomicity(DbTestBase):
    def test_failed_write_rolls_back(self):
        db.log_candidate(self.db_path, "keep", "/k.pkl", source="t")
        with self.assertRaises(sqlite3.IntegrityError):
            with db._session(self.db_path) as (cur, _):
                cur.execute("INSERT INTO candidates (candidate_id, filepath, source)"
                            " VALUES ('keep', '/dup.pkl', 'dup')")  # PK clash
        n = self._row("SELECT COUNT(*) FROM candidates WHERE candidate_id='keep'")[0]
        self.assertEqual(n, 1, "rollback must leave prior state intact")


if __name__ == "__main__":
    unittest.main()
