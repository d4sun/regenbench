"""Tests for scripts/generate_charts.py (per-step chart generation).

Host-only (matplotlib + DB reads, no docker). Verifies that charts are
written into per-step subfolders, PNG files are valid, steps whose data is
missing are skipped, and the matplotlib guard fails cleanly.
"""

from __future__ import annotations

import builtins
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import generate_charts  # noqa: E402

DB = str(REPO / "data/regenbench_campaign.db")
SHELF = str(REPO / "data/shelf_life.db")
MANIFEST = str(REPO / "data/crawled/seed_manifest.json")
ORACLE_VAL = str(REPO / "real_benign_corpus/oracle-validation.json")
FP_EVAL = str(REPO / "real_benign_corpus/oracle-calibrated/current/fp-eval-eval.json")


class TestGenerateCharts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plt = generate_charts._require_pyplot()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = self._tmp.name

    def _png(self, rel: str) -> Path:
        p = Path(self.out) / rel
        self.assertTrue(p.is_file(), f"missing chart: {rel}")
        with open(p, "rb") as f:
            self.assertEqual(f.read(4), b"\x89PNG", f"not a PNG: {rel}")
        return p

    def test_full_pipeline_produces_per_step_folders(self):
        generate_charts.main([
            "--db", DB, "--shelf-db", SHELF, "--out", self.out,
            "--manifest", MANIFEST, "--oracle-validation", ORACLE_VAL,
            "--fp-eval", FP_EVAL,
        ])
        self._png("01_crawl/corpus_composition.png")
        self._png("02_oracle/oracle_score_distribution.png")
        self._png("03_calibrate/calibration_fp.png")
        for name in ("coverage_opcode", "coverage_callable", "family_entropy",
                     "bypass_yield_per_round", "per_family_bypasses",
                     "guided_vs_unguided_yield"):
            self._png(f"04_campaigns/{name}.png")
        for name in ("per_scanner_evasion", "cross_format_summary"):
            self._png(f"05_evaluation/{name}.png")
        self._png("06_defense/repair_metrics.png")
        self._png("07_gguf/gguf_detection_matrix.png")
        self._png("08_shelf_life/retention_by_version.png")

    def test_missing_step_data_is_skipped(self):
        self.assertIsNone(generate_charts.chart_crawl(
            self.plt, self.out, "/nonexistent/manifest.json", "png"))
        self.assertIsNone(generate_charts.chart_oracle(
            self.plt, self.out, "/nonexistent/oracle.json", "png"))
        self.assertEqual(generate_charts.chart_campaigns(
            self.plt, self.out, "/nonexistent/campaign.db", "png"), [])
        self.assertIsNone(generate_charts.chart_gguf(
            self.plt, self.out, "/nonexistent/campaign.db", "png"))
        self.assertIsNone(generate_charts.chart_shelf_life(
            self.plt, self.out, "/nonexistent/shelf.db", "png"))

    def test_matplotlib_missing_fails_cleanly(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "matplotlib" or name.startswith("matplotlib."):
                raise ImportError("no matplotlib")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            with self.assertRaises(SystemExit):
                generate_charts._require_pyplot()

    def test_chart_functions_return_paths(self):
        p = generate_charts.chart_crawl(self.plt, self.out, MANIFEST, "png")
        self.assertTrue(p and p.endswith("corpus_composition.png"))
        p = generate_charts.chart_shelf_life(self.plt, self.out, SHELF, "png")
        self.assertTrue(p and p.endswith("retention_by_version.png"))


if __name__ == "__main__":
    unittest.main()