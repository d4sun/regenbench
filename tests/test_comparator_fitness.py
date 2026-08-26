"""Phase 2 correctness tests for pipeline/comparator.py (T5.1) and fitness.py (T5.2).

Property-style tests: an exhaustive truth table plus seeded randomized fuzzing
against an independently written reference implementation.
"""

from __future__ import annotations

import itertools
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.comparator import check_bypass  # noqa: E402
from pipeline.fitness import compute_fitness, compute_fitness_multi  # noqa: E402


def _reference_bypass(panel_verdicts, oracle_verdict):
    """Independent restatement of the spec (Section 'Confirmed bypass'):
    every panel scanner says benign AND the dynamic oracle says malicious.
    Error verdicts must never count as evasion."""
    if not panel_verdicts:
        return False
    return (
        all(v == "benign" for v in panel_verdicts)
        and oracle_verdict == "malicious"
    )


class TestCheckBypassTruthTable(unittest.TestCase):
    VERDICTS = ("benign", "malicious", "error")
    ORACLE = ("benign", "malicious", "error")

    def test_exhaustive_panels_size_1_to_3(self):
        for size in (1, 2, 3):
            for panel in itertools.product(self.VERDICTS, repeat=size):
                for oracle in self.ORACLE:
                    with self.subTest(panel=panel, oracle=oracle):
                        self.assertEqual(
                            check_bypass(list(panel), oracle),
                            _reference_bypass(panel, oracle),
                            (panel, oracle),
                        )

    def test_empty_panel_is_never_a_bypass(self):
        for oracle in self.ORACLE + ("", "unknown"):
            self.assertFalse(check_bypass([], oracle))

    def test_error_panel_verdict_folds_to_false_even_if_oracle_malicious(self):
        self.assertFalse(check_bypass(["benign", "error"], "malicious"))
        self.assertFalse(check_bypass(["error"], "malicious"))

    def test_single_malicious_detector_blocks_bypass(self):
        self.assertFalse(check_bypass(["benign", "malicious", "benign"], "malicious"))

    def test_canonical_true_case(self):
        self.assertTrue(check_bypass(["benign"] * 4, "malicious"))

    def test_randomized_fuzz_against_reference(self):
        rng = random.Random(20260822)
        vocab = ["benign", "malicious", "error", "timeout", "", "BENIGN",
                 "benign ", None]
        for _ in range(1000):
            size = rng.randint(0, 5)
            panel = [rng.choice(vocab) for _ in range(size)]
            oracle = rng.choice(vocab)
            try:
                expected = _reference_bypass(panel, oracle)
                actual = check_bypass(panel, oracle)
            except Exception as exc:  # pragma: no cover
                self.fail(f"raised {exc!r} on {(panel, oracle)}")
            self.assertEqual(actual, expected, (panel, oracle))


class TestComputeFitness(unittest.TestCase):
    TOTAL = 4

    def test_known_answer_values(self):
        cases = [
            # (detected, total, decision_score, expected)
            (0, 4, 0.0, 5.0),   # full evasion + max boundary bonus
            (4, 4, None, 0.5),  # no evasion; missing score treated as dist 1.0
            (2, 4, 1.0, 2.5),   # 2 evasion + 0.5
            (0, 4, float("inf"), 1.0),  # huge distance -> bonus ~0 -> exactly 1.0? see below
        ]
        for detected, total, score, expected in cases[:-1]:
            with self.subTest(detected=detected, score=score):
                self.assertAlmostEqual(
                    compute_fitness(detected, total, score), expected)
        # inf distance: 1/(1+inf) == 0.0 -> fitness equals evasion alone.
        self.assertEqual(compute_fitness(0, 4, float("inf")), 4.0)

    def test_bonus_lies_in_open_half_open_interval(self):
        # With an empty panel the score IS the boundary bonus alone.
        rng = random.Random(42)
        for _ in range(500):
            score = rng.uniform(-50, 50) if rng.random() < 0.9 else None
            fit = compute_fitness(0, 0, score)
            self.assertGreater(fit, 0.0)
            self.assertLessEqual(fit, 1.0)

    def test_monotone_decreasing_in_detected_count(self):
        prev = compute_fitness(0, 6, 0.37)
        for d in range(1, 7):
            cur = compute_fitness(d, 6, 0.37)
            self.assertLess(cur, prev)
            prev = cur

    def test_distance_uses_absolute_value(self):
        for score in (0.0, 0.13, -3.7, 12.9):
            self.assertAlmostEqual(
                compute_fitness(1, 4, score),
                compute_fitness(1, 4, -score),
            )

    def test_none_equals_distance_one(self):
        self.assertAlmostEqual(
            compute_fitness(2, 5, None), compute_fitness(2, 5, 1.0))
        self.assertAlmostEqual(
            compute_fitness(2, 5, None), compute_fitness(2, 5, -1.0))

    def test_full_evasion_beats_any_partial_at_same_score(self):
        for score in (-10.0, -0.001, 0.0, 0.001, 10.0, None):
            best = compute_fitness(0, 3, score)
            for d in range(1, 4):
                self.assertLess(compute_fitness(d, 3, score), best)

    def test_zero_scanners_edge(self):
        # Degenerate panel: only the boundary bonus remains.
        self.assertAlmostEqual(compute_fitness(0, 0, 0.0), 1.0)


class TestMultiFitness(unittest.TestCase):
    def test_graded_evasion_credit(self):
        verdicts = {"a": "malicious", "b": "malicious",
                    "c": "benign", "d": "benign"}
        partial = compute_fitness_multi(verdicts, None)
        none_evaded = compute_fitness_multi(
            {"a": "malicious", "b": "malicious",
             "c": "malicious", "d": "malicious"}, None)
        all_evaded = compute_fitness_multi(
            {"a": "benign", "b": "benign", "c": "benign", "d": "benign"}, None)
        self.assertLess(none_evaded, partial)
        self.assertLess(partial, all_evaded)

    def test_error_verdicts_penalized_not_credited(self):
        clean = compute_fitness_multi({"a": "error"}, None)
        benign = compute_fitness_multi({"a": "benign"}, None)
        self.assertLess(clean, benign)
        self.assertEqual(compute_fitness_multi({"a": "error"}, None), 0.5)

    def test_novelty_adds_linearly(self):
        base = compute_fitness_multi({"a": "malicious"}, None, novelty_score=0.0)
        novel = compute_fitness_multi({"a": "malicious"}, None, novelty_score=1.0)
        self.assertAlmostEqual(novel - base, 1.0)

    def test_boundary_symmetry_preserved(self):
        self.assertAlmostEqual(
            compute_fitness_multi({"a": "benign"}, 0.7),
            compute_fitness_multi({"a": "benign"}, -0.7))


class TestNoveltyTrackerAndGreybox(unittest.TestCase):
    def _controller(self):
        from pipeline.feedback import FeedbackController
        return FeedbackController()

    def test_first_sight_full_then_decays(self):
        from pipeline.feedback import NoveltyTracker
        nt = NoveltyTracker()
        sig = (("PROTO", "GLOBAL"), ("s1",))
        self.assertEqual(nt.score(sig), 1.0)
        self.assertEqual(nt.score(sig), 0.5)
        self.assertEqual(nt.score(sig), 1.0 / 3.0)
        self.assertEqual(nt.novel_signatures, 1)

    def test_greybox_ingestion_flags_and_tallies(self):
        fc = self._controller()
        before = fc.weights.get(("os", "system"))
        fc.update([{
            "callable": ("os", "system"),
            "fitness": 0.0, "evaded_all": False, "valid": True,
            "scanner_verdicts": {"picklescan": "malicious",
                                 "modelscan": "benign"},
            "matched_rules": ["global:os.system:dangerous"],
        }])
        self.assertEqual(fc.scanner_stats["picklescan"]["malicious"], 1)
        self.assertEqual(fc.scanner_stats["modelscan"]["benign"], 1)
        self.assertEqual(fc.flagged_callables[("os", "system")], 1)
        self.assertLess(fc.weights[("os", "system")], before)

    def test_update_without_greybox_keys_is_noop_safe(self):
        fc = self._controller()
        fc.update([{"callable": ("os", "system"),
                    "fitness": 1.0, "evaded_all": True, "valid": True}])
        self.assertEqual(fc.scanner_stats, {})
        self.assertEqual(fc.flagged_callables, {})


if __name__ == "__main__":
    unittest.main()
