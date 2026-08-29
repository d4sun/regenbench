"""Determinism of the parallel candidate generation path.

ProcessPoolExecutor workers fork and inherit the parent's module-level
``random`` state at fork time, so without an explicit reseed the generated
bytes depend on worker scheduling -- the same command can produce different
candidates on different runs. The campaign reseeds each worker from a
per-candidate seed derived from (campaign seed, round, index), making
candidate bytes a pure function of their position.
"""

from __future__ import annotations

import hashlib
import os
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _payload_sha(pt_bytes: bytes) -> str:
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(pt_bytes)) as z:
        pkl_name = [n for n in z.namelist() if n.endswith("data.pkl")][0]
        return hashlib.sha256(z.read(pkl_name)).hexdigest()


class TestCandidateRngSeed(unittest.TestCase):
    def test_deterministic_per_slot(self):
        from scripts.run_fuzzing_campaign import _candidate_rng_seed
        self.assertEqual(_candidate_rng_seed(777, 1, 0),
                         _candidate_rng_seed(777, 1, 0))
        self.assertNotEqual(_candidate_rng_seed(777, 1, 0),
                            _candidate_rng_seed(777, 1, 1))
        self.assertNotEqual(_candidate_rng_seed(777, 1, 0),
                            _candidate_rng_seed(778, 1, 0))
        self.assertNotEqual(_candidate_rng_seed(777, 1, 0),
                            _candidate_rng_seed(777, 2, 0))

    def test_unseeded_returns_none(self):
        from scripts.run_fuzzing_campaign import _candidate_rng_seed
        self.assertIsNone(_candidate_rng_seed(None, 1, 0))


class TestGenerateCandidateWorkerDeterminism(unittest.TestCase):
    """Same seed -> identical candidate payloads; distinct seeds -> distinct.

    Runs in-process, so it also guards against the reseed being lost when the
    worker runs under ProcessPoolExecutor (which forks and re-imports).
    """

    _BENIGN = None

    @classmethod
    def setUpClass(cls):
        base = Path("ci/corpus/torch/benign/benign.pt")
        if base.exists():
            cls._BENIGN = base.read_bytes()

    def test_same_seed_same_bytes(self):
        if self._BENIGN is None:
            self.skipTest("benign base checkpoint missing")
        from scripts.run_fuzzing_campaign import (
            _candidate_rng_seed, _generate_candidate_worker,
        )
        seed = _candidate_rng_seed(777, 1, 3)
        a = _generate_candidate_worker(
            self._BENIGN, "x=1", None, "gadget", ["stack_global_encoding"],
            "splice", True, 0.15, 0.05, 0.0, 0.05, 0.05, 0.0, 0.0, seed)
        b = _generate_candidate_worker(
            self._BENIGN, "x=1", None, "gadget", ["stack_global_encoding"],
            "splice", True, 0.15, 0.05, 0.0, 0.05, 0.05, 0.0, 0.0, seed)
        self.assertEqual(_payload_sha(a), _payload_sha(b))

    def test_distinct_seed_distinct_bytes(self):
        if self._BENIGN is None:
            self.skipTest("benign base checkpoint missing")
        from scripts.run_fuzzing_campaign import (
            _candidate_rng_seed, _generate_candidate_worker,
        )
        s1 = _candidate_rng_seed(777, 1, 0)
        s2 = _candidate_rng_seed(777, 1, 1)
        a = _generate_candidate_worker(
            self._BENIGN, "x=1", None, "gadget", ["stack_global_encoding"],
            "splice", True, 0.15, 0.05, 0.0, 0.05, 0.05, 0.0, 0.0, s1)
        b = _generate_candidate_worker(
            self._BENIGN, "x=1", None, "gadget", ["stack_global_encoding"],
            "splice", True, 0.15, 0.05, 0.0, 0.05, 0.05, 0.0, 0.0, s2)
        self.assertNotEqual(_payload_sha(a), _payload_sha(b))

    def test_none_seed_keeps_legacy_fork_inherit(self):
        # A None seed must not crash the worker; it simply inherits the
        # current (seeded or not) module RNG.
        from scripts.run_fuzzing_campaign import _generate_candidate_worker
        out = _generate_candidate_worker(
            self._BENIGN or b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.",
            "x=1", None, "gadget", [], "splice",
            True, 0.15, 0.05, 0.0, 0.05, 0.05, 0.0, 0.0, None)
        self.assertIsInstance(out, bytes)


if __name__ == "__main__":
    unittest.main()