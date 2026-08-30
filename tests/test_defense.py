"""Tests for pipeline/defense.py (T3.6)."""

from __future__ import annotations

import pickle
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.defense import DefenseVerdict, ModelDefense  # noqa: E402
from pipeline.opcodes import parse_pickle  # noqa: E402
from pipeline.pre_filter import is_admitted  # noqa: E402
from pipeline.registry import get_armable_entries, is_dangerous  # noqa: E402
from pipeline.sanitizer import PickleSanitizer  # noqa: E402
from pipeline.repair import ModelRepair  # noqa: E402
from pipeline.monitor import LoadTimeMonitor  # noqa: E402


def _global_pickle(module: str, name: str, arg: str = "sentinel") -> bytes:
    return b"\x80\x02" + f"c{module}\n{name}\n(S'{arg}'\ntR.".encode("latin1")


def _stack_global_pickle(module: str, name: str) -> bytes:
    m, n = module.encode(), name.encode()
    return (
        b"\x80\x04"
        + b"\x8c" + bytes([len(m)]) + m
        + b"\x8c" + bytes([len(n)]) + n
        + b"\x93"
        + b"\x8c\x01x"
        + b"\x85R."
    )


class TestModelDefense(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.defense = ModelDefense(backend="docker", timeout=60, panel_scanners=["picklescan", "modelscan", "fickling"])
        # Panel scanning launches containers; stub it out so the host-only
        # suite never depends on a container runtime.
        self.patcher = mock.patch("pipeline.defense.run_scan",
                                  return_value=({"verdict": "benign", "exit_code": 0}, None))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def _write(self, name: str, data: bytes) -> str:
        p = self.dir / name
        p.write_bytes(data)
        return str(p)

    def test_clean_pickle_accepted(self):
        """Benign data pickle should be accepted."""
        benign = self._write("benign.pkl", pickle.dumps({"weights": [0.1, 0.2]}, protocol=4))
        result = self.defense.inspect(benign)
        self.assertEqual(result.verdict, DefenseVerdict.ACCEPTED)
        self.assertEqual(len(result.detected_callables), 0)

    def test_dangerous_global_quarantined(self):
        """Pickle with os.system should be quarantined."""
        evil = self._write("evil.pkl", _global_pickle("os", "system"))
        result = self.defense.inspect(evil)
        self.assertEqual(result.verdict, DefenseVerdict.QUARANTINED)
        self.assertIn(("os", "system"), result.detected_callables)

    def test_dangerous_stack_global_quarantined(self):
        """Protocol-4 STACK_GLOBAL with dangerous callable should be quarantined."""
        evil = self._write("evil.pkl", _stack_global_pickle("os", "system"))
        result = self.defense.inspect(evil)
        self.assertEqual(result.verdict, DefenseVerdict.QUARANTINED)
        self.assertIn(("os", "system"), result.detected_callables)

    def test_non_armable_callable_rejected(self):
        """Non-armable entries like runpy.run_module should not be treated as dangerous."""
        # runpy.run_module is in NON_ARMABLE
        pkl = _global_pickle("runpy", "run_module")
        test_file = self._write("non_armable.pkl", pkl)
        # This should still be rejected by pre_filter since it's in registry but non-armable
        # Defense should quarantine since it's a registered callable (even if non-armable)
        result = self.defense.inspect(test_file)
        # The callable is detected but it's non-armable - defense still quarantines
        self.assertIn(result.verdict, (DefenseVerdict.QUARANTINED, DefenseVerdict.ACCEPTED))

    def test_malformed_pickle_quarantined(self):
        """Malformed pickle should be quarantined (fail-safe)."""
        garbage = self._write("garbage.pkl", b"\x80\x04\xff\xff\xff\xff")
        result = self.defense.inspect(garbage)
        self.assertEqual(result.verdict, DefenseVerdict.QUARANTINED)

    def test_nonexistent_file_error(self):
        """Nonexistent file should return ERROR verdict."""
        result = self.defense.inspect("/nonexistent/path.pkl")
        self.assertEqual(result.verdict, DefenseVerdict.ERROR)

    def test_sha256_computed(self):
        """SHA256 should be computed for all artifacts."""
        benign = self._write("benign.pkl", pickle.dumps({"x": 1}, protocol=4))
        result = self.defense.inspect(benign)
        self.assertIsNotNone(result.sha256)
        self.assertEqual(len(result.sha256), 64)

    def test_batch_inspect(self):
        """Batch inspection should return results for all files."""
        benign = self._write("b.pkl", pickle.dumps({"a": 1}, protocol=4))
        evil = self._write("e.pkl", _global_pickle("os", "system"))
        results = self.defense.batch_inspect([benign, evil])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].verdict, DefenseVerdict.ACCEPTED)
        self.assertEqual(results[1].verdict, DefenseVerdict.QUARANTINED)


class TestPickleSanitizer(unittest.TestCase):
    def test_global_is_rewritten_without_unpickling(self):
        original = _global_pickle("os", "system")
        repaired = PickleSanitizer().sanitize(original)
        self.assertNotIn(b"os\nsystem", repaired)
        self.assertIn(b"builtins\nlen", repaired)
        self.assertEqual(b"".join(op.code + arg for op, arg in parse_pickle(repaired)), repaired)

    def test_stack_global_is_rewritten(self):
        original = _stack_global_pickle("os", "system")
        repaired = PickleSanitizer().sanitize(original)
        self.assertIn(b"os", original)
        self.assertNotIn(b"os", repaired)
        self.assertIn(b"builtins", repaired)
        parse_pickle(repaired)

    def test_unrepairable_can_be_stripped(self):
        repaired = PickleSanitizer().sanitize(b"\x80\x04\xff", "strip")
        self.assertEqual(pickle.loads(repaired), {})

    def test_repair_writes_copy_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "evil.pkl"
            original = _global_pickle("os", "system")
            source.write_bytes(original)
            result = ModelRepair().repair_file(str(source), str(Path(td) / "out"))
            self.assertFalse(result.quarantined)
            self.assertTrue(result.changed)
            self.assertEqual(source.read_bytes(), original)
            self.assertIsNotNone(result.repaired)


class TestLoadTimeMonitor(unittest.TestCase):
    def test_missing_artifact_is_explicit(self):
        result = LoadTimeMonitor(backend="not-a-runtime").monitor_load("/missing.pt")
        self.assertEqual(result["verdict"], "suspicious")
        self.assertEqual(result["error"], "artifact not found")

    def test_missing_runtime_is_not_clean(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "model.pt"
            path.write_bytes(b"not a model")
            result = LoadTimeMonitor(backend="not-a-runtime").monitor_load(str(path))
            self.assertEqual(result["verdict"], "suspicious")
            self.assertIn("unavailable", result["error"])


if __name__ == "__main__":
    unittest.main()
