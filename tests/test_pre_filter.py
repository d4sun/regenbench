"""Phase 2 correctness tests for pipeline/pre_filter.py (T4.1).

The admission gate must admit candidates that arm a registry callable
(GLOBAL, INST, or protocol-4 STACK_GLOBAL forms), reject benign imports,
descend into nested _pickle.loads(BINBYTES(...)) payloads, extract the
pickle from PyTorch zip checkpoints, and FAIL OPEN (admit) on malformed
bytes so crafted payloads cannot skip dynamic analysis.
"""

from __future__ import annotations

import pickle
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.opcodes import parse_pickle  # noqa: E402
from pipeline.pre_filter import is_admitted, _has_dangerous_import  # noqa: E402
from pipeline.registry import get_entry, is_dangerous  # noqa: E402


def _global_pickle(module: str, name: str, arg: str = "sentinel") -> bytes:
    """Artifact-shaped raw pickle: \\x80 PROTO header + protocol-0 GLOBAL reduce.

    Real candidates always start with the PROTO magic (or are zip archives),
    so fixtures must too -- otherwise the admission gate's magic-bytes check
    rejects them before any parsing happens.
    """
    return b"\x80\x02" + f"c{module}\n{name}\n(S'{arg}'\ntR.".encode("latin1")


def _stack_global_pickle(module: str, name: str) -> bytes:
    """Protocol-4 style: two SHORT_BINUNICODE pushes + STACK_GLOBAL + REDUCE."""
    m, n = module.encode(), name.encode()
    return (
        b"\x80\x04"
        + b"\x8c" + bytes([len(m)]) + m
        + b"\x8c" + bytes([len(n)]) + n
        + b"\x93"          # STACK_GLOBAL
        + b"\x8c\x01x"     # SHORT_BINUNICODE "x"
        + b"\x85R."        # TUPLE1 REDUCE STOP
    )


def _loads_wrap(inner: bytes) -> bytes:
    """Wrap ``inner`` in GLOBAL(_pickle, loads)(BINBYTES(inner)).

    Uses 'B' (BINBYTES, 4-byte LE length) -- NOT 'C', which is
    SHORT_BINBYTES with a single-byte length.
    """
    return (
        b"\x80\x05"
        + b"c_pickle\nloads\n"
        + b"B" + struct.pack("<I", len(inner)) + inner
        + b"\x85R."
    )


class TestRegistryAssumptions(unittest.TestCase):
    def test_fixture_callables_are_classified_as_expected(self):
        self.assertTrue(is_dangerous("os", "system"))
        self.assertFalse(is_dangerous("math", "sqrt"))
        self.assertIsNotNone(get_entry("os", "system"))


class TestAdmissionGate(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _write(self, name: str, data: bytes) -> str:
        p = self.dir / name
        p.write_bytes(data)
        return str(p)

    # -- admitted: dangerous import in each opcode form ------------------

    def test_admits_dangerous_global(self):
        self.assertTrue(is_admitted(
            self._write("g.pkl", _global_pickle("os", "system"))))

    def test_admits_dangerous_inst(self):
        # INST's opcode letter is lowercase 'i' ('I' is INT); PROTO magic first.
        self.assertTrue(is_admitted(
            self._write("i.pkl", b"\x80\x02ios\nsystem\n(S'x'\ntR.")))

    def test_admits_dangerous_stack_global(self):
        self.assertTrue(is_admitted(
            self._write("s.pkl", _stack_global_pickle("os", "system"))))

    def test_admits_nested_payload_in_binbytes(self):
        outer = _loads_wrap(_global_pickle("os", "system"))
        self.assertTrue(is_admitted(self._write("nested.pkl", outer)))

    # -- rejected: benign / non-armable content --------------------------

    def test_rejects_benign_global(self):
        self.assertFalse(is_admitted(
            self._write("b.pkl", _global_pickle("math", "sqrt"))))

    def test_rejects_benign_builtins_reduce(self):
        self.assertFalse(is_admitted(
            self._write("bb.pkl", _global_pickle("builtins", "print"))))

    def test_rejects_plain_data_pickle(self):
        self.assertFalse(is_admitted(
            self._write("plain.pkl",
                        pickle.dumps({"weights": [0.1, 0.2]}, protocol=4))))

    # -- fail-open behaviour ---------------------------------------------

    def test_malformed_bytes_fail_open_to_dynamic_oracle(self):
        # Starts with the raw-pickle magic but is unparseable garbage:
        # it MUST be admitted so the container can judge it.
        self.assertTrue(is_admitted(self._write("garbage.pkl", b"\x80\x04\xff\xff\xff\xff")))
        self.assertTrue(is_admitted(self._write("trunc.pkl", b"\x80\x04X\x64\x00\x00\x00ab")))

    # -- magic-byte gate ---------------------------------------------------

    def test_nonexistent_path_rejected(self):
        self.assertFalse(is_admitted(str(self.dir / "missing.pkl")))

    def test_empty_file_rejected(self):
        self.assertFalse(is_admitted(self._write("empty.pkl", b"")))

    def test_text_file_without_magic_rejected(self):
        self.assertFalse(is_admitted(self._write("notes.txt", b"# not a pickle\n")))

    def test_directory_path_rejected(self):
        self.assertFalse(is_admitted(str(self.dir)))


class TestTorchZipHandling(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_zip_with_dangerous_data_pkl_admitted(self):
        pt = self.dir / "evil.pt"
        with zipfile.ZipFile(pt, "w") as z:
            z.writestr("archive/data.pkl", _global_pickle("os", "system"))
            z.writestr("archive/version", b"3")
        self.assertTrue(is_admitted(str(pt)))

    def test_zip_with_benign_data_pkl_rejected(self):
        pt = self.dir / "good.pt"
        with zipfile.ZipFile(pt, "w") as z:
            z.writestr("archive/data.pkl",
                       pickle.dumps({"state": [1.0]}, protocol=2))
        self.assertFalse(is_admitted(str(pt)))

    def test_zip_without_data_pkl_rejected(self):
        pt = self.dir / "nozip.pt"
        with zipfile.ZipFile(pt, "w") as z:
            z.writestr("readme.txt", "hello")
        self.assertFalse(is_admitted(str(pt)))


class TestNestedPayloadRecursion(unittest.TestCase):
    """Unit-level checks of _has_dangerous_import recursion guards."""

    def test_recursion_depth_cap_does_not_crash(self):
        # Build 20 nested layers; cap is 16 so deep descent gives up safely.
        inner = _global_pickle("os", "system")
        for _ in range(20):
            inner = _loads_wrap(inner)
        parsed = parse_pickle(inner)
        # Either found at shallow depth or capped out; must not raise.
        self.assertIsInstance(_has_dangerous_import(parsed), bool)

    def test_unparseable_nested_payload_is_ignored_not_fatal(self):
        # Starts with PROTO magic (so recursion descends) but the body is
        # an unknown opcode byte -- parse_pickle raises inside the nested
        # call, which must be swallowed, not propagated.
        outer = _loads_wrap(b"\x80\x04\xff")
        parsed = parse_pickle(outer)
        self.assertFalse(_has_dangerous_import(parsed))


if __name__ == "__main__":
    unittest.main()
