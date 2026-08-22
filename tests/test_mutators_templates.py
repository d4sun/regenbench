"""Phase 2 correctness tests for pipeline/mutators.py (T3.4) and templates.py (T2.x).

Golden known-answer checks for each mutation operator and attack template,
plus the same parse->reconstruct invariant demanded of real candidates.
"""

from __future__ import annotations

import pickle
import random
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.opcodes import OpcodeCategory, OPCODES_BY_NAME, parse_pickle  # noqa: E402
from pipeline.mutators import PickleMutator  # noqa: E402
from pipeline.registry import get_entry  # noqa: E402
from pipeline.templates import (  # noqa: E402
    AttackTemplate,
    ExternalModuleTemplate,
    FAMILIES,
    FAMILY_LABELS,
    FAMILY_TEMPLATES,
    OverwrittenModuleTemplate,
    PyPIInjectedTemplate,
    family_template,
    inject_payload_into_torch,
)


def _op(name: str):
    return OPCODES_BY_NAME[name]


class TestOpcodeSwap(unittest.TestCase):
    def setUp(self):
        self.m = PickleMutator()
        random.seed(20260822)

    def test_only_value_ops_are_swappable(self):
        # Container/build ops must pass through untouched.
        passthrough = ["EMPTY_LIST", "EMPTY_DICT", "APPEND", "SETITEMS",
                       "MARK", "REDUCE", "BINUNICODE"]
        for name in passthrough:
            op = _op(name)
            arg = b"\x04\x00\x00\x00abcd"
            with self.subTest(name=name):
                self.assertIs(self.m.mutate_opcode_swap(op, arg)[0], op)

    def test_value_op_swaps_stay_in_equivalence_class(self):
        equivalents = {
            "NONE": {"NEWTRUE", "NEWFALSE"},
            "NEWTRUE": {"NONE", "NEWFALSE"},
            "NEWFALSE": {"NONE", "NEWTRUE"},
        }
        for name, others in equivalents.items():
            seen = set()
            for seed in range(30):
                random.seed(seed)
                new_op, new_arg = self.m.mutate_opcode_swap(_op(name), b"")
                self.assertIn(new_op.name, others)
                self.assertEqual(new_arg, b"")
                seen.add(new_op.name)
            # With 30 seeds both alternatives must occur.
            self.assertEqual(seen, others, name)


class TestCallableSubstitution(unittest.TestCase):
    def setUp(self):
        self.m = PickleMutator()

    def test_global_target_is_replaced_by_registry_entry(self):
        op = _op("GLOBAL")
        new_op, new_arg = self.m.mutate_callable_substitution(op, b"os\nsystem\n")
        self.assertIs(new_op, op)
        parts = new_arg.decode("latin1").split("\n")
        entry = get_entry(parts[0], parts[1])
        self.assertIsNotNone(entry, f"{parts!r} not in registry")

    def test_inst_is_also_substituted(self):
        op = _op("INST")
        _, new_arg = self.m.mutate_callable_substitution(op, b"os\nsystem\n")
        self.assertTrue(new_arg.endswith(b"\n"))

    def test_non_global_ops_untouched(self):
        op = _op("BINUNICODE")
        arg = b"\x04\x00\x00\x00test"
        self.assertEqual(self.m.mutate_callable_substitution(op, arg), (op, arg))


class TestArgumentFuzz(unittest.TestCase):
    def setUp(self):
        self.m = PickleMutator()

    def test_binfloat_stays_8_bytes_big_endian(self):
        op = _op("BINFLOAT")
        val = struct.unpack(">d", self.m.mutate_argument_fuzz(op, b"\x00" * 8))
        self.assertEqual(len(val[0].hex()) > 0, True)
        self.assertIn(val[0], [float(x) for x in self.m.sample_floats])

    def test_binint_stays_4_bytes_little_endian(self):
        op = _op("BININT")
        raw = self.m.mutate_argument_fuzz(op, b"\x01\x00\x00\x00")
        self.assertEqual(len(raw), 4)
        self.assertEqual(struct.unpack("<i", raw)[0], raw and int.from_bytes(raw, "little", signed=True))

    def test_binint1_single_byte(self):
        op = _op("BININT1")
        raw = self.m.mutate_argument_fuzz(op, b"\x07")
        self.assertEqual(len(raw), 1)
        self.assertLessEqual(raw[0], 255)

    def test_short_binunicode_prefix_matches_payload(self):
        op = _op("SHORT_BINUNICODE")
        raw = self.m.mutate_argument_fuzz(op, b"\x03abc")
        length = raw[0]
        self.assertEqual(length, len(raw) - 1)
        self.assertLessEqual(length, 255)
        raw.decode  # payload must be valid to decode downstream
        raw[1:].decode("utf-8")

    def test_binunicode_length_prefix_consistent(self):
        op = _op("BINUNICODE")
        raw = self.m.mutate_argument_fuzz(op, b"\x03\x00\x00\x00abc")
        declared = struct.unpack("<I", raw[:4])[0]
        self.assertEqual(declared, len(raw) - 4)

    def test_no_arg_op_yields_empty(self):
        op = _op("MEMOIZE")
        self.assertEqual(self.m.mutate_argument_fuzz(op, b""), b"")

    def test_delimited_global_defers_to_substitution(self):
        op = _op("GLOBAL")
        arg = b"os\nsystem\n"
        self.assertEqual(self.m.mutate_argument_fuzz(op, arg), arg)


class TestStructuralStackingAndMutate(unittest.TestCase):
    def setUp(self):
        self.m = PickleMutator()

    def test_stacking_appends_valid_independent_stream(self):
        base = pickle.dumps({"model": [1, 2]}, protocol=4)
        stacked = self.m.mutate_structural_stacking(base)
        self.assertTrue(stacked.startswith(base))
        extra = stacked[len(base):]
        self.assertEqual(pickle.loads(extra), {"fuzzed_stack_payload": True})

    def test_mutate_output_round_trips_through_parser(self):
        random.seed(7)
        base = pickle.dumps({"weights": [0.5], "meta": "benign"}, protocol=4)
        out = self.m.mutate(base)
        parsed = parse_pickle(out)
        self.assertEqual(parsed[-1][0].name, "STOP")
        self.assertEqual(b"".join(op.code + arg for op, arg in parsed), out)

    def test_mutate_with_zero_probs_is_identity(self):
        base = pickle.dumps({"a": 1}, protocol=4)
        self.assertEqual(self.m.mutate(base, 0, 0, 0, 0), base)


class TestPayloadTemplates(unittest.TestCase):
    SENTINEL = "__regenbench_sentinel__"

    def test_generate_payload_known_answer_bytes(self):
        from pipeline.templates import _generate_payload
        expected = (
            b"cos\nsystem\n"
            + pickle.dumps(("echo hi",), protocol=2)[2:-1]
            + b"R."
        )
        self.assertEqual(
            _generate_payload("os", "system", ("echo hi",)), expected)

    def _assert_parses_and_contains(self, blob: bytes, *needles: bytes):
        parsed = parse_pickle(blob)
        self.assertEqual(parsed[-1][0].name, "STOP")
        for needle in needles:
            self.assertIn(needle, blob)

    def test_pypi_template_structure(self):
        blob = PyPIInjectedTemplate().generate_pickle_payload(self.SENTINEL)
        self._assert_parses_and_contains(
            blob,
            b"IPython.utils.process\nsystem\n",
            b"python3 -c",
            self.SENTINEL.encode(),
        )

    def test_pypi_template_custom_sink(self):
        blob = PyPIInjectedTemplate("somepkg.mod", "runner").generate_pickle_payload(self.SENTINEL)
        self._assert_parses_and_contains(blob, b"somepkg.mod\nrunner\n")

    def test_external_template_runstring_args(self):
        blob = ExternalModuleTemplate().generate_pickle_payload(self.SENTINEL)
        self._assert_parses_and_contains(
            blob,
            b"numpy.testing._private.utils\nrunstring\n",
            self.SENTINEL.encode(),
        )
        # runstring sinks receive (code, {}) -- the empty dict literal.
        self.assertIn(b"}", blob)

    def test_overwritten_template_two_stage_structure(self):
        t = OverwrittenModuleTemplate()  # collections.OrderedDict
        blob = t.generate_pickle_payload(self.SENTINEL)
        parsed = parse_pickle(blob)
        globals_seen = [arg for op, arg in parsed if op.name == "GLOBAL"]
        self.assertEqual(len(globals_seen), 2)
        self.assertEqual(globals_seen[0], b"builtins\nexec\n")
        self.assertEqual(globals_seen[1], b"collections\nOrderedDict\n")
        self.assertIn(self.SENTINEL.encode(), blob)
        # Stage 1 installs the shadow module via exec(setup, {}): protocol-2
        # encodes the empty dict as the single EMPTY_DICT ('}') opcode.
        self.assertIn(b"}", blob)

    def test_overwritten_module_code_binds_real_class_early(self):
        src = OverwrittenModuleTemplate().generate_module_code()
        self.assertIn("_real_collections.OrderedDict", src)
        self.assertIn("_ShadowOrderedDict", src)
        self.assertIn("sys.modules['collections']", src.replace('"collections"', "'collections'"))

    def test_family_registry_shape(self):
        self.assertEqual(FAMILIES, ("gadget", "overwritten", "pypi_injected", "external"))
        self.assertIsNone(family_template("gadget"))
        for fam in ("overwritten", "pypi_injected", "external"):
            self.assertIsInstance(family_template(fam), AttackTemplate)
        self.assertEqual(set(FAMILY_LABELS), set(FAMILIES))
        self.assertEqual(set(FAMILY_TEMPLATES), set(FAMILIES) - {"gadget"})


class TestInjectIntoTorch(unittest.TestCase):
    """Golden test for the data.pkl surgery incl. the FRAME length rewrite."""

    def _make_pt(self, path: Path, proto: int) -> None:
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("archive/version", b"3")
            z.writestr("archive/data.pkl",
                       pickle.dumps({"weight": [0.1]}, protocol=proto))

    def _read_data_pkl(self, path: Path) -> bytes:
        with zipfile.ZipFile(path) as z:
            return z.read("archive/data.pkl")

    def test_injection_proto2_appends_loads_call_before_stop(self):
        with tempfile.TemporaryDirectory() as d:
            benign = Path(d) / "b.pt"
            evil = Path(d) / "e.pt"
            self._make_pt(benign, 2)
            payload = _generate = PyPIInjectedTemplate().generate_pickle_payload("touch_marker")
            inject_payload_into_torch(str(benign), str(evil), _generate)
            data = self._read_data_pkl(evil)
            self.assertTrue(data.endswith(b"."))
            self.assertIn(b"c_pickle\nloads\n", data)
            self.assertIn(payload[:20], data)
            # Original content preserved ahead of the injection.
            orig = self._read_data_pkl(benign)
            self.assertTrue(data.startswith(orig[:-1]))

    def test_injection_proto4_rewrites_frame_length(self):
        with tempfile.TemporaryDirectory() as d:
            benign = Path(d) / "b4.pt"
            evil = Path(d) / "e4.pt"
            self._make_pt(benign, 4)
            payload = b"\x80\x02N."
            inject_payload_into_torch(str(benign), str(evil), payload)
            data = self._read_data_pkl(evil)
            self.assertEqual(data[0], 0x80)
            self.assertEqual(data[2], 0x95)  # FRAME
            declared = struct.unpack("<Q", data[3:11])[0]
            self.assertEqual(declared, len(data) - 11)
            # The repaired stream must still parse cleanly.
            parsed = parse_pickle(data)
            self.assertEqual(parsed[-1][0].name, "STOP")


if __name__ == "__main__":
    unittest.main()
