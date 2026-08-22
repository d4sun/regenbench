"""Phase 2 correctness tests for pipeline/opcodes.py (T3.1).

Golden + property tests for the opcode taxonomy and the byte-stream parser,
including the parse->reconstruct round-trip invariant used by every mutator.
"""

from __future__ import annotations

import pickle
import pickletools
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.opcodes import (  # noqa: E402
    OpcodeCategory,
    OPCODES_BY_BYTE,
    OPCODES_BY_NAME,
    OpcodeClassification,
    parse_pickle,
)


def _reconstruct(parsed):
    return b"".join(op.code + arg for op, arg in parsed)


class TestTaxonomy(unittest.TestCase):
    """The taxonomy must agree with pickletools' own argument descriptors."""

    def test_expected_categories(self):
        cases = {
            "STOP": (OpcodeCategory.NO_ARG, None),
            "MARK": (OpcodeCategory.NO_ARG, None),
            "MEMOIZE": (OpcodeCategory.NO_ARG, None),
            "BINUNICODE": (OpcodeCategory.LENGTH_PREFIXED, 4),
            "SHORT_BINUNICODE": (OpcodeCategory.LENGTH_PREFIXED, 1),
            "BINUNICODE8": (OpcodeCategory.LENGTH_PREFIXED, 8),
            "BINBYTES": (OpcodeCategory.LENGTH_PREFIXED, 4),
            # FRAME reads a raw 8-byte little-endian length via uint64
            # (arg.n == 8 > 0), so it lands in FIXED_ARG, not LENGTH_PREFIXED.
            "FRAME": (OpcodeCategory.FIXED_ARG, 8),
            "BINFLOAT": (OpcodeCategory.FIXED_ARG, 8),
            "BININT": (OpcodeCategory.FIXED_ARG, 4),
            "BININT1": (OpcodeCategory.FIXED_ARG, 1),
            "GLOBAL": (OpcodeCategory.DELIMITED, None),
            "INST": (OpcodeCategory.DELIMITED, None),
        }
        for name, (cat, width) in cases.items():
            with self.subTest(name=name):
                cls = OPCODES_BY_NAME[name]
                self.assertEqual(cls.category, cat)
                self.assertEqual(cls.arg_width, width)

    def test_every_pickletools_opcode_is_indexed(self):
        for op in pickletools.opcodes:
            self.assertIn(op.code.encode("latin1"), OPCODES_BY_BYTE)
            self.assertIn(op.name, OPCODES_BY_NAME)
            self.assertIs(OPCODES_BY_BYTE[op.code.encode("latin1")],
                          OPCODES_BY_NAME[op.name])

    def test_by_byte_and_by_name_consistent(self):
        self.assertEqual(len(OPCODES_BY_BYTE), len(OPCODES_BY_NAME))
        for byte, cls in OPCODES_BY_BYTE.items():
            self.assertEqual(byte, cls.code)
            self.assertIs(OPCODES_BY_NAME[cls.name], cls)


class TestParseReconstructRoundTrip(unittest.TestCase):
    """Mutators rely on: reconstruct(parse(data)) == data for real pickles."""

    OBJECTS = [
        None, True, False, 0, -1, 127, 255, 65535, 2**40, -2**40,
        3.14159, -0.0, float("inf"),
        "", "hello world", "a" * 300, "unicode \u00e9\u4e2d",
        b"bytes\x00payload", bytearray(b"xy"),
        [], [1, 2, 3], {}, {"a": 1, "b": [1, 2]},
        {"nested": {"deep": (1, 2, ("tuple",))}},
    ]

    def test_round_trip_all_protocols(self):
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            for obj in self.OBJECTS:
                with self.subTest(proto=proto, obj=repr(obj)[:40]):
                    data = pickle.dumps(obj, protocol=proto)
                    parsed = parse_pickle(data)
                    self.assertEqual(_reconstruct(parsed), data)

    def test_final_opcode_is_stop(self):
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            parsed = parse_pickle(pickle.dumps({"k": "v"}, protocol=proto))
            self.assertEqual(parsed[-1][0].name, "STOP")

    def test_stop_with_padding_stops(self):
        data = pickle.dumps({"a": 1}) + b"\x00\r\n\t "
        parsed = parse_pickle(data)
        self.assertEqual(parsed[-1][0].name, "STOP")
        # Padding-only suffix must not be interpreted as more opcodes.
        self.assertEqual(_reconstruct(parsed), pickle.dumps({"a": 1}))

    def test_global_reads_two_delimited_fields(self):
        data = b"cos\nsystem\n(S'ls'\ntR."
        parsed = parse_pickle(data)
        glob_op, glob_arg = parsed[0]
        self.assertEqual(glob_op.name, "GLOBAL")
        self.assertEqual(glob_arg, b"os\nsystem\n")

    def test_inst_reads_two_delimited_fields(self):
        # INST's opcode letter is lowercase 'i' (uppercase 'I' is INT).
        data = b"ios\nsystem\n."
        parsed = parse_pickle(data)
        inst_op, inst_arg = parsed[0]
        self.assertEqual(inst_op.name, "INST")
        self.assertEqual(inst_arg, b"os\nsystem\n")


class TestParseErrors(unittest.TestCase):
    """Malformed streams must raise ValueError (callers fail closed)."""

    def test_unknown_opcode_byte(self):
        with self.assertRaises(ValueError):
            parse_pickle(b"\x80\x04\xff\xff\xff")

    def test_truncated_fixed_argument(self):
        # BINFLOAT ('G') requires 8 bytes; supply 3.
        with self.assertRaises(ValueError):
            parse_pickle(b"\x80\x04G\x3f\xf0\x00")

    def test_truncated_length_prefix(self):
        # BINUNICODE ('X') requires a 4-byte length; supply 1.
        with self.assertRaises(ValueError):
            parse_pickle(b"\x80\x04X\x05\x00")

    def test_length_exceeds_stream(self):
        # Declares a 100-byte unicode payload; stream ends immediately after.
        with self.assertRaises(ValueError):
            parse_pickle(b"\x80\x04Xd\x00\x00\x00abc")

    def test_missing_newline_delimiter(self):
        with self.assertRaises(ValueError):
            parse_pickle(b"\x80\x04cabcd")

    def test_global_missing_second_field(self):
        with self.assertRaises(ValueError):
            parse_pickle(b"\x80\x04cos\n.")

    def test_empty_input(self):
        self.assertEqual(parse_pickle(b""), [])


if __name__ == "__main__":
    unittest.main()
