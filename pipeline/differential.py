"""RQ1 Cross-Parser Disagreement Generation (Phase 3a).

Generates pickle variants that parse differently between the standard
pickle parser and cloudpickle, exposing parser-specific behaviors
that can be weaponized for scanner evasion.

Wired behind ``CandidateGenerator(differential_prob=0.0)`` — default 0.0
(de-scoped from the headline 973-valid campaign in favor of coverage-guided
mutation; see
``reference/baseline_snapshot/results-20260818-141227/comparison-methodology.md``
and ``pipeline/generator.py:427``). Enable with ``--differential-prob 0.1``
for RQ1 novelty experiments; unit-exercised but not the dominant signal.
"""

from __future__ import annotations

import pickle
import pickletools
from typing import Callable

from pipeline.opcodes import parse_pickle


def _cloudpickle_loads(data: bytes):
    """Try to load with cloudpickle, fall back to standard pickle."""
    try:
        import cloudpickle
        return cloudpickle.loads(data)
    except ImportError:
        return pickle.loads(data)


def _pickle_loads(data: bytes):
    return pickle.loads(data)


def disagreement(
    pkl_bytes: bytes,
    parsers: tuple[Callable[[bytes], Any], Callable[[bytes], Any]] = (_pickle_loads, _cloudpickle_loads)
) -> tuple[bool, Any, Any] | None:
    """Check if two parsers produce different results on the same pickle bytes.

    Returns:
        - None if both parse successfully and produce equivalent results
        - (True, result1, result2) if they differ
        - (False, exc1, exc2) if one/both raise exceptions
    """
    try:
        r1 = parsers[0](pkl_bytes)
    except Exception as e1:
        r1 = e1

    try:
        r2 = parsers[1](pkl_bytes)
    except Exception as e2:
        r2 = e2

    if isinstance(r1, Exception) and isinstance(r2, Exception):
        return None  # both error - no disagreement

    if isinstance(r1, Exception) or isinstance(r2, Exception):
        return (False, r1, r2)  # one errors, other succeeds

    # Compare results - for dict-like objects, compare keys/values
    if isinstance(r1, dict) and isinstance(r2, dict):
        if r1.keys() != r2.keys():
            return (True, r1, r2)
        for k in r1:
            if r1[k] != r2[k]:
                return (True, r1, r2)
        return None  # equivalent dicts

    if r1 != r2:
        return (True, r1, r2)

    return None


def differential_mutate(
    pkl_bytes: bytes,
    parsers: tuple[Callable[[bytes], Any], Callable[[bytes], Any]] = (_pickle_loads, _cloudpickle_loads),
    max_mutations: int = 100
) -> list[bytes]:
    """Return pickle variants that parse differently between parsers.

    Strategy: iterate through parsed opcodes and apply targeted mutations
    known to trigger parser differences:
    - Protocol version changes (PROTO opcode)
    - Opcode encoding variations (SHORT_BINUNICODE vs BINUNICODE vs UNICODE)
    - MEMOIZE placement differences
    - FRAME vs non-FRAME streams
    - STACK_GLOBAL vs GLOBAL/INST
    """
    variants = []
    parsed = parse_pickle(pkl_bytes)

    # Mutation 1: Toggle protocol version (PROTO opcode)
    proto_idx = next((i for i, (op, _) in enumerate(parsed) if op.name == "PROTO"), None)
    if proto_idx is not None:
        op, arg = parsed[proto_idx]
        current_proto = arg[0] if arg else 0
        for new_proto in range(4):
            if new_proto != current_proto:
                new_arg = bytes([new_proto])
                mutated = _reconstruct(parsed, proto_idx, new_arg)
                if _has_disagreement(mutated, parsers):
                    variants.append(mutated)

    # Mutation 2: String encoding variations
    for i, (op, arg) in enumerate(parsed):
        if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING", "BINSTRING"):
            # Try different string encodings
            new_args = _string_encoding_variants(op, arg)
            for new_arg in new_args:
                mutated = _reconstruct(parsed, i, new_arg)
                if _has_disagreement(mutated, parsers):
                    variants.append(mutated)

    # Mutation 3: GLOBAL vs STACK_GLOBAL interchange
    for i, (op, arg) in enumerate(parsed):
        if op.name == "GLOBAL":
            # Convert to STACK_GLOBAL pattern: push module, push name, STACK_GLOBAL
            new_bytes = _global_to_stack_global(parsed, i)
            if _has_disagreement(new_bytes, parsers):
                variants.append(new_bytes)
        elif op.name == "STACK_GLOBAL":
            # Convert to GLOBAL
            new_bytes = _stack_global_to_global(parsed, i)
            if _has_disagreement(new_bytes, parsers):
                variants.append(new_bytes)

    # Mutation 4: Add/remove FRAME opcodes (protocol 4+)
    frame_idx = next((i for i, (op, _) in enumerate(parsed) if op.name == "FRAME"), None)
    if frame_idx is None:
        # Try adding FRAME
        mutated = _add_frame_opcode(parsed)
        if _has_disagreement(mutated, parsers):
            variants.append(mutated)
    else:
        # Try removing FRAME
        mutated = _remove_frame_opcode(parsed, frame_idx)
        if _has_disagreement(mutated, parsers):
            variants.append(mutated)

    # Mutation 5: MEMOIZE placement
    for i, (op, arg) in enumerate(parsed):
        if op.name == "MEMOIZE":
            # Try removing this MEMOIZE
            mutated = _reconstruct(parsed, i, b"", remove=True)
            if _has_disagreement(mutated, parsers):
                variants.append(mutated)
            break  # only try first MEMOIZE

    return variants[:max_mutations]


def _reconstruct(parsed: list, idx: int, new_arg: bytes, remove: bool = False) -> bytes:
    """Reconstruct pickle bytes with one opcode's argument changed/removed."""
    if remove:
        return b"".join(op.code + arg for j, (op, arg) in enumerate(parsed) if j != idx)
    return b"".join(
        (op.code + new_arg) if j == idx else (op.code + arg)
        for j, (op, arg) in enumerate(parsed)
    )


def _string_encoding_variants(op, arg: bytes) -> list[bytes]:
    """Generate alternative string encodings for the same string value."""
    from pipeline.opcodes import OPCODES_BY_NAME

    if op.name == "SHORT_BINUNICODE":
        s = arg[1:].decode("utf-8", "replace")
        variants = []
        # Try BINUNICODE (4-byte length)
        if len(s) <= 0xFFFFFFFF:
            variants.append(OPCODES_BY_NAME["BINUNICODE"].code + len(s).to_bytes(4, "little") + s.encode("utf-8"))
        # Try UNICODE (newline-delimited)
        variants.append(OPCODES_BY_NAME["UNICODE"].code + s.encode("utf-8") + b"\n")
        return variants

    if op.name == "BINUNICODE":
        s = arg[4:].decode("utf-8", "replace")
        variants = []
        if len(s) <= 255:
            variants.append(OPCODES_BY_NAME["SHORT_BINUNICODE"].code + bytes([len(s)]) + s.encode("utf-8"))
        variants.append(OPCODES_BY_NAME["UNICODE"].code + s.encode("utf-8") + b"\n")
        return variants

    if op.name == "UNICODE":
        s = arg.strip(b"\r\n").decode("utf-8", "replace")
        variants = []
        if len(s) <= 255:
            variants.append(OPCODES_BY_NAME["SHORT_BINUNICODE"].code + bytes([len(s)]) + s.encode("utf-8"))
        if len(s) <= 0xFFFFFFFF:
            variants.append(OPCODES_BY_NAME["BINUNICODE"].code + len(s).to_bytes(4, "little") + s.encode("utf-8"))
        return variants

    if op.name in ("SHORT_BINSTRING", "BINSTRING"):
        is_short = op.name == "SHORT_BINSTRING"
        s = arg[1:] if is_short else arg[4:]
        variants = []
        if is_short:
            if len(s) <= 0xFFFFFFFF:
                variants.append(OPCODES_BY_NAME["BINSTRING"].code + len(s).to_bytes(4, "little") + s)
        else:
            if len(s) <= 255:
                variants.append(OPCODES_BY_NAME["SHORT_BINSTRING"].code + bytes([len(s)]) + s)
        return variants

    return []


def _global_to_stack_global(parsed: list, idx: int) -> bytes:
    """Convert GLOBAL module\nname\n to STACK_GLOBAL pattern."""
    from pipeline.opcodes import OPCODES_BY_NAME
    op, arg = parsed[idx]
    parts = arg.decode("latin1").split("\n")
    if len(parts) < 2:
        return b"".join(op.code + arg for op, arg in parsed)
    module, name = parts[0], parts[1]

    # Build: push module (SHORT_BINUNICODE), push name (SHORT_BINUNICODE), STACK_GLOBAL
    new_parts = []
    for j, (o, a) in enumerate(parsed):
        if j == idx:
            new_parts.append(OPCODES_BY_NAME["SHORT_BINUNICODE"].code + bytes([len(module)]) + module.encode("utf-8"))
            new_parts.append(OPCODES_BY_NAME["SHORT_BINUNICODE"].code + bytes([len(name)]) + name.encode("utf-8"))
            new_parts.append(OPCODES_BY_NAME["STACK_GLOBAL"].code)
        else:
            new_parts.append(o.code + a)
    return b"".join(new_parts)


def _stack_global_to_global(parsed: list, idx: int) -> bytes:
    """Convert STACK_GLOBAL (preceded by two strings) to GLOBAL."""
    from pipeline.opcodes import OPCODES_BY_NAME
    # Find the two string pushes before STACK_GLOBAL
    strings = []
    for j in range(idx - 1, max(-1, idx - 5), -1):
        o, a = parsed[j]
        if o.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING", "BINSTRING"):
            if o.name == "SHORT_BINUNICODE":
                strings.append(a[1:].decode("utf-8", "replace"))
            elif o.name == "BINUNICODE":
                strings.append(a[4:].decode("utf-8", "replace"))
            elif o.name == "UNICODE":
                strings.append(a.strip(b"\r\n").decode("utf-8", "replace"))
            if len(strings) == 2:
                break
    if len(strings) != 2:
        return b"".join(op.code + arg for op, arg in parsed)
    module, name = strings[1], strings[0]  # reversed order

    new_parts = []
    skip = set()
    for j in range(idx - 1, max(-1, idx - 5), -1):
        o, a = parsed[j]
        if o.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING", "BINSTRING"):
            skip.add(j)

    for j, (o, a) in enumerate(parsed):
        if j in skip:
            continue
        if j == idx:
            new_parts.append(OPCODES_BY_NAME["GLOBAL"].code + f"{module}\n{name}\n".encode("latin1"))
        else:
            new_parts.append(o.code + a)
    return b"".join(new_parts)


def _add_frame_opcode(parsed: list) -> bytes:
    """Add FRAME opcode at start (protocol 4)."""
    from pipeline.opcodes import OPCODES_BY_NAME
    body = b"".join(op.code + arg for op, arg in parsed)
    frame_len = len(body).to_bytes(8, "little")
    return OPCODES_BY_NAME["PROTO"].code + b"\x04" + OPCODES_BY_NAME["FRAME"].code + frame_len + body


def _remove_frame_opcode(parsed: list, idx: int) -> bytes:
    """Remove FRAME opcode and downgrade protocol."""
    from pipeline.opcodes import OPCODES_BY_NAME
    new_parts = []
    for j, (op, arg) in enumerate(parsed):
        if j == idx:
            continue
        if op.name == "PROTO" and arg and arg[0] >= 4:
            # Downgrade to protocol 3
            new_parts.append(OPCODES_BY_NAME["PROTO"].code + b"\x03")
        else:
            new_parts.append(op.code + arg)
    return b"".join(new_parts)


def _has_disagreement(pkl_bytes: bytes, parsers: tuple) -> bool:
    """Quick check if pickle bytes cause parser disagreement."""
    return disagreement(pkl_bytes, parsers) is not None