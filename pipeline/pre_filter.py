"""T4.1 — Static Pre-Filter Admission Gate.

Filters out benign/malformed candidates before dynamic container execution.
"""

from __future__ import annotations

import os
import zipfile
from pipeline.opcodes import parse_pickle
from pipeline.registry import is_dangerous

_MAX_RECURSION = 16


def _string_value(op, arg: bytes) -> str | None:
    """Extract the string pushed by a string opcode (used for STACK_GLOBAL)."""
    name = op.name
    if name == "SHORT_BINUNICODE":
        return arg[1:].decode("utf-8", "replace")
    if name == "BINUNICODE":
        return arg[4:].decode("utf-8", "replace")
    if name == "UNICODE":
        return arg.strip(b"\r\n").decode("utf-8", "replace").strip("'\"")
    if name in ("SHORT_BINSTRING", "BINSTRING"):
        return arg[1:].decode("latin1") if name == "SHORT_BINSTRING" else arg[4:].decode("latin1")
    return None


def _nested_payload(op, arg: bytes) -> bytes | None:
    """Extract raw payload bytes of length-prefixed bytes opcodes for recursion."""
    name = op.name
    if name == "SHORT_BINBYTES":
        return arg[1:]
    if name == "BINBYTES":
        return arg[4:]
    if name == "BINBYTES8":
        return arg[8:]
    return None


def _has_dangerous_import(parsed: list, depth: int = 0) -> bool:
    if depth > _MAX_RECURSION:
        return False

    n = len(parsed)
    for i, (op, arg) in enumerate(parsed):
        if op.name in ("GLOBAL", "INST"):
            parts = arg.decode("latin1").split("\n")
            if len(parts) >= 2 and is_dangerous(parts[0], parts[1]):
                return True

        # Protocol >= 4 pushes module and name as two strings then STACK_GLOBAL.
        elif op.name == "STACK_GLOBAL":
            strings = []
            for j in range(i - 1, max(-1, i - 6), -1):
                value = _string_value(parsed[j][0], parsed[j][1])
                if value is not None:
                    strings.append(value)
                    if len(strings) == 2:
                        break
            if len(strings) == 2:
                module, name = strings[1], strings[0]
                if is_dangerous(module, name):
                    return True

        # The generator/templates hide the dangerous import inside a nested
        # _pickle.loads(BINBYTES(...)) payload; descend to find it.
        payload = _nested_payload(op, arg)
        if payload is not None:
            try:
                if payload.startswith(b"\x80") or payload.startswith(b"c") or payload.startswith(b"("):
                    if _has_dangerous_import(parse_pickle(payload), depth + 1):
                        return True
            except Exception:
                continue

    return False


def is_admitted(file_path: str) -> bool:
    """Cheapest check: admits a candidate to the dynamic oracle only if it is syntactically
    valid and contains at least one dangerous import callable from the registry."""
    if not os.path.exists(file_path):
        return False

    # Magic bytes check
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False

    if not magic:
        return False

    # If it is a PyTorch checkpoint, it is a ZIP archive starting with PK\x03\x04
    is_zip = magic.startswith(b"PK\x03\x04")
    is_raw_pickle = magic[0] == 0x80

    if not (is_zip or is_raw_pickle):
        return False

    try:
        if is_zip:
            # For zip, we read the embedded data.pkl file
            with zipfile.ZipFile(file_path) as z:
                # Find the pickle payload (usually archive/data.pkl in PyTorch format)
                pkl_name = [name for name in z.namelist() if name.endswith("data.pkl")]
                if not pkl_name:
                    # An archive that cannot be interpreted is not evidence of
                    # safety; let the sandboxed oracle make the final decision.
                    return True
                pkl_bytes = z.read(pkl_name[0])
        else:
            with open(file_path, "rb") as f:
                pkl_bytes = f.read()

        parsed = parse_pickle(pkl_bytes)

        # Look for dangerous imports, including nested payloads
        if _has_dangerous_import(parsed):
            return True
    except Exception:
        # Fail-closed: a malformed/unparseable artifact must still reach the
        # dynamic oracle. Rejecting it here would silently let a crafted
        # payload bypass behavioral analysis entirely.
        return True

    return False
