"""T3.1 — Port PickleFuzzer opcode categorization.

Exposes a 4-category taxonomy of pickle opcodes derived dynamically from
cpython's pickletools definitions, with helper parser routines.
"""

from __future__ import annotations

import pickletools
from enum import Enum
from typing import Any


class OpcodeCategory(Enum):
    NO_ARG = "no_arg"
    FIXED_ARG = "fixed_arg"
    LENGTH_PREFIXED = "length_prefixed"
    DELIMITED = "delimited"


class OpcodeClassification:
    def __init__(self, code: bytes, name: str, category: OpcodeCategory, arg_width: int | None, proto: int):
        self.code = code  # 1-byte bytes representation of opcode character
        self.name = name
        self.category = category
        self.arg_width = arg_width  # fixed arg width, prefix length width (1, 4, 8), or None
        self.proto = proto

    def __repr__(self) -> str:
        return f"Opcode({self.name}, {self.category.value}, width={self.arg_width}, proto={self.proto})"


# Dynamically construct the taxonomy from pickletools to support CPython's full opcode set
OPCODES_BY_BYTE: dict[bytes, OpcodeClassification] = {}
OPCODES_BY_NAME: dict[str, OpcodeClassification] = {}

for op in pickletools.opcodes:
    code_bytes = op.code.encode("latin1")
    
    if op.arg is None:
        category = OpcodeCategory.NO_ARG
        arg_width = None
    elif op.arg.n > 0:
        category = OpcodeCategory.FIXED_ARG
        arg_width = op.arg.n
    elif op.arg.n == -1:
        category = OpcodeCategory.DELIMITED
        arg_width = None
    elif op.arg.n == -2:
        category = OpcodeCategory.LENGTH_PREFIXED
        arg_width = 1
    elif op.arg.n in (-3, -4):
        category = OpcodeCategory.LENGTH_PREFIXED
        arg_width = 4
    elif op.arg.n == -5:
        category = OpcodeCategory.LENGTH_PREFIXED
        arg_width = 8
    else:
        # Fallback for unrecognized argument descriptors
        category = OpcodeCategory.DELIMITED
        arg_width = None

    classification = OpcodeClassification(
        code=code_bytes,
        name=op.name,
        category=category,
        arg_width=arg_width,
        proto=op.proto,
    )
    
    OPCODES_BY_BYTE[code_bytes] = classification
    OPCODES_BY_NAME[op.name] = classification


def parse_pickle(data: bytes) -> list[tuple[OpcodeClassification, bytes]]:
    """Parse a pickle byte stream into a list of (opcode, argument_bytes) tuples."""
    parsed = []
    i = 0
    limit = len(data)
    
    while i < limit:
        opcode_byte = data[i:i+1]
        i += 1
        if not opcode_byte:
            break
            
        if opcode_byte not in OPCODES_BY_BYTE:
            raise ValueError(f"Unknown pickle opcode byte: {opcode_byte!r} at index {i-1}")
            
        op = OPCODES_BY_BYTE[opcode_byte]
        
        if op.category == OpcodeCategory.NO_ARG:
            arg = b""
        elif op.category == OpcodeCategory.FIXED_ARG:
            assert op.arg_width is not None
            if i + op.arg_width > limit:
                raise ValueError(f"Stream ended while reading fixed argument for {op.name}")
            arg = data[i:i+op.arg_width]
            i += op.arg_width
        elif op.category == OpcodeCategory.LENGTH_PREFIXED:
            assert op.arg_width is not None
            if i + op.arg_width > limit:
                raise ValueError(f"Stream ended while reading length prefix for {op.name}")
            # Read prefix length
            prefix = data[i:i+op.arg_width]
            i += op.arg_width
            
            # Parse length
            if op.arg_width == 1:
                length = prefix[0]
            else:
                length = int.from_bytes(prefix, byteorder="little", signed=False)
                
            if i + length > limit:
                raise ValueError(f"Stream ended while reading {length} bytes payload for {op.name}")
            payload = data[i:i+length]
            i += length
            arg = prefix + payload
        elif op.category == OpcodeCategory.DELIMITED:
            # Read until newline '\n'
            idx = data.find(b"\n", i)
            if idx == -1:
                raise ValueError(f"Delimited opcode {op.name} is missing delimiter newline")
            arg = data[i:idx+1]
            i = idx + 1
            
            # Special case for GLOBAL/INST which are followed by a second newline-delimited string
            if op.name in ("GLOBAL", "INST"):
                idx2 = data.find(b"\n", i)
                if idx2 == -1:
                    raise ValueError(f"GLOBAL/INST second field is missing delimiter newline")
                arg += data[i:idx2+1]
                i = idx2 + 1
        else:
            raise ValueError(f"Unsupported category: {op.category}")
            
        parsed.append((op, arg))
        
        # Stop when we hit STOP only if the remaining data is just padding/zeros
        if op.name == "STOP":
            remaining = data[i:]
            if not remaining.strip(b"\x00\r\n\t "):
                break
            
    return parsed
