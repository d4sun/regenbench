"""T3.4 — Implement Mutation Operators.

Provides mutators for opcode swapping, dangerous callable substitution,
argument fuzzing, and structural stacking on pickle byte streams.
"""

from __future__ import annotations

import pickle
import random
import struct
from typing import Any

from pipeline.opcodes import parse_pickle, OPCODES_BY_BYTE, OPCODES_BY_NAME, OpcodeCategory, OpcodeClassification
from pipeline.registry import get_all_entries


class PickleMutator:
    """Implements PickleFuzzer / coverage-guided style mutation operators on pickle streams."""

    def __init__(self):
        self.sample_strings = ["benign", "fuzzed", "", "A" * 10, "A" * 256, "127.0.0.1", "localhost"]
        self.sample_ints = [0, 1, -1, 127, 255, 32767, 65535, 2147483647, -2147483648]
        self.sample_floats = [0.0, 1.0, -1.0, 3.14159, 1e-5, float("inf"), float("-inf"), float("nan")]

    def mutate_opcode_swap(self, op: OpcodeClassification, arg: bytes) -> tuple[OpcodeClassification, bytes]:
        """Swap an opcode for an equivalent one in the same category/stack behavior."""
        if op.category == OpcodeCategory.NO_ARG:
            equivalents = {
                "NONE": ["NEWTRUE", "NEWFALSE"],
                "NEWTRUE": ["NONE", "NEWFALSE"],
                "NEWFALSE": ["NONE", "NEWTRUE"],
                "EMPTY_LIST": ["EMPTY_TUPLE", "EMPTY_DICT", "EMPTY_SET"],
                "EMPTY_TUPLE": ["EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET"],
                "EMPTY_DICT": ["EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_SET"],
                "EMPTY_SET": ["EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_DICT"],
                "APPEND": ["SETITEM"],
                "SETITEM": ["APPEND"],
            }
            if op.name in equivalents:
                new_name = random.choice(equivalents[op.name])
                if new_name in OPCODES_BY_NAME:
                    return OPCODES_BY_NAME[new_name], b""
        return op, arg

    def mutate_callable_substitution(self, op: OpcodeClassification, arg: bytes) -> tuple[OpcodeClassification, bytes]:
        """Substitute a GLOBAL/INST import callable with another from the registry."""
        if op.name in ("GLOBAL", "INST"):
            try:
                parts = arg.decode("latin1").split("\n")
                if len(parts) >= 2:
                    # Select a new dangerous callable from our registry
                    entries = get_all_entries()
                    if entries:
                        entry = random.choice(entries)
                        new_arg = f"{entry.module}\n{entry.name}\n".encode("latin1")
                        return op, new_arg
            except Exception:
                pass
        return op, arg

    def mutate_argument_fuzz(self, op: OpcodeClassification, arg: bytes) -> bytes:
        """Fuzz structural arguments (integers, floats, strings) to boundaries."""
        if op.category == OpcodeCategory.NO_ARG:
            return b""
            
        try:
            # 1. Length-prefixed string/bytes arguments
            if op.category == OpcodeCategory.LENGTH_PREFIXED:
                new_payload = random.choice(self.sample_strings).encode("utf-8")
                length = len(new_payload)
                
                if op.arg_width == 1:
                    prefix = bytes([min(length, 255)])
                    new_payload = new_payload[:255]
                elif op.arg_width == 4:
                    prefix = struct.pack("<I", length)
                elif op.arg_width == 8:
                    prefix = struct.pack("<Q", length)
                else:
                    return arg
                return prefix + new_payload

            # 2. Fixed-width arguments (e.g. floats, ints)
            if op.category == OpcodeCategory.FIXED_ARG:
                assert op.arg_width is not None
                if op.name == "BINFLOAT" and op.arg_width == 8:
                    val = random.choice(self.sample_floats)
                    return struct.pack(">d", val)
                elif op.name == "BININT" and op.arg_width == 4:
                    val = random.choice(self.sample_ints)
                    return struct.pack("<i", val)
                elif op.name == "BININT1" and op.arg_width == 1:
                    val = random.randint(0, 255)
                    return bytes([val])
                elif op.name == "BININT2" and op.arg_width == 2:
                    val = random.randint(0, 65535)
                    return struct.pack("<H", val)
                return arg

            # 3. Delimited arguments (newline terminated)
            if op.category == OpcodeCategory.DELIMITED:
                if op.name in ("GLOBAL", "INST"):
                    return arg  # Handled separately by callable substitution
                    
                if op.name in ("INT", "LONG"):
                    val = random.choice(self.sample_ints)
                    return f"{val}\n".encode("ascii")
                elif op.name == "FLOAT":
                    val = random.choice(self.sample_floats)
                    return f"{val}\n".encode("ascii")
                elif op.name in ("STRING", "UNICODE"):
                    val = random.choice(self.sample_strings)
                    return f"'{val}'\n".encode("utf-8")
        except Exception:
            pass
            
        return arg

    def mutate_structural_stacking(self, pkl_bytes: bytes) -> bytes:
        """Create stacked-pickle variants by appending another independent pickle stream."""
        # Simple valid pickle representing a nested stack payload
        extra_bytes = pickle.dumps({"fuzzed_stack_payload": True})
        return pkl_bytes + extra_bytes

    def mutate(
        self,
        pkl_bytes: bytes,
        op_swap_prob: float = 0.1,
        callable_sub_prob: float = 0.2,
        arg_fuzz_prob: float = 0.2,
        stack_prob: float = 0.05,
    ) -> bytes:
        """Parse, apply selected mutation operators, and reconstruct the pickle stream."""
        # 1. Structural stacking mutation
        if random.random() < stack_prob:
            pkl_bytes = self.mutate_structural_stacking(pkl_bytes)
            
        parsed = parse_pickle(pkl_bytes)
        mutated_parsed = []
        
        for op, arg in parsed:
            if op.name == "STOP":
                mutated_parsed.append((op, arg))
                continue
                
            curr_op, curr_arg = op, arg
            
            # 2. Opcode swapping mutation
            if random.random() < op_swap_prob:
                curr_op, curr_arg = self.mutate_opcode_swap(curr_op, curr_arg)
                
            # 3. Callable substitution mutation
            if random.random() < callable_sub_prob:
                curr_op, curr_arg = self.mutate_callable_substitution(curr_op, curr_arg)
                
            # 4. Argument fuzzing mutation
            if random.random() < arg_fuzz_prob:
                curr_arg = self.mutate_argument_fuzz(curr_op, curr_arg)
                
            mutated_parsed.append((curr_op, curr_arg))
            
        return b"".join(op.code + arg for op, arg in mutated_parsed)
