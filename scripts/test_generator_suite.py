#!/usr/bin/env python3
"""T3.6 — Unit and Property Test Suite for Generator, Mutator, and Validity Oracle.

Asserts 100% grammar-valid pickle outputs and validates individual components.
"""

from __future__ import annotations

import os
import pickle
import sys
import tempfile
import torch

from pipeline.generator import CandidateGenerator
from pipeline.mutators import PickleMutator
from pipeline.opcodes import parse_pickle, OPCODES_BY_NAME, OpcodeCategory
from pipeline.registry import load_registry, is_dangerous
from pipeline.validity import ValidityOracle


def test_opcode_taxonomy():
    print("[test] Verifying PickleFuzzer opcode classification...")
    assert "STOP" in OPCODES_BY_NAME
    assert "REDUCE" in OPCODES_BY_NAME
    assert "BININT" in OPCODES_BY_NAME
    assert "GLOBAL" in OPCODES_BY_NAME
    
    assert OPCODES_BY_NAME["STOP"].category == OpcodeCategory.NO_ARG
    assert OPCODES_BY_NAME["REDUCE"].category == OpcodeCategory.NO_ARG
    assert OPCODES_BY_NAME["BININT"].category == OpcodeCategory.FIXED_ARG
    assert OPCODES_BY_NAME["GLOBAL"].category == OpcodeCategory.DELIMITED
    print("  => Opcode taxonomy mappings OK.")


def test_parsing_and_reconstruction():
    print("[test] Verifying pickle tokenizing and reconstruction...")
    test_cases = [
        {"a": 1, "b": [2, 3.5]},
        12345,
        "hello fuzzer",
        b"x" * 1000,
    ]
    for obj in test_cases:
        for proto in range(pickle.HIGHEST_PROTOCOL + 1):
            data = pickle.dumps(obj, protocol=proto)
            parsed = parse_pickle(data)
            reconstructed = b"".join(op.code + arg for op, arg in parsed)
            assert reconstructed == data, f"Reconstruction failed for proto {proto}"
    print("  => Tokenizer & reconstruction OK.")


def test_registry_loading():
    print("[test] Verifying dangerous-callable registry...")
    load_registry()
    assert is_dangerous("os", "system")
    assert is_dangerous("subprocess", "Popen")
    assert is_dangerous("builtins", "eval")
    assert not is_dangerous("math", "cos")
    print("  => Registry queries OK.")


def test_mutator_operators():
    print("[test] Verifying individual mutation operators...")
    mutator = PickleMutator()
    benign_pkl = pickle.dumps({"test": 123})
    
    # 1. Stacking
    stacked = mutator.mutate_structural_stacking(benign_pkl)
    assert len(stacked) > len(benign_pkl)
    parsed_stacked = parse_pickle(stacked)
    assert b"".join(op.code + arg for op, arg in parsed_stacked) == stacked
    
    # 2. General mutations
    fuzzed = mutator.mutate(
        benign_pkl,
        op_swap_prob=1.0,
        callable_sub_prob=1.0,
        arg_fuzz_prob=1.0,
        stack_prob=0.0,
    )
    assert fuzzed != benign_pkl
    parsed_fuzzed = parse_pickle(fuzzed)
    assert b"".join(op.code + arg for op, arg in parsed_fuzzed) == fuzzed
    print("  => Mutator operators OK.")


def test_validity_oracle():
    print("[test] Verifying validity oracle checks...")
    oracle = ValidityOracle(container_backend="podman")
    generator = CandidateGenerator()
    
    temp_dir = tempfile.gettempdir()
    trigger_file = os.path.join(temp_dir, "suite_trigger_test.txt")
    payload = f"with open('{trigger_file}', 'w') as f: f.write('ok')"
    
    benign_pkl = pickle.dumps({"hello": "world"})
    
    # Valid candidate
    valid_pkl = generator.mutate_pickle_bytes(
        pkl_bytes=benign_pkl,
        payload_code=payload,
        dangerous_callable=("builtins", "exec"),
        mutate_meta=True,
        mutation_prob=0.1,
    )
    assert oracle.validate_pickle(valid_pkl, trigger_file) is True
    
    # Corrupted candidate
    corrupted_pkl = valid_pkl[:-10]
    assert oracle.validate_pickle(corrupted_pkl, trigger_file) is False
    print("  => Validity oracle checks OK.")


def test_property_grammar_validity():
    print("[test] Running property-based fuzzing tests (assert 100% grammar-valid)...")
    generator = CandidateGenerator()
    mutator = PickleMutator()
    oracle = ValidityOracle()
    
    temp_dir = tempfile.gettempdir()
    trigger_file = os.path.join(temp_dir, "suite_property_trigger.txt")
    payload = f"with open('{trigger_file}', 'w') as f: f.write('1')"

    benign_base = pickle.dumps({"data": [1.0, 2.0, 3.0], "meta": "test"})
    
    for i in range(100):
        # Apply combined mutations and payload injection
        candidate = generator.mutate_pickle_bytes(
            pkl_bytes=benign_base,
            payload_code=payload,
            dangerous_callable=("builtins", "exec"),
            mutate_meta=True,
            mutation_prob=0.3,
        )
        # Apply additional random fuzzing
        candidate = mutator.mutate(
            candidate,
            op_swap_prob=0.1,
            callable_sub_prob=0.1,
            arg_fuzz_prob=0.2,
            stack_prob=0.05,
        )
        
        # Verify grammar-valid parser parse-ability
        try:
            parsed = parse_pickle(candidate)
            reconstructed = b"".join(op.code + arg for op, arg in parsed)
            assert reconstructed == candidate, "Reconstructed candidate mismatch!"
        except Exception as e:
            raise AssertionError(f"Grammar validation failed on iteration {i}: {e}")
            
    print("  => Property tests OK: 100/100 outputs are 100% grammar-valid.")


def main() -> int:
    print("====================================================")
    print("STARTING GENERATOR & MUTATOR TEST SUITE (T3.6)")
    print("====================================================")
    try:
        test_opcode_taxonomy()
        test_parsing_and_reconstruction()
        test_registry_loading()
        test_mutator_operators()
        test_validity_oracle()
        test_property_grammar_validity()
        print("\n====================================================")
        print("ALL TESTS PASSED SUCCESSFULLY!")
        print("====================================================")
        return 0
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("\n====================================================")
        print("TEST SUITE FAILED!")
        print("====================================================")
        return 1


if __name__ == "__main__":
    sys.exit(main())
