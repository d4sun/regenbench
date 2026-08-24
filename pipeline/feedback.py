"""T5.3 & T5.4 — Feedback-Directed Fuzzing Loop Controller.

Tracks cumulative non-decreasing opcode and dangerous-callable coverage,
and dynamically adjusts mutation parameters and selection weights based on fitness feedback.
"""

from __future__ import annotations

import os
import zipfile
from typing import Any

from pipeline.opcodes import parse_pickle, OPCODES_BY_BYTE
from pipeline.registry import get_armable_entries, get_all_entries, is_dangerous
from pipeline.templates import FAMILIES, FAMILY_TEMPLATES
from pipeline.db import log_coverage


def _string_value(op, arg: bytes) -> str | None:
    """Extract the string pushed by a string opcode (for STACK_GLOBAL)."""
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


class CoverageTracker:
    """Logs non-decreasing opcode and dangerous-callable coverage over rounds."""

    def __init__(self, db_path: str, run_id: str = ""):
        self.db_path = db_path
        self.run_id = run_id
        self.seen_opcodes: set[str] = set()
        self.seen_callables: set[tuple[str, str]] = set()
        
        # Determine total possible coverage items
        self.total_opcodes = max(1, len(OPCODES_BY_BYTE))
        self.total_callables = max(1, len(get_all_entries()))

    def track_candidate(self, file_path: str) -> None:
        """Parse a candidate file and log all seen opcodes and dangerous callables."""
        if not os.path.exists(file_path):
            return

        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
            if not magic:
                return

            is_zip = magic.startswith(b"PK\x03\x04")
            
            if is_zip:
                with zipfile.ZipFile(file_path) as z:
                    pkl_name = [name for name in z.namelist() if name.endswith("data.pkl")]
                    if not pkl_name:
                        return
                    pkl_bytes = z.read(pkl_name[0])
            else:
                with open(file_path, "rb") as f:
                    pkl_bytes = f.read()

            parsed = parse_pickle(pkl_bytes)
            self._track_parsed(parsed)
        except Exception:
            pass

    def _track_parsed(self, parsed: list[tuple[Any, bytes]]) -> None:
        for i, (op, arg) in enumerate(parsed):
            # Add opcode to coverage
            self.seen_opcodes.add(op.name)

            # Check for dangerous imports
            if op.name in ("GLOBAL", "INST"):
                parts = arg.decode("latin1").split("\n")
                if len(parts) >= 2:
                    module, name = parts[0], parts[1]
                    if is_dangerous(module, name):
                        self.seen_callables.add((module, name))

            # Protocol >= 4: module and name are pushed as two strings
            # (with MEMOIZE ops between them) before STACK_GLOBAL.
            elif op.name == "STACK_GLOBAL":
                strings = []
                for j in range(i - 1, max(-1, i - 6), -1):
                    value = _string_value(parsed[j][0], parsed[j][1])
                    if value is not None:
                        strings.append(value)
                        if len(strings) == 2:
                            break
                if len(strings) == 2 and is_dangerous(strings[1], strings[0]):
                    self.seen_callables.add((strings[1], strings[0]))

            # Recursively track nested pickle payloads in string/bytes arguments
            if op.name in ("SHORT_BINSTRING", "BINSTRING", "UNICODE", "SHORT_BINBYTES", "BINBYTES", "BINBYTES8"):
                val = arg
                if op.name == "SHORT_BINSTRING":
                    val = arg[1:]
                elif op.name == "BINSTRING":
                    val = arg[4:]
                elif op.name == "UNICODE":
                    val = arg.strip(b"\r\n'\"")
                elif op.name == "SHORT_BINBYTES":
                    val = arg[1:]
                elif op.name == "BINBYTES":
                    val = arg[4:]
                elif op.name == "BINBYTES8":
                    val = arg[8:]

                # Check if it looks like a nested pickle stream
                if val and (val.startswith(b"\x80") or val.startswith(b"c") or val.startswith(b"(")):
                    try:
                        nested_parsed = parse_pickle(val)
                        self._track_parsed(nested_parsed)
                    except Exception:
                        pass

    def log_round(self, round_num: int) -> tuple[float, float]:
        """Calculate and log current coverage percentages to the database."""
        opcode_cov = len(self.seen_opcodes) / self.total_opcodes
        callable_cov = len(self.seen_callables) / self.total_callables
        
        log_coverage(self.db_path, round_num, opcode_cov, callable_cov, run_id=self.run_id)
        return opcode_cov, callable_cov


class NoveltyTracker:
    """Exploration bonus over structural candidate signatures (Phase 2).

    A signature is the tuple of opcode names plus the set of dangerous
    callables/strategies a candidate carries. First-sight signatures score
    1.0; repeats decay as ``1/(1+count)`` so the fuzzer keeps exploring new
    regions instead of re-sampling the same detected configuration.
    """

    def __init__(self):
        self._counts: dict[tuple, int] = {}
        self.novel_signatures = 0

    @staticmethod
    def signature(parsed_ops, extra: frozenset[str] = frozenset()) -> tuple:
        ops = tuple(op.name for op, _ in parsed_ops)
        return (ops, tuple(sorted(extra)))

    def score(self, signature: tuple) -> float:
        count = self._counts.get(signature, 0)
        self._counts[signature] = count + 1
        if count == 0:
            self.novel_signatures += 1
            return 1.0
        return 1.0 / (1.0 + count)


class FeedbackController:
    """Adjusts selection weights and mutation parameters using round results."""

    def __init__(self):
        # Fetch all registered dangerous callables (armable subset only: the
        # non-armable sinks cannot carry the inline payload, so selecting them
        # would waste campaign budget on candidates that can never trigger).
        self.callables = [(entry.module, entry.name) for entry in get_armable_entries()]
        # Equal initial weighting
        self.weights = {c: 1.0 for c in self.callables}
        
        # Family-level weights (Phase 2): weight by evasion success per family
        # gadget family uses callable weights; template families use family weight
        self.families = list(FAMILIES)
        self.family_weights = {f: 1.0 for f in self.families}

        # Mutation rate baselines
        self.op_swap_prob = 0.15
        self.callable_sub_prob = 0.15
        self.arg_fuzz_prob = 0.15

        # Phase 2 grey-box state: per-scanner verdict tallies and the
        # callables whose names appeared in scanner matched_rules.
        self.scanner_stats: dict[str, dict[str, int]] = {}
        self.flagged_callables: dict[tuple[str, str], int] = {}

    def get_callable_weights(self) -> dict[tuple[str, str], float]:
        """Return the current normalized weights for dangerous callables."""
        total = sum(self.weights.values())
        if total <= 0.0:
            return {c: 1.0 / len(self.callables) for c in self.callables}
        return {c: w / total for c, w in self.weights.items()}

    def get_family_weights(self) -> dict[str, float]:
        """Return the current normalized weights for attack families."""
        total = sum(self.family_weights.values())
        if total <= 0.0:
            return {f: 1.0 / len(self.families) for f in self.families}
        return {f: w / total for f, w in self.family_weights.items()}

    def _ingest_greybox(self, round_results: list[dict[str, Any]]) -> None:
        """Update per-scanner tallies and penalize rules-flagged callables."""
        for res in round_results:
            verdicts = res.get("scanner_verdicts") or {}
            for scanner, verdict in verdicts.items():
                stats = self.scanner_stats.setdefault(
                    scanner, {"benign": 0, "malicious": 0, "error": 0})
                if verdict in stats:
                    stats[verdict] += 1

            # Penalize any registry callable whose module.name appears in a
            # fired rule: that signature is known-bad to this scanner, so the
            # search should drift toward other sinks / heavier obfuscation.
            for rule in res.get("matched_rules") or []:
                for known in self.callables:
                    if f"{known[0]}.{known[1]}" in rule:
                        self.flagged_callables[known] = (
                            self.flagged_callables.get(known, 0) + 1)
                        if known in self.weights:
                            self.weights[known] *= 0.85

    def update(self, round_results: list[dict[str, Any]]) -> None:
        """Bias future selections and mutations toward successful configurations.
        
        Each result in round_results is a dict:
            {
                "callable": (module, name),
                "family": str,           # attack family (gadget, overwritten, pypi_injected, etc.)
                "fitness": float,
                "evaded_all": bool,      # True if candidate bypassed all panel scanners
                "valid": bool
            }
        """
        if not round_results:
            return

        # 0. Phase-2 grey-box ingestion (optional keys; no-ops when absent).
        self._ingest_greybox(round_results)

        # 1. Bias dangerous callables towards higher fitness outcomes
        for res in round_results:
            c = res.get("callable")
            fit = res.get("fitness", 0.0)
            if c in self.weights:
                # Add a portion of the fitness score to its weight (reinforcement)
                self.weights[c] += 0.2 * fit

        # 1b. Bias attack families towards higher evasion success
        for res in round_results:
            fam = res.get("family")
            evaded = res.get("evaded_all", False)
            if fam in self.family_weights:
                # Reward family if it produced a full-panel evasion
                if evaded:
                    self.family_weights[fam] += 2.0  # Strong reward for full evasion
                elif res.get("valid", False):
                    self.family_weights[fam] += 0.1  # Small reward for validity

        # 2. Adjust mutation parameters based on global evasion rates
        valid_results = [r for r in round_results if r.get("valid", False)]
        if not valid_results:
            return
            
        evasion_rate = sum(1 for r in valid_results if r.get("evaded_all", False)) / len(valid_results)
        
        if evasion_rate < 0.2:
            # Low evasion rate: increase mutation entropy to explore more options
            self.op_swap_prob = min(0.40, self.op_swap_prob + 0.05)
            self.callable_sub_prob = min(0.40, self.callable_sub_prob + 0.05)
            self.arg_fuzz_prob = min(0.45, self.arg_fuzz_prob + 0.05)
        elif evasion_rate > 0.6:
            # High evasion rate: specialize around current configurations
            self.op_swap_prob = max(0.05, self.op_swap_prob - 0.03)
            self.callable_sub_prob = max(0.05, self.callable_sub_prob - 0.03)
            self.arg_fuzz_prob = max(0.05, self.arg_fuzz_prob - 0.03)
