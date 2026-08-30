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


# RQ2 combo-reinforcement tiers, mirroring compute_fitness_lexicographic.
TIER1_FIT = 10000.0  # oracle-confirmed + valid
TIER2_FIT = 1000.0   # panel-evading + valid
TIER1_WEIGHT = 5.0
TIER2_WEIGHT = 2.0
TIER3_WEIGHT = 0.1


def compute_semantic_fingerprint(file_path: str) -> tuple:
    """Compute a semantic fingerprint for a candidate to identify novel attack families.
    
    The fingerprint captures the semantic structure of the attack:
    - Callable set: which dangerous callables are used (module, name)
    - Strategy set: which evasion strategies are applied
    - Opcode categories: high-level categories of opcodes used (not individual opcodes)
    - Transport: loads vs splice
    - Family: the attack family
    
    This is more stable than full opcode sequences and enables detection of
    genuinely novel attack patterns vs minor mutations.
    """
    import zipfile
    from pipeline.opcodes import parse_pickle, OpcodeCategory
    from pipeline.registry import is_dangerous
    
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if not magic:
            return ()
        
        is_zip = magic.startswith(b"PK\x03\x04")
        if is_zip:
            with zipfile.ZipFile(file_path) as z:
                pkl_name = [name for name in z.namelist() if name.endswith("data.pkl")]
                if not pkl_name:
                    return ()
                pkl_bytes = z.read(pkl_name[0])
        else:
            with open(file_path, "rb") as f:
                pkl_bytes = f.read()
        
        parsed = parse_pickle(pkl_bytes)
        
        # Extract callables
        callables = set()
        for op, arg in parsed:
            if op.name in ("GLOBAL", "INST"):
                parts = arg.decode("latin1").split("\n")
                if len(parts) >= 2 and is_dangerous(parts[0], parts[1]):
                    callables.add((parts[0], parts[1]))
            elif op.name == "STACK_GLOBAL":
                strings = []
                for j in range(len(parsed) - 1, max(-1, len(parsed) - 6), -1):
                    val = _string_value(parsed[j][0], parsed[j][1])
                    if val is not None:
                        strings.append(val)
                        if len(strings) == 2:
                            break
                if len(strings) == 2:
                    module, name = strings[1], strings[0]
                    if is_dangerous(module, name):
                        callables.add((module, name))
        
        # Extract opcode categories (not individual opcodes)
        opcode_cats = set()
        for op, _ in parsed:
            if op.category != OpcodeCategory.NO_ARG:
                opcode_cats.add(op.category.name)
        
        # Extract transport from file structure (simplified)
        transport = "splice" if is_zip else "loads"
        
        # Return semantic fingerprint as a tuple
        return (
            tuple(sorted(callables)),
            tuple(sorted(opcode_cats)),
            transport,
        )
    except Exception:
        return ()


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


REACHABLE_OPCODES: frozenset[str] = frozenset({
    # Opcodes actually producible by pickle.dumps on dict/list primitives +
    # the payload generators (GLOBAL/REDUCE/STACK_GLOBAL) + evasion encodings.
    # Full pickletools (~70) includes never-emitted ops like PERSID/BINPERSID.
    "PROTO", "FRAME", "STOP", "EMPTY_DICT", "EMPTY_LIST", "EMPTY_TUPLE",
    "BINGET", "LONG_BINGET", "GET", "PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE",
    "MARK", "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "EMPTY_SET", "ADDITEMS",
    "SETITEM", "SETITEMS", "APPEND", "APPENDS", "BUILD", "REDUCE", "GLOBAL",
    "STACK_GLOBAL", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX",
    "BINUNICODE", "SHORT_BINUNICODE", "UNICODE", "BINSTRING", "SHORT_BINSTRING",
    "BINBYTES", "SHORT_BINBYTES", "BINBYTES8",
    "BININT", "BININT1", "BININT2", "INT", "LONG", "LONG1", "LONG4",
    "BINFLOAT", "FLOAT", "NONE", "NEWTRUE", "NEWFALSE",
    "POP", "POP_MARK", "DUP", "EXT1", "EXT2", "EXT4",
})


class CoverageTracker:
    """Logs non-decreasing opcode, callable and family coverage over rounds."""

    def __init__(self, db_path: str, run_id: str = ""):
        self.db_path = db_path
        self.run_id = run_id
        self.seen_opcodes: set[str] = set()
        self.seen_callables: set[tuple[str, str]] = set()
        self.seen_families: set[str] = set()
        self.seen_families_with_bypass: set[str] = set()

        # Denominator = reachable space, not theoretical maximum.  Full
        # pickletools (~70) includes never-emitted ops (PERSID etc.); registry
        # includes platform-excluded + NON_ARMABLE entries that can never be
        # selected.  Reachable denominator makes the % meaningful.
        self.total_opcodes = len(REACHABLE_OPCODES)
        self.total_callables = max(1, len(get_armable_entries()))
        self.total_families = len(FAMILIES)

    def track_candidate(self, file_path: str, family: str | None = None,
                        is_bypass: bool = False) -> None:
        """Parse a candidate file and log all seen opcodes, callables and families."""
        if family is not None:
            self.seen_families.add(family)
            if is_bypass:
                self.seen_families_with_bypass.add(family)
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
        # Reachable-space coverage (primary)
        opcode_cov = len(self.seen_opcodes & REACHABLE_OPCODES) / max(1, self.total_opcodes)
        callable_cov = len(self.seen_callables) / max(1, self.total_callables)
        family_cov = len(self.seen_families) / max(1, self.total_families)
        family_bypass_cov = len(self.seen_families_with_bypass) / max(1, self.total_families)

        log_coverage(self.db_path, round_num, opcode_cov, callable_cov, run_id=self.run_id)
        return opcode_cov, callable_cov

    def family_coverage(self) -> tuple[float, float]:
        """(family_explored, family_with_bypass) as fractions."""
        explored = len(self.seen_families) / max(1, self.total_families)
        with_bypass = len(self.seen_families_with_bypass) / max(1, self.total_families)
        return explored, with_bypass

    @staticmethod
    def family_entropy(family_counts: dict[str, int]) -> float:
        """Shannon entropy of the family distribution.  Uniform 5 families = 1.61 nats."""
        import math
        total = sum(family_counts.values())
        if total <= 0:
            return 0.0
        ent = 0.0
        for c in family_counts.values():
            if c > 0:
                p = c / total
                ent -= p * math.log(p)
        return ent


class NoveltyTracker:
    """Exploration bonus over structural candidate signatures (Phase 2).

    A signature is the tuple of opcode names plus the set of dangerous
    callables/strategies a candidate carries. First-sight signatures score
    1.0; repeats decay as ``1/(1+count)`` so the fuzzer keeps exploring new
    regions instead of re-sampling the same detected configuration.
    
    Semantic signature (for synthesis exploration): (callable_set, strategy_set)
    where callable_set is frozenset of (module, name) tuples.
    """

    def __init__(self):
        self._counts: dict[tuple, int] = {}
        self._semantic_counts: dict[tuple, int] = {}
        self.novel_signatures = 0
        self.novel_semantic = 0

    @staticmethod
    def signature(parsed_ops, extra: frozenset[str] = frozenset()) -> tuple:
        ops = tuple(op.name for op, _ in parsed_ops)
        return (ops, tuple(sorted(extra)))

    @staticmethod
    def semantic_signature(callables: frozenset[tuple[str, str]], 
                           strategies: frozenset[str]) -> tuple:
        """Semantic signature: (sorted_callables, sorted_strategies)."""
        return (tuple(sorted(callables)), tuple(sorted(strategies)))

    def score(self, signature: tuple) -> float:
        count = self._counts.get(signature, 0)
        self._counts[signature] = count + 1
        if count == 0:
            self.novel_signatures += 1
            return 1.0
        return 1.0 / (1.0 + count)

    def score_semantic(self, signature: tuple) -> float:
        """Score for semantic signature (callable_set + strategy_set)."""
        count = self._semantic_counts.get(signature, 0)
        self._semantic_counts[signature] = count + 1
        if count == 0:
            self.novel_semantic += 1
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

        # RQ2 combo weights: (family, transport, frozenset(strategies)) -> weight.
        # The lexicographic Tier-1/Tier-2 boundaries live in the combo space, so
        # the feedback loop rewards the full (family, transport, strategies)
        # configuration -- not just the family -- for guided sampling.
        self.combo_weights: dict[tuple[str, str, frozenset[str]], float] = {}

        # Mutation rate baselines
        self.op_swap_prob = 0.05  # Reduced from 0.15 to improve stability
        self.callable_sub_prob = 0.0  # Disabled by default: random callable substitution can break payload construction
        self.arg_fuzz_prob = 0.05  # Reduced from 0.15 to improve stability

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

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back to
        family-only / strategy sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_configuration(
        self,
        rng,
        allowed_families: set[str] | None = None,
        fixed_strategies: frozenset[str] | None = None,
        fixed_transport: str | None = None,
    ) -> tuple[str, str, frozenset[str]] | None:
        """One weighted draw over known-rewarded configuration combos.

        Restricted to ``allowed_families`` (default: all families) and any
        pinned strategy/transport. Returns ``None`` when no combo evidence
        matches, so the campaign can fall back to its regular sampling path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if (allowed_families is None or k[0] in allowed_families)
            and (fixed_strategies is None or k[2] == fixed_strategies)
            and (fixed_transport is None or k[1] == fixed_transport)
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, strategies

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back to
        family-weighted sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_combo(
        self,
        rng,
        allowed_families: set[str],
        fixed_strategies: frozenset[str] | None = None,
        fixed_transport: str | None = None,
    ) -> tuple[str, str, list[str]] | None:
        """One weighted draw over known-rewarded combos restricted to
        ``allowed_families``.

        When ``fixed_strategies`` (``--evasion-strategies``) or
        ``fixed_transport`` is pinned, only combos matching it are eligible.
        Returns ``None`` when no combo evidence exists for the allowed set;
        callers then use the family/callable/strategy fallback path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if k[0] in allowed_families
            and (fixed_strategies is None or k[2] == fixed_strategies)
            and (fixed_transport is None or k[1] == fixed_transport)
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back
        to family-weighted sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_combo(
        self,
        rng,
        allowed_families: set[str],
        fixed_strategies: frozenset[str] | None = None,
        fixed_transport: str | None = None,
    ) -> tuple[str, str, list[str]] | None:
        """One weighted draw over known-rewarded combos restricted to
        ``allowed_families`` (and any fixed strategy/transport pins).

        Returns ``None`` when no combo evidence exists for the allowed set;
        callers then use the family/callable/strategy fallback path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if k[0] in allowed_families
            and (fixed_strategies is None or k[2] == fixed_strategies)
            and (fixed_transport is None or k[1] == fixed_transport)
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back to
        family-weighted sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_combo(self, rng, allowed_families,
                     fixed_strategies: frozenset[str] | None = None,
                     fixed_transport: str | None = None):
        """One weighted draw over known-rewarded combos restricted to
        ``allowed_families``.

        When ``fixed_strategies`` (``--evasion-strategies``) or
        ``fixed_transport`` is pinned, only combos matching it are eligible.
        Returns ``None`` when no combo evidence exists for the allowed set;
        callers then use the family/callable/strategy fallback path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if k[0] in allowed_families
            and (fixed_strategies is None or k[2] == fixed_strategies)
            and (fixed_transport is None or k[1] == fixed_transport)
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back
        to family-weighted sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_combo(self, rng, allowed_families,
                     fixed_strategies: frozenset[str] | None = None,
                     fixed_transport: str | None = None):
        """One weighted draw over known-rewarded combos restricted to
        ``allowed_families``.

        When ``fixed_strategies`` (``--evasion-strategies``) or
        ``fixed_transport`` is pinned, only combos matching it are eligible.
        Returns ``None`` when no combo evidence exists for the allowed set;
        callers then use the family/callable/strategy fallback path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if k[0] in allowed_families
            and (fixed_strategies is None or k[2] == fixed_strategies)
            and (fixed_transport is None or k[1] == fixed_transport)
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back
        to family-weighted sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_combo(self, rng, allowed_families,
                     fixed_strategies: frozenset[str] | None = None,
                     fixed_transport: str | None = None):
        """One weighted draw over known-rewarded combos restricted to
        ``allowed_families``.

        When ``fixed_strategies`` (``--evasion-strategies``) or
        ``fixed_transport`` is pinned, only combos matching it are eligible.
        Returns ``None`` when no combo evidence exists for the allowed set;
        callers then use the family/callable/strategy fallback path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if k[0] in allowed_families
            and (fixed_strategies is None or k[2] == fixed_strategies)
            and (fixed_transport is None or k[1] == fixed_transport)
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back
        to family-weighted sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_combo(self, rng, allowed_families,
                     fixed_strategies: frozenset[str] | None = None):
        """One weighted draw over known-rewarded combos restricted to
        ``allowed_families``.

        When ``fixed_strategies`` is pinned (``--evasion-strategies``), only
        combos whose strategy set exactly matches it are eligible. Returns
        ``None`` when no combo evidence exists for the allowed set; callers
        then use the family/callable/strategy fallback path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if k[0] in allowed_families
            and (fixed_strategies is None or k[2] == fixed_strategies)
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Normalized weights over (family, transport, strategies) combos.

        Empty before the first rewarded combo is observed; callers fall back
        to family-weighted sampling when empty.
        """
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_combo(self, rng, allowed_families,
                     default_transport: str | None = None,
                     fixed_strategies: set[str] | None = None):
        """One weighted draw over known-rewarded combos restricted to
        ``allowed_families`` (and ``fixed_strategies`` when pinned).

        Returns ``None`` when no combo evidence exists for the allowed set;
        callers then use the family/callable/strategy fallback path.
        """
        pool = [
            (k, w) for k, w in self.combo_weights.items()
            if k[0] in allowed_families
            and (fixed_strategies is None or fixed_strategies <= k[2])
        ]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def get_combo_weights(self) -> dict[tuple[str, str, frozenset[str]], float]:
        """Return normalized weights over (family, transport, strategies) combos."""
        total = sum(self.combo_weights.values())
        if total <= 0.0:
            return {}
        return {k: w / total for k, w in self.combo_weights.items()}

    def sample_family(self, rng, allowed_families) -> str:
        """Weighted family draw over the allowed attack families."""
        weighted = {f: w for f, w in self.family_weights.items() if f in allowed_families}
        if not weighted:
            return rng.choice(sorted(allowed_families))
        population = list(weighted)
        probs = [weighted[f] for f in population]
        return rng.choices(population, weights=probs, k=1)[0]

    def sample_combo(self, rng, allowed_families: set[str], default_transport: str,
                     pick_strategies) -> tuple[str, str, list[str]] | None:
        """Draw (family, transport, strategies) as one weighted combo sample.

        Returns ``None`` when no combo evidence exists yet (callers fall back to
        a family-weighted draw); otherwise returns a stored successful combo.
        ``pick_strategies`` is only used on an empty combo space and is never
        invoked here (kept for API symmetry with the campaign's fallback).
        """
        pool = [(k, w) for k, w in self.combo_weights.items()
                if k[0] in allowed_families]
        if not pool:
            return None
        keys = [k for k, _ in pool]
        probs = [w for _, w in pool]
        fam, transport, strategies = rng.choices(keys, weights=probs, k=1)[0]
        return fam, transport, sorted(strategies)

    def sample_with_novelty(self, rng, allowed_families: set[str], 
                            novelty_tracker: NoveltyTracker,
                            fixed_strategies: frozenset[str] | None = None,
                            fixed_transport: str | None = None,
                            explore_prob: float = 0.25) -> tuple[str, str, frozenset[str]] | None:
        """Sample configuration with semantic novelty bias for synthesis exploration.
        
        Used when combo_weights is empty (early campaign or new synthesis).
        Biases toward unseen (family, strategy_set) combinations.
        
        Combo exploitation would otherwise lock out families absent from
        combo_weights: once round 1 populates the pool with the sampled
        families, any family that never made it in is never drawn again.
        Exploration probability scales up with the share of allowed families
        missing from the combo pool, so an uncovered family is guaranteed to
        stay reachable.
        """
        # 1. Exploit combo weights (unless exploring an unseen family).
        covered = {k[0] for k in self.combo_weights} & allowed_families
        missing = allowed_families - covered
        if missing:
            # Scale exploration with the uncovered fraction: a family that has
            # never been sampled must be drawn often enough to be discovered.
            explore_prob = max(explore_prob, 0.4 + 0.6 * len(missing) / len(allowed_families))
        if rng.random() >= explore_prob:
            combo = self.sample_combo(rng, allowed_families, fixed_strategies, fixed_transport)
            if combo:
                return combo
        
        # 2. Fallback: family-weighted + semantic novelty bonus
        family = self.sample_family(rng, allowed_families)
        transport = fixed_transport or "splice"
        
        # Get candidate strategy sets for this family
        strategy_pool = self._candidate_strategy_sets(family)
        if fixed_strategies:
            strategy_pool = [s for s in strategy_pool if s == fixed_strategies]
        
        if not strategy_pool:
            return family, transport, frozenset()
        
        # Score each strategy set by semantic novelty
        scored = []
        for s in strategy_pool:
            sem_sig = NoveltyTracker.semantic_signature(frozenset(), frozenset(s))
            nov = novelty_tracker.score_semantic(sem_sig)
            weight = self.family_weights.get(family, 1.0) * (1.0 + 2.0 * nov)
            scored.append((s, weight))
        
        strategies = rng.choices([s for s, _ in scored], weights=[w for _, w in scored], k=1)[0]
        return family, transport, frozenset(strategies)

    def _candidate_strategy_sets(self, family: str) -> list[frozenset[str]]:
        """Get known strategy sets for a family from combo weights."""
        seen = set()
        for (fam, _trans, strat), _weight in self.combo_weights.items():
            if fam == family:
                seen.add(strat)
        if not seen:
            # Default strategy sets per family. Anti-evasive stacks excluded:
            # nested_loads_wrap/payload_obfuscation add _pickle.loads, and
            # indirect_chain adds builtins.__import__/getattr -- all denylisted
            # by PickleScan. Only sets that preserve the sink's stealth belong.
            defaults = {
                "gadget": [frozenset(), frozenset(["stack_global_encoding"])],
                "overwritten": [frozenset(), frozenset(["stack_global_encoding"])],
                "pypi_injected": [frozenset(), frozenset(["stack_global_encoding"])],
                "external": [frozenset(), frozenset(["stack_global_encoding"])],
                "indirect_chain": [frozenset(), frozenset(["stack_global_encoding"])],
            }
            return defaults.get(family, [frozenset()])
        return list(seen)

    def sample_coverage_gaps(self, rng, tracker: CoverageTracker,
                              allowed_families: set[str]) -> tuple[str, tuple[str, str]] | None:
        """Sample unseen opcodes/callables for coverage-driven exploration.
        
        Returns (family, callable) for unseen callable, or (family, "opcode") for unseen opcode.
        """
        from pipeline.opcodes import OPCODES_BY_BYTE
        from pipeline.registry import get_armable_entries
        
        unseen_opcodes = set(OPCODES_BY_BYTE.keys()) - tracker.seen_opcodes
        unseen_callables = set((e.module, e.name) for e in get_armable_entries()) - tracker.seen_callables
        
        if unseen_callables and rng.random() < 0.6:
            family = rng.choice(list(allowed_families))
            callable = rng.choice(list(unseen_callables))
            return family, callable
        elif unseen_opcodes and rng.random() < 0.4:
            family = rng.choice(list(allowed_families))
            return family, ("opcode", rng.choice(list(unseen_opcodes)))
        return None

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

        # 1b. Tier-based combo + family reinforcement (RQ2). The winning
        # configuration lives in the (family, transport, strategies) product
        # space; reward the full combo -- not just the family -- using the
        # lexicographic tier boundaries so oracle-confirmed (Tier 1) and
        # panel-evading (Tier 2) configurations dominate guided sampling.
        for res in round_results:
            fam = res.get("family")
            transport = res.get("transport", "loads") or "loads"
            strategies = frozenset(res.get("strategies") or [])
            fit = res.get("fitness", 0.0)
            valid = res.get("valid", False)
            evaded = res.get("evaded_all", False)
            if fit >= TIER1_FIT:
                delta = TIER1_WEIGHT
            elif fit >= TIER2_FIT or (valid and evaded):
                delta = TIER2_WEIGHT
            elif valid and fit > 0.0:
                delta = TIER3_WEIGHT
            else:
                delta = 0.0
            if delta <= 0.0:
                continue
            key = (fam, transport, strategies)
            self.combo_weights[key] = self.combo_weights.get(key, 1.0) + delta
            if fam in self.family_weights:
                self.family_weights[fam] += delta

        # 2. Adjust mutation parameters based on global evasion rates
        valid_results = [r for r in round_results if r.get("valid", False)]
        if not valid_results:
            return
            
        evasion_rate = sum(1 for r in valid_results if r.get("evaded_all", False)) / len(valid_results)
        
        # Cap mutation probabilities to prevent structural corruption
        # Higher values cause pickle stream corruption (invalid opcodes)
        MAX_OP_SWAP = 0.25
        MAX_CALLABLE_SUB = 0.25
        MAX_ARG_FUZZ = 0.30
        MIN_OP_SWAP = 0.05
        MIN_CALLABLE_SUB = 0.05
        MIN_ARG_FUZZ = 0.05
        
        if evasion_rate < 0.2:
            # Low evasion rate: increase mutation entropy to explore more options
            self.op_swap_prob = min(MAX_OP_SWAP, self.op_swap_prob + 0.05)
            self.callable_sub_prob = min(MAX_CALLABLE_SUB, self.callable_sub_prob + 0.05)
            self.arg_fuzz_prob = min(MAX_ARG_FUZZ, self.arg_fuzz_prob + 0.05)
        elif evasion_rate > 0.6:
            # High evasion rate: specialize around current configurations
            self.op_swap_prob = max(MIN_OP_SWAP, self.op_swap_prob - 0.03)
            self.callable_sub_prob = max(MIN_CALLABLE_SUB, self.callable_sub_prob - 0.03)
            self.arg_fuzz_prob = max(MIN_ARG_FUZZ, self.arg_fuzz_prob - 0.03)
