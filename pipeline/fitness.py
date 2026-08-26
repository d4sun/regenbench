"""T5.2 — Distance-to-Boundary Fitness.

Calculates a continuous fitness score for candidates based on panel evasion
and oracle decision distance, plus (Phase 2) per-scanner partial-evasion
credit and an exploration/novelty bonus so the feedback loop has a usable
gradient when every candidate is fully detected.

Phase 3: Multiple fitness modes for ablation experiments:
  - CURRENT: panel evasion + boundary + novelty (existing behavior)
  - ORACLE_AWARE: panel evasion + oracle bonus + boundary + novelty
  - ORACLE_DOMINANT: lexicographic ranking (dynamic confirmation > panel > coverage > novelty)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FitnessMode(Enum):
    """Fitness computation mode for ablation experiments."""
    CURRENT = "current"
    ORACLE_AWARE = "oracle_aware"
    ORACLE_DOMINANT = "oracle_dominant"


def compute_fitness(detected_count: int, total_scanners: int, decision_score: float | None) -> float:
    """Compute a continuous fitness score.
    
    The score rewards:
    1. Maximum scanner evasion (minimizing detected_count).
    2. Minimizing absolute distance to the DynaHug OCSVM decision boundary (decision_score closer to 0.0).
    
    Formula:
      fitness = (total_scanners - detected_count) + 1.0 / (1.0 + abs(decision_score))
    """
    evasion_score = float(total_scanners - detected_count)
    dist = abs(decision_score) if decision_score is not None else 1.0
    boundary_score = 1.0 / (1.0 + dist)
    return evasion_score + boundary_score


@dataclass(frozen=True)
class FitnessWeights:
    """Multi-objective weights; overridable per campaign via config."""

    evasion: float = 3.0        # per scanner verdict flipped to benign (3x boost)
    boundary: float = 2.0       # distance-to-boundary term scale (2x boost)
    novelty: float = 1.0        # exploration bonus scale (reduced to prioritize evasion)
    error_penalty: float = 0.5  # unknown-verdict cost (fail-closed panel, 2x penalty)
    oracle_bonus: float = 5.0   # bonus for oracle-confirmed malicious (ORACLE_AWARE mode, larger bonus)


DEFAULT_WEIGHTS = FitnessWeights()


def compute_fitness_multi(
    scanner_verdicts: dict[str, str],
    decision_score: float | None,
    novelty_score: float = 0.0,
    weights: FitnessWeights = DEFAULT_WEIGHTS,
) -> float:
    """Phase-2 multi-objective fitness over per-scanner verdicts.

    Components:
      * evasion   -- one weight unit per scanner reporting "benign"; gives
        the search a graded gradient toward full evasion instead of the
        all-or-nothing plateau when every candidate is flagged.
      * boundary  -- unchanged distance-to-boundary bonus (scale applied).
      * novelty   -- caller-supplied exploration bonus (NoveltyTracker).
      * errors    -- small penalty per errored scan: fail-closed verdicts are
        neither evasion nor detection, and unbounded retries of crashing
        configurations waste budget.

        fitness = w_evasion*benign_count - w_error*error_count
                + w_boundary / (1 + |decision_score|)
                + w_novelty * novelty_score
    """
    benign = sum(1 for v in scanner_verdicts.values() if v == "benign")
    errors = sum(1 for v in scanner_verdicts.values() if v == "error")
    dist = abs(decision_score) if decision_score is not None else 1.0
    return (
        weights.evasion * benign
        - weights.error_penalty * errors
        + weights.boundary * (1.0 / (1.0 + dist))
        + weights.novelty * novelty_score
    )


def compute_fitness_oracle_aware(
    scanner_verdicts: dict[str, str],
    oracle_verdict: str,
    is_valid: bool,
    decision_score: float | None,
    novelty_score: float = 0.0,
    weights: FitnessWeights = DEFAULT_WEIGHTS,
) -> float:
    """Oracle-aware fitness: adds bonus for oracle-confirmed malicious execution.
    
    This mode rewards candidates that:
    1. Evade panel scanners (existing behavior)
    2. Are confirmed malicious by the dynamic oracle (DynaHug)
    3. Are valid (execute successfully)
    """
    base = compute_fitness_multi(scanner_verdicts, decision_score, novelty_score, weights)
    
    if is_valid and oracle_verdict == "malicious":
        base += weights.oracle_bonus
    
    return base


def compute_fitness_lexicographic(
    scanner_verdicts: dict[str, str],
    oracle_verdict: str,
    is_valid: bool,
    novelty_score: float,
    coverage_delta: float,
    decision_score: float | None = None,
    mode: FitnessMode = FitnessMode.CURRENT,
) -> float:
    """Lexicographic fitness ranking for ORACLE_DOMINANT mode.
    
    **REVISED RANKING** (highest to lowest):
    1. FULL PANEL EVASION (all scanners benign)           → 10000+ pts
    2. PARTIAL PANEL EVASION (gradient 1000-9000 pts)     → more benign = higher
    4. ORACLE CONFIRMED (malicious + valid)               → 500+ pts
    5. VALID + NOVEL                                      → 100+ pts
    6. VALID + COVERAGE                                   → 10+ pts
    7. VALID                                              → 1 pt
    8. INVALID                                            → 0 pts
    
    Decision score provides continuous gradient ACROSS all tiers.
    """
    if not is_valid:
        return 0.0  # Tier 8: Invalid
    
    # Calculate boundary proximity (continuous signal across ALL tiers)
    distance = abs(decision_score) if decision_score is not None else 1.0
    boundary_proximity = 1.0 / (1.0 + distance)
    
    # Count panel evasion progress
    benign_count = sum(1 for v in scanner_verdicts.values() if v == "benign")
    total_scanners = len(scanner_verdicts) if scanner_verdicts else 1
    evasion_ratio = benign_count / total_scanners if total_scanners > 0 else 0.0
    
    # Tier 1: Full panel evasion (ALL scanners benign)
    if evasion_ratio == 1.0 and scanner_verdicts:
        return 10000.0 + boundary_proximity * 1000 + novelty_score * 10 + coverage_delta
    
    # Tier 2: Partial panel evasion (gradient: more benign = higher score)
    if benign_count > 0:
        # 1000 base + up to 8000 for evasion progress (9000 max at 99% evasion)
        partial_bonus = 1000.0 + (evasion_ratio * 8000.0)
        return partial_bonus + boundary_proximity * 100 + novelty_score * 10 + coverage_delta
    
    # Tier 3: Oracle confirmed malicious (even if panel detected)
    if oracle_verdict == "malicious":
        return 500.0 + boundary_proximity * 50 + novelty_score * 10 + coverage_delta
    
    # Tier 4: Valid + novel exploration
    if novelty_score > 0:
        return 100.0 + novelty_score * 10 + boundary_proximity * 10 + coverage_delta
    
    # Tier 5: Valid + coverage improvement
    if coverage_delta > 0:
        return 10.0 + coverage_delta + boundary_proximity * 1
    
    # Tier 6: Valid but nothing special
    return 1.0 + boundary_proximity * 0.1
