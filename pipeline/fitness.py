"""T5.2 — Distance-to-Boundary Fitness.

Calculates a continuous fitness score for candidates based on panel evasion
and oracle decision distance, plus (Phase 2) per-scanner partial-evasion
credit and an exploration/novelty bonus so the feedback loop has a usable
gradient when every candidate is fully detected.

Phase 3: Multiple fitness modes for ablation experiments:
  - CURRENT: panel evasion + boundary + novelty (existing behavior)
  - ORACLE_AWARE: panel evasion + execution oracle bonus (multiplier) + boundary + novelty
  - ORACLE_DOMINANT: lexicographic ranking (deprecated - creates plateaus)
  - CONTINUOUS: smooth multi-objective (evasion * oracle_multiplier + boundary + novelty + coverage)
  - COVERAGE_GUIDED: coverage delta as primary signal
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FitnessMode(Enum):
    """Fitness computation mode for ablation experiments."""
    CURRENT = "current"
    ORACLE_AWARE = "oracle_aware"
    ORACLE_DOMINANT = "oracle_dominant"
    CONTINUOUS = "continuous"
    COVERAGE_GUIDED = "coverage_guided"


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

    evasion: float = 1.0        # per scanner verdict flipped to benign
    boundary: float = 1.0       # distance-to-boundary term scale
    novelty: float = 2.0        # exploration bonus scale
    error_penalty: float = 0.25 # unknown-verdict cost (fail-closed panel)
    oracle_bonus: float = 3.0   # bonus for oracle-confirmed malicious (ORACLE_AWARE mode)


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
    """Oracle-aware fitness: adds multiplier for execution oracle confirmation.
    
    This mode rewards candidates that:
    1. Evade panel scanners (per-scanner gradient via compute_fitness_multi)
    2. Are confirmed malicious by the execution oracle (is_valid = trigger fired)
    3. Uses oracle as a MULTIPLIER on evasion score, not additive tier gate
    """
    base = compute_fitness_multi(scanner_verdicts, decision_score, novelty_score, weights)
    
    if is_valid and oracle_verdict == "malicious":
        # Multiplier on evasion component: doubles the evasion reward
        benign = sum(1 for v in scanner_verdicts.values() if v == "benign")
        base += weights.evasion * benign  # additional evasion weight
        base += weights.oracle_bonus      # fixed oracle bonus
    
    return base


def compute_fitness_continuous(
    scanner_verdicts: dict[str, str],
    execution_oracle_verdict: str,
    is_valid: bool,
    decision_score: float | None,
    novelty_score: float = 0.0,
    coverage_delta: float = 0.0,
    weights: FitnessWeights = DEFAULT_WEIGHTS,
) -> float:
    """Continuous fitness: smooth multi-objective without tier plateaus.
    
    Components (all continuous, no hard thresholds):
    - evasion: per-scanner benign count (0 to N)
    - oracle_multiplier: 2.0 if execution oracle confirms, 1.0 otherwise
    - boundary: distance to DynaHug decision boundary (smooth)
    - novelty: exploration bonus (smooth decay)
    - coverage: coverage delta (smooth)
    
    Formula:
      fitness = evasion_score * oracle_multiplier + boundary_score + novelty_score * w_novelty + coverage_delta * w_coverage
    """
    benign = sum(1 for v in scanner_verdicts.values() if v == "benign")
    errors = sum(1 for v in scanner_verdicts.values() if v == "error")
    
    # Oracle multiplier: 2x evasion reward when execution confirmed
    oracle_multiplier = 2.0 if (is_valid and execution_oracle_verdict == "malicious") else 1.0
    
    evasion_score = weights.evasion * benign * oracle_multiplier
    error_penalty = weights.error_penalty * errors
    
    dist = abs(decision_score) if decision_score is not None else 1.0
    boundary_score = weights.boundary * (1.0 / (1.0 + dist))
    
    novelty_component = weights.novelty * novelty_score
    coverage_component = weights.novelty * 0.5 * coverage_delta  # half novelty weight for coverage
    
    return evasion_score - error_penalty + boundary_score + novelty_component + coverage_component


def compute_fitness_coverage_guided(
    scanner_verdicts: dict[str, str],
    execution_oracle_verdict: str,
    is_valid: bool,
    decision_score: float | None,
    novelty_score: float = 0.0,
    coverage_delta: float = 0.0,
    weights: FitnessWeights = DEFAULT_WEIGHTS,
) -> float:
    """Coverage-guided fitness: coverage delta as primary exploration signal.
    
    When evasion plateaus (all candidates detected), coverage_delta drives exploration.
    Oracle confirmation still provides evasion multiplier.
    """
    base = compute_fitness_continuous(
        scanner_verdicts, execution_oracle_verdict, is_valid, 
        decision_score, novelty_score, coverage_delta, weights
    )
    
    # Boost coverage component when evasion is low (plateau detected)
    benign = sum(1 for v in scanner_verdicts.values() if v == "benign")
    total = len(scanner_verdicts)
    evasion_rate = benign / max(1, total)
    
    if evasion_rate < 0.3 and coverage_delta > 0:
        # Plateau: emphasize coverage exploration
        base += weights.novelty * 2.0 * coverage_delta
    
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
    
    Ranking (highest to lowest):
    1. CONFIRMED_MALICIOUS + VALID     (oracle_verdict == "malicious" AND is_valid)
    2. PANEL_EVASION + VALID           (all panel benign AND is_valid)
    3. VALID + NOVEL                   (is_valid AND novelty_score > 0)
    4. VALID + COVERAGE                (is_valid AND coverage_delta > 0)
    5. INVALID                         (not is_valid)
    
    Returns a float where higher = better, with large gaps between tiers
    to enforce lexicographic ordering.
    """
    panel_all_benign = (
        all(v == "benign" for v in scanner_verdicts.values()) 
        and scanner_verdicts
    )
    
    if not is_valid:
        return 0.0  # Tier 5: Invalid
    
    if oracle_verdict == "malicious":
        # Tier 1: Confirmed malicious - use decision_score for granularity
        distance = abs(decision_score) if decision_score is not None else 1.0
        boundary_proximity = 1.0 / (1.0 + distance)
        return 10000.0 + boundary_proximity * 100 + novelty_score * 10 + coverage_delta
    
    if all(v == "benign" for v in scanner_verdicts.values()) and scanner_verdicts:
        return 1000.0 + novelty_score * 10 + coverage_delta  # Tier 2: Panel evasion
    
    if novelty_score > 0:
        return 100.0 + novelty_score * 10 + coverage_delta  # Tier 3: Novel
    
    if coverage_delta > 0:
        return 10.0 + coverage_delta  # Tier 4: Coverage improvement
    
    return 1.0  # Tier 5: Valid but nothing special
