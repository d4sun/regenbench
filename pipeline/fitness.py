"""T5.2 — Distance-to-Boundary Fitness.

Calculates a continuous fitness score for candidates based on panel evasion
and oracle decision distance, plus (Phase 2) per-scanner partial-evasion
credit and an exploration/novelty bonus so the feedback loop has a usable
gradient when every candidate is fully detected.
"""

from __future__ import annotations

from dataclasses import dataclass


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
