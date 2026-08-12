"""T5.2 — Distance-to-Boundary Fitness.

Calculates a continuous fitness score for candidates based on panel evasion and oracle decision distance.
"""

from __future__ import annotations


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
