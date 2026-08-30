"""T5.1 — Dual-Oracle Comparator.

Corroborates panel scanner verdicts against dynamic execution verdicts to confirm bypasses.

The "execution oracle" is the deterministic ValidityOracle (trigger polling),
not the statistical DynaHug anomaly detector. DynaHug provides a supplementary
decision_score signal only.
"""

from __future__ import annotations


def check_bypass(panel_verdicts: list[str], execution_oracle_verdict: str) -> bool:
    """Identify confirmed scanner bypasses.
    
    A candidate is flagged as a confirmed bypass if:
    1. Every panel scanner classifies the candidate as "benign" (evasion of static panel).
    2. The execution oracle confirms payload execution via trigger side-effect.
    
    Args:
        panel_verdicts: List of verdicts from static scanners ("benign", "malicious", "error")
        execution_oracle_verdict: Verdict from execution oracle ("malicious" = trigger fired, "benign" = no trigger)
    """
    if not panel_verdicts:
        return False
    all_panel_benign = all(v == "benign" for v in panel_verdicts)
    return all_panel_benign and execution_oracle_verdict == "malicious"
