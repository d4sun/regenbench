"""T5.1 — Dual-Oracle Comparator.

Corroborates panel scanner verdicts against dynamic behavior verdicts to confirm bypasses.
"""

from __future__ import annotations


def check_bypass(panel_verdicts: list[str], oracle_verdict: str) -> bool:
    """Identify confirmed scanner bypasses.
    
    A candidate is flagged as a confirmed bypass if:
    1. Every panel scanner classifies the candidate as "benign" (i.e. evasion of static panel).
    2. The dynamic oracle (DynaHug) classifies the candidate as "malicious" (i.e. payload executed).
    """
    if not panel_verdicts:
        return False
    # If any scanner labeled it malicious, it did not evade the panel
    all_panel_benign = all(v == "benign" for v in panel_verdicts)
    return all_panel_benign and oracle_verdict == "malicious"
