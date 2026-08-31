"""T5.1 — Dual-Oracle Comparator.

Corroborates panel scanner verdicts against dynamic execution verdicts to confirm bypasses.

The "execution oracle" is the deterministic ValidityOracle (trigger polling) /
StraceOracle (syscall rubric), not the statistical DynaHug anomaly detector.
DynaHug provides a supplementary decision_score signal only.

P2.3 consensus tiers:
  Tier 1 (Confirmed Bypass): panel all-benign + StraceOracle malicious (>=2)
  Tier 2 (Probable Bypass): panel all-benign + Strace benign + DynaHug malicious
  Tier 3 (Scanner Evasion Only): panel all-benign + Strace benign + DynaHug benign
"""

from __future__ import annotations


def check_bypass_tier(panel_verdicts: list[str], strace_verdict: str, dynahug_verdict: str) -> str | None:
    """Return consensus tier (1/2/3) or None if not evading panel.

    Args:
        panel_verdicts: list of panel scanner verdicts
        strace_verdict: StraceOracle verdict (malicious/suspicious/benign)
        dynahug_verdict: DynaHug verdict (malicious/benign)
    """
    if not panel_verdicts or not all(v == "benign" for v in panel_verdicts):
        return None
    if strace_verdict == "malicious":
        return "1"
    if strace_verdict in ("benign", "suspicious", "error", None):
        # Tier 2 vs 3 depends on DynaHug
        if dynahug_verdict == "malicious":
            return "2"
        else:
            return "3"
    return "3"


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
