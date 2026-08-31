# Disclosure: Fickling bypass via gadget / subprocess.getstatusoutput

## Reproduction
1. `python3 -m pipeline.mutators` gadget with `subprocess.getstatusoutput` (`pipeline/registry.py` `dangerous_callables.yaml:54` vs `fickling` denylist)
2. `fickling --check-safety` reports `LIKELY_SAFE` (no AST rule for `getstatusoutput` vs `getoutput` distinction)
3. `StraceOracle` confirms execve `pipeline/monitor.py:27`

## Root Cause
Fickling AST rules `containers/fickling/wrapper.py` allowlist `torch` plumbing but not `subprocess.getstatusoutput` vs `getoutput` nuance; direct `GLOBAL subprocess getstatusoutput` not in `fickling` severity `OVERTLY_MALICIOUS`.

## Suggested Fix
Expand Fickling `suspicious_globals` to include `subprocess.getstatusoutput` and `getoutput` variants.

## Artifact
`data/candidates/guided-r1/round_2/candidate_5.pt` (if gadget) or synthetic via `CandidateGenerator.generate_candidate_pt(attack_family="gadget", dangerous_callable=("subprocess","getstatusoutput"))` `pipeline/generator.py:340`.
