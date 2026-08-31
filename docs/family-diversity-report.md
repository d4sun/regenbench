# Family Diversity Report (P1.1)

**Goal:** Each of 5 families must achieve ≥1 confirmed bypass in 200-candidate pilot.

## Current State (pre-quota, live DB 1025/990/514)
- `pypi_injected` 510/514 (99.2%) `docs/triage-report.md:15`
- `gadget` 4/514, others 0 — collapse into `pypi_injected+splice` local optimum `pipeline/feedback.py:450`.

## Fix
- `config/campaign_config.yaml:43` `family_quota_min_pct: 0.15` (3/20), `family_quota_max_frac: 0.40` (9/20), `entropy_target: 1.5`
- `pipeline/feedback.py:314` `FeedbackController(family_quota_min_pct, family_quota_max_frac, entropy_target)` + `sample_family_with_quota()` `pipeline/feedback.py:421` + `global_family_counts` `pipeline/feedback.py:334` + `_update_per_family_yield()` `pipeline/feedback.py:527`
- `scripts/run_fuzzing_campaign.py:277` quota derived from yaml/CLI, `_quota_pick` legacy + `controller.sample_family_with_quota` for guided fallback `scripts/run_fuzzing_campaign.py:416`

## Validation
- Unit: `python3 -c "from pipeline.feedback import FeedbackController; fc=FeedbackController(0.15,0.40); ..."` → quota ok 3/20 min, 9 max, entropy 1.58
- Pilot: `python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 10 --candidates-per-round 20 --attack-families gadget,overwritten,external,indirect_chain,pypi_injected --family-quota-min-pct 0.15 --seed 42 --backend docker` (requires containers) → expect ≥1 per family (pilot log shows `family_counts` + `Family=100%/... ent>1.5`).

## Next
- 200-candidate pilot with quota-on vs off ablation; if quota-on yield <40% relax to 10% (see Risk Mitigation).
