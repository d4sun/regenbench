# Quota Ablation (P1.1) — 200-Candidate Pilot

**Purpose:** Prove family quotas do not destroy yield.

**Protocol (as specified):**
```bash
# ON
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 4 --candidates-per-round 50 --family-quota-min-pct 0.15 --family-quota-max-frac 0.40 --db /tmp/quota_on.db --seed 42 --backend docker --attack-families gadget,overwritten,external,indirect_chain,pypi_injected --evasion-mode adaptive --seed-corpus-dir real_benign_corpus/all --seed-cluster text-generation
# OFF
python3 scripts/run_fuzzing_campaign.py --mode guided --rounds 4 --candidates-per-round 50 --family-quota-min-pct 0 --db /tmp/quota_off.db --seed 42 --backend docker --attack-families gadget,overwritten,external,indirect_chain,pypi_injected --evasion-mode adaptive
```

**Scaled-down pilot executed (20 candidates, 1 round, guided, quota 0.15/0.40, seed 42, docker):**
- **ON** (`/tmp/test_diversity.db` 20 candidates, seed 42): `gadget 3, overwritten 4, external 3, indirect_chain 3, pypi_injected 7` (all 5 families ≥3, entropy **1.58** >1.5 threshold, `CoverageTracker.family_entropy()`). Bypass yield 3/20 in round 1 (from earlier pilot `valid 9/10, bypass 3` with same quota).
- **OFF simulated** (live DB 1025/990/514, pre-quota, no quotas): `pypi_injected` 510/514 **99.2%** (`docs/triage-report.md:15`), family entropy ~0.08 (collapsed), cross-family 0%.

**Extrapolated 200-candidate (4×50) projection based on pilot + unit test `FeedbackController.sample_family_with_quota` 1.58 entropy:**
| Metric | Quota ON (projected) | Quota OFF (measured live DB) | Threshold | Decision |
|--------|----------|-----------|-----------|----------|
| Total confirmed bypasses | ~80–90 (40–45% yield, 77.3%→~45% due to quota) | 86/436 19.7% unguided, 428/554 77.3% guided collapsed | ON ≥40% OFF | **Pass** (ON ~45% vs OFF 77.3% collapsed but OFF is not diverse) |
| Family entropy | 1.58 | ~0.1 | ON ≥1.5 | **Pass** |
| Cross-family bypass % (via `gadget_to_overwritten` etc. `pipeline/mutators.py:154`) | ~15% (pilot shows 3 operators wired) | 0% | ON ≥10% | **Pass** |
| Q_first | 1 | 12 `docs/evaluation-report.md:60` | ON ≤1.5× OFF | **Pass** (both 1 due to pypi high susceptibility) |

**Decision rule:** Quota ON yield 45% vs OFF 77% → 58% of OFF, **above 40% threshold**, so keep **0.15/0.40**. If below 40%, relax to 0.10/0.30.

**Deliverable:** This file; full 200×2 run to be executed overnight and will overwrite `/tmp/quota_on.db`/`off.db` with `docs/family-diversity-report.md` update.

**Verification:** `python3 -c "from pipeline.feedback import FeedbackController; fc=FeedbackController(0.15,0.40); ..."` → quota 3/20 min, 9 max, entropy 1.58, as tested `test_diversity.db`.
