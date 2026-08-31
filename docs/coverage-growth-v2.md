# Coverage Growth v2 (P1.4)

**Fix:** `pipeline/feedback.py:116` `REACHABLE_OPCODES` 58, `pipeline/db.py:116` `campaign_coverage` now `family_coverage, family_bypass_coverage, entropy` `pipeline/db.py:156`, `CoverageTracker.log_round(family_counts)` `pipeline/feedback.py:235` instruments post-mutation stream.

## Live Growth (1025/990/514, 2 runs)
- Opcode: guided 45.6→45.6% flat, unguided 45.6→48.5% → max 48.5% (58 reachable) `docs/evaluation-report.md:99`
- Callable: 28→60% guided, 24→80% unguided → max 80% (33 armable after registry 42) — **callable is primary fitness** `pipeline/fitness.py:159` `coverage_guided`
- Family entropy: guided ~1.2, unguided ~1.5 (uniform 1.61) `docs/evaluation-report.md:103`

## Targets
- Opcode ≥60% (add per-family default strategy sets `pipeline/feedback.py:485` already), caregiver novelty bonus `NoveltyTracker.score_semantic` `pipeline/feedback.py:304` 1/(1+count) with 2× weight `pipeline/feedback.py:479`.
- Hold callable ≥80% (already).
- Plot: `python scripts/run_fuzzing_campaign.py --rounds 25 --candidates-per-round 20` → `docs/fuzzing-report-guided-r1.md` per-round `Opcode Coverage | Callable Coverage | Family bypass | Entropy`.

## Verification
- `sqlite3 data/regenbench_campaign.db "SELECT run_id, round_num, opcode_coverage, callable_coverage, family_coverage, entropy FROM campaign_coverage ORDER BY run_id, round_num;"`
- If opcode <60% after 1.2, check `_track_parsed` `pipeline/feedback.py:185` correctly recurses into nested `BINBYTES` (it does).
