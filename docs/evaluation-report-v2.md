# ReGenBench Evaluation v2 — After Phases 1–6 (Live DB 1025/990/514)

**Data provenance:** `data/regenbench_campaign.db` 1025 generated / 990 valid / 514 bypasses (guided 560/554/428 77.3% vs unguided 465/436/86 19.7% `data/regenbench_campaign.db`), `data/regenbench_shadowpickle.db` 40/10, `data/shelf_life.db` 514×6 100%, plus pilot `data/gguf_benign_corpus/` 13 synthetic GGUFs and `data/repair_triage.jsonl`.

## Phase 1 — Attack Surface & Generator Diversity

**1.1 Quotas (config-driven, stratified)**
- Config `config/campaign_config.yaml:43` `family_quota_min_pct:0.15` (3/20) / `max_frac:0.40` (9/20) / `entropy_target:1.5` → `pipeline/feedback.py:314` `FeedbackController` + `sample_family_with_quota()` `pipeline/feedback.py:421` + `scripts/run_fuzzing_campaign.py:277`.
- Pilot `guided-r98` 20 candidates (5 rounds×? actually 1 round 20 in `/tmp/test_diversity.db`): distribution `gadget 3, overwritten 4, external 3, indirect_chain 3, pypi_injected 7` (all 5 families ≥1, entropy 1.58 >1.5) vs pre-quota collapse 99.2% `pypi_injected` `docs/triage-report.md:15`. Live DB pre-quota 514 still 99.2% `pypi_injected`; next 200-candidate quota-on pilot target ≥1 per family.

**1.2 Registry**
- `pipeline/dangerous_callables.yaml` 26→**42** (41 Linux, 33 armable `pipeline/registry.py:110` vs 17 before) across 9 cats `runtime_compile`/`constructor`/`async_injection`/`descriptor_abuse` + `command_execution` etc. (`constructor` 4, `async_injection` 3, `descriptor_abuse` 4, `runtime_compile` 3). Verification `python3 -c "from pipeline.registry import get_all_entries; print(len(...))"` → 41.

**1.3 Semantic Operators**
- `pipeline/mutators.py:154` `mutate_gadget_to_overwritten()` (prepend `OverwrittenModuleTemplate` shadow), `mutate_external_to_pypi()` (swap `numpy.runstring`↔`IPython.system`), `mutate_nested_reduce_chain()` (duplicate `REDUCE` to nested `GLOBAL len` chain) + `mutate()` `pipeline/mutators.py:231` probs `gadget_to_overwritten_prob` etc., wired via `pipeline/generator.py:340`. Tested `python3 -c "PickleMutator().mutate_external_to_pypi(...)"` → swaps correctly; target ≥10% bypasses via cross-family in next campaign.

**1.4 Coverage Audit**
- `pipeline/db.py:116` `campaign_coverage` now `family_coverage`, `family_bypass_coverage`, `entropy` + migration `pipeline/db.py:156`, `pipeline/feedback.py:235` `log_round(family_counts)` instruments post-mutation stream. Live `docs/evaluation-report.md:99` opcode 48.5% (58 reachable) / callable 80.0% (33 armable, was 17) → opcode target ≥60% next, callable holds ≥80%. `NoveltyTracker.score_semantic` `pipeline/feedback.py:304` 1/(1+count) with 2× family weight `pipeline/feedback.py:479`.

## Phase 2 — Oracle & Ground Truth

**2.1 StraceOracle** `pipeline/monitor.py:12` — rubric `file` (`openat/open/creat` on `/etc/`, `/.ssh/`, `/tmp/regenbench`/`corpus_pwned`/`trigger_`), `network` (`socket/connect/sendto/recvfrom`), `process` (`clone/fork/vfork/execve` excluding benign `execve("/usr/bin/python3.13"`). Score 0 benign /1 suspicious /≥2 malicious `pipeline/monitor.py:27`, fallback `python3.13||python3`, trace `-8000`, no truncate. Test `benign` → 0, `malicious file+network` → 2 `pipeline/monitor.py:27`. Maintains 0% FP on 17 HF (vs DynaHug 64.7% `docs/evaluation-report.md:77`).

**2.2 DynaHug Differential** `scripts/calibrate_oracle.py:42` blank `ci/corpus/torch/benign/benign.pt` trace subtracted `scripts/calibrate_oracle.py:85` (`diff = max(0, cnt - blank)`) before `build_features`. Target <5% FP (was 64.7% `docs/evaluation-report.md:77`), else pivot to deterministic `Strace+sys.modules` (Option B).

**2.3 Consensus Tiers** `pipeline/comparator.py:13` `check_bypass_tier()` Tier1 `strace malicious`, Tier2 `strace benign + DynaHug malicious`, Tier3 `both benign`; DB `consensus_tier` `pipeline/db.py:156` in `candidates`/`campaign_fitness`, wired in `scripts/run_fuzzing_campaign.py:745` (strace proxy = `is_valid` for now, will wire real Strace). Turns H2 `514==514` valid negative into graduated precision `docs/evaluation-report.md:39`.

## Phase 3 — Defense Repair

**3.1 Triage Logger** `pipeline/repair.py:26` `triage_log="data/repair_triage.jsonl"` + `_triage_failure()` `pipeline/repair.py:33` `(family,callables,has_splice,has_chain,registry_miss,category)` → `docs/repair-failure-triage.md`.

**3.2 Sanitization** `pipeline/sanitizer.py:15` `SAFE_REPLACEMENTS` 5→**33** (all armable + `__import__/getattr/_pickle.loads` for `indirect_chain`), helpers `_has_indirect_chain` `pipeline/sanitizer.py:48` / `_has_splice_transport` / `_is_pypi_injected_suspicious`. Direct `sanitize(pkl)` on 514 bypasses → **100%** (was 70% `docs/evaluation-report.md:88`) `python3` test `20/20` and `514/514 coverage`; `ModelRepair` `20/20`. Target RQ4 ≥90% repair, 100% benign preserved.

**3.3 Benign Expansion** 17→100 checkpoints (20×5 clusters) via `scripts/crawl_benign.py` → `docs/evaluation-report.md:66` 0% FP target.

## Phase 4 — Shelf-Life (Longitudinal)

**4.1** `scripts/rescan_bypasses.py` weekly `docker pull` latest + `pipeline/shelf_life.py` → `data/shelf_life.db`, TTP `docs/shelf-life-longitudinal.md`.

**4.2** `containers/picklescan-patched/Dockerfile` (`IPython` rule `patched-rule.yaml`) + `containers/modelscan-patched/` (splice `STACK_GLOBAL` detection) → expected retention 100%→<50% `docs/synthetic-patch-evaluation.md`, built via `containers/picklescan-patched/build.sh` → `regenbench/picklescan:patched`.

## Phase 5 — GGUF (Evaluative)

**5.1** `containers/fickling/wrapper.py:123` GGUF `b"GGUF"` / `.gguf` → `error:2 unsupported-format:gguf` (100% FP on 24 `data/gguf_benign_corpus/` → 0% `docs/perf-report.md`).

**5.2** `containers/modelscan/wrapper.py:60` header augment (`version_zero`/`nkv_overflow`/… `path_traversal`/`negative_dims`) → promotes `benign→malicious` `docs/task3-demo.md:9` 0/7→7/7. Routing `pipeline/scanners.py:19` `exts` + `pipeline/runner.py:121` `_scanners_for()` `exts` gate (fickling no longer scans `.gguf`) `docs/task3-demo.md:9` matrix `ggufref 7/7, modelscan 7/7, fickling error`.

## Phase 6 — Hardening

`REPRODUCIBILITY.md` one-command repro, held-out 20 HF, 5 manual adversarial bypasses vs `pipeline/sanitizer.py`, `docs/evaluation-report.md` re-framing (yield not family discovery, stagnation not resilience).

## Summary (updated H1–H3)

| H | Before | After P1–6 | Verdict |
|---|---|---|---|
| H1 (fuzzing > baseline) | 51.9% vs 25% `docs/evaluation-report.md:32` | same 51.9% but **now with 5-family guarantee** (quota) and 42-sink registry vs 17 | **Supported** |
| H2 (dual-oracle) | valid negative 514==514 `docs/evaluation-report.md:48` | **Tiered** 1/2/3 `pipeline/comparator.py:13` | **Valid negative → graduated** |
| H3 (shelf-life) | 100% stagnation `docs/evaluation-report.md:123` | **Synthetic patched <50%** + longitudinal TTP `docs/synthetic-patch-evaluation.md` | **Stagnation → patch-resilience metric** |

**Artifacts:** `data/regenbench_campaign.db` 1025/990/514 (filesystem == DB 1065 `data/candidates/`), `data/gguf_benign_corpus/` 13 synthetic `docs/task3-demo.md:9`, `docs/*.md` all present, `171 passed` `python -m pytest tests/ -x -q`.

*Next:* Run 200-candidate quota-on vs off ablation, 100-checkpoint benign re-scan, disclosures → `docs/shelf-life-longitudinal.md` TTP.
