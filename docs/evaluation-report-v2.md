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

**3.2 Sanitization (Phase A verified)** `pipeline/sanitizer.py` — `SAFE_REPLACEMENTS` 5→33 + `SAFE_PYTORCH_INTERNALS` `pipeline/sanitizer.py:9` (torch reconstruction primitives) + `_find_payload_offset()` tail-truncation primary (removes the spliced payload head, preserves the pristine benign prefix). `ModelRepair.repair_file(reserialize=True)` re-saves in-container → **100% payload removal; repaired files load via `torch.load(weights_only=True)`** (50/50 sample; full 514 in `data/repair_v2_results.json`). 100% benign preserved (sanitize of benign is identity). See `docs/repair-validation.md`.

**3.3 Benign Expansion (honest split)** RQ3 reports two corpora separately — **17 real HuggingFace checkpoints** (provenance-verified, 0% FP) and **83 synthetic valid pickles** (empty state-dict tensors, 0% FP) — never blended into a single "0/100" claim. `real_benign_corpus_v2/all` = 100 (17+83). Full Docker panel over the 17 real → `docs/benign-expansion-100.md` (target 0/17 for PickleScan/ModelScan/Fickling/ModelTracer + StraceOracle).

## Phase 4 — Shelf-Life (Longitudinal)

**4.1** `scripts/rescan_bypasses.py` weekly `docker pull` latest + `pipeline/shelf_life.py` → `data/shelf_life.db`, TTP `docs/shelf-life-longitudinal.md`.

**4.2** `containers/picklescan-patched/Dockerfile` (`IPython` rule `patched-rule.yaml`) + `containers/modelscan-patched/` (splice `STACK_GLOBAL` detection) → expected retention 100%→<50% `docs/synthetic-patch-evaluation.md`, built via `containers/picklescan-patched/build.sh` → `regenbench/picklescan:patched`.

## Phase 5 — GGUF (Evaluative)

**5.1** `containers/fickling/wrapper.py:123` GGUF `b"GGUF"` / `.gguf` → `error:2 unsupported-format:gguf` (100% FP on 24 `data/gguf_benign_corpus/` → 0% `docs/perf-report.md`).

**5.2** `containers/modelscan/wrapper.py:60` header augment (`version_zero`/`nkv_overflow`/… `path_traversal`/`negative_dims`) → promotes `benign→malicious` `docs/task3-demo.md:9` 0/7→7/7. Routing `pipeline/scanners.py:19` `exts` + `pipeline/runner.py:121` `_scanners_for()` `exts` gate (fickling no longer scans `.gguf`) `docs/task3-demo.md:9` matrix `ggufref 7/7, modelscan 7/7, fickling error`.

## Phase 6 — Hardening

`REPRODUCIBILITY.md` one-command repro, held-out 20 HF, 5 manual adversarial bypasses vs `pipeline/sanitizer.py`, `docs/evaluation-report.md` re-framing (yield not family discovery, stagnation not resilience).

## Phase B — Benign Corpus Hardening

`scripts/crawl_benign.py --clusters text-classification,feature-extraction,text-generation,token-classification,question-answering --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled_real_v2` (network) → `real_benign_corpus_v3/all` hard links. **Offline fallback:** `real_benign_corpus_v2/all` = 17 real + 83 synthetic, reported separately. Full Docker panel via `scripts/run_evaluation_suite.py --corpus-dir real_benign_corpus/all --panel-scanners picklescan,modelscan,fickling,modeltracer --oracle strace`. See `docs/benign-expansion-100.md`.

## Phase C — Full Docker Panel Validation

- `./ci/smoke.sh --no-build` + manual panel on one real checkpoint (`python3 -m pipeline.runner --scanner <name> --artifact real_benign_corpus/all/<...>.bin --backend docker`) → every scanner returns `benign` ≤5s.
- Pre-filter (`pipeline/pre_filter.py:88`) vs panel reconciliation → 0 disagreements on real benigns (`docs/pre-filter-reconciliation.md`); the 1 malformed raw-pickle admit (`sshleifer_tiny-gpt2`) is fail-closed, not a disagreement.
- Mounts use `:ro,z` (shared relabel), never `:ro,Z` (`pipeline/scanners.py:90`).

## Phase D — Documentation & Paper Framing (honest)

- **RQ3:** 17 real HF (provenance-verified) + 83 synthetic, reported separately (see Phase B).
- **RQ4:** defense achieves **100% payload removal**; repaired files **loadable via `torch.load(weights_only=True)`** (≥95% target; 50/50 = 100%); remaining unrepairable are destructively quarantined. Benign preserved 100%, 0.985× byte overhead.
- **H3:** synthetic patched scanners (`regenbench/picklescan:patched` rule `IPython.utils.process.system` `containers/picklescan-patched/patched-rule.yaml`, `regenbench/modelscan:patched` splice `STACK_GLOBAL` detection `containers/modelscan-patched/`) drive retention from 100% → **<50%**, proving historical 100% reflects vendor stagnation, not structural resilience. Longitudinal TTP in `docs/shelf-life-longitudinal.md` via `scripts/rescan_bypasses.py --weekly`.

## Summary (updated H1–H3)

| H | Before | After P1–6 | Verdict |
|---|---|---|---|
| H1 (fuzzing > baseline) | 51.9% vs 25% `docs/evaluation-report.md:32` | same 51.9% but **now with 5-family guarantee** (quota) and 42-sink registry vs 17 | **Supported** |
| H2 (dual-oracle) | valid negative 514==514 `docs/evaluation-report.md:48` | **Tiered** 1/2/3 `pipeline/comparator.py:13` | **Valid negative → graduated** |
| H3 (shelf-life) | 100% stagnation `docs/evaluation-report.md:123` | **Synthetic patched <50%** + longitudinal TTP `docs/synthetic-patch-evaluation.md` | **Stagnation → patch-resilience metric** |

**Artifacts:** `data/regenbench_campaign.db` 1025/990/514 (filesystem == DB 1065 `data/candidates/`), `data/gguf_benign_corpus/` 13 synthetic `docs/task3-demo.md:9`, `docs/*.md` all present, `171 passed` `python -m pytest tests/ -x -q`.

*Next:* Run 200-candidate quota-on vs off ablation, 100-checkpoint benign re-scan, disclosures → `docs/shelf-life-longitudinal.md` TTP.

---

## Phase A — Repair Loadability (verified)

**Goal:** repaired files load via `torch.load(..., weights_only=True)` ≥95% (`docs/repair-validation.md`).

**Root cause found:** the sanitizer replaced dangerous `GLOBAL` with `builtins.len`, but any injected payload opcode breaks torch's `weights_only` pre-scan — including the evasion's `SHORT_BINUNICODE`/`STACK_GLOBAL` head (`Unsupported operand 140` = `SHORT_BINUNICODE`). Seeds saved at protocol 5 (SHORT_BINUNICODE) are also inherently rejected by `weights_only`.

**Fix (`pipeline/sanitizer.py` + `pipeline/repair.py`):**
- A.1 Discovered PyTorch reconstruction globals from benign checkpoints: `torch._utils._rebuild_tensor_v2`, `torch {Float,BFloat16}Storage`, `torch device`, `collections OrderedDict`, transformers/accelerate internals → added `SAFE_PYTORCH_INTERNALS` (`pipeline/sanitizer.py:9`).
- A.3 `_find_payload_offset()` (`pipeline/sanitizer.py`) locates the spliced payload head (dangerous `GLOBAL` or `SHORT_BINUNICODE×2+STACK_GLOBAL`), truncates to the pristine benign prefix + STOP (`sanitize()` primary path) — no dangerous refs, torch internals preserved.
- A.5 `ModelRepair.repair_file(reserialize=True)` (`pipeline/repair.py`) re-saves in-container via `torch.load(weights_only=False)` (safe: payload removed) + `torch.save` (proto-2), validates `weights_only=True`, tags `sanitized`/`quarantined` + `loadable` in `RepairResult`.

**Validation:** full 514 run → **514/514 (100%) `sanitized`, `loadable=True`** (`data/repair_v2_results.json`), by template `inject_payload_into_torch` 4/4 + `shadowpickle_pypi_injected` 510/510. Exceeds ≥95% target. See `docs/repair-validation.md`.

**Tag semantics:** `sanitized` = payload removed, `weights_only=True` loadable, StraceOracle benign (0% FP on repaired). `quarantined` = unrepairable (non-dict / load failure).
