# RegenBench Implementation Plan

## Context

A critical evaluation identified that the RegenBench implementation faithfully constructs the proposed pipeline architecture but fails to validate any of the three core hypotheses (H1, H2, H3). Four critical issues block scientific claims:

1. **Critical bug**: `PyPIInjectedTemplate` (the winning family per evaluation) is defined at `templates.py:132-149` but NOT registered in `FAMILY_TEMPLATES` at `templates.py:247-251`. Only 3 of 4 ShadowPickle families are selectable.
2. **Fitness signal mismatch**: `FeedbackController.update()` (`feedback.py:221-283`) only uses +2.0 for full evasion, never the lexicographic Tier 1 (+10000.0) bonus from `compute_fitness_lexicographic` (`fitness.py:113-157`). Result: guided underperforms unguided (0.29% vs 5.34%, p≈2.6×10⁻⁸).
3. **Broken oracle**: `EnsembleOracle.validate_torch()` (`oracle_ensemble.py:297`) uses AND-gate `dynahug_result and anomaly_result and executed` — DynaHug's 63.5% FP rate blocks all bypasses.
4. **Round-results dict missing keys**: `scripts/run_fuzzing_campaign.py:549-558` doesn't populate `transport` or `strategies` in feedback dict — even fixed controllers have no data.

Two deliverables:
- **D1**: AI assistant context file (CLAUDE.md) for token-efficient future sessions
- **D2**: Concrete fix plan covering all 5 priorities from the critique

---

## Deliverable 1: AI Assistant Context File (15 min)

Create `/home/d4sun/Projects/regenbench/CLAUDE.md` — a compact reference future AI sessions can read once instead of re-exploring ~5000 LOC.

**Sections**:
1. **Architecture overview** (one diagram + 6-line description): pipeline → scanner/oracle fan-out → tracking sink.
2. **Module map** (table): `pipeline/{generator,mutators,feedback,fitness,oracle_ensemble,validity,templates,shelf_life}.py` — role + key class.
3. **Critical files** (numbered): the 8 files most likely to be touched, with one-line "what lives here" summaries.
4. **Known bugs** (bullet list): pypi_injected missing from FAMILY_TEMPLATES; round_results missing transport/strategies; AND-gate suppresses oracle.
5. **Reusable patterns**: `_structurally_sane` (generator.py:23-47), `_trigger_exists` (validity.py:21-33), `NoveltyTracker.signature` (feedback.py:147-149), `CoverageTracker` (feedback.py:33-130).
6. **Common commands**: `run_fitness_ablation_experiment.sh`, `run_oracle_dominant_validation.sh`, `run_evaluation_suite.py`, container rebuild paths.
7. **Workflow recipe** (8-line): edit → `python -m pytest tests/test_generator_suite.py -x` → small campaign via `run_pilot_campaign.py` → full ablation.

**Acceptance**: future `claude` session reads CLAUDE.md instead of running 3 Explore agents.

---

## Deliverable 2: Fix Plan (Ordered by Dependencies)

### Phase 0 — Register `pypi_injected` (1-line, 15 min) — UNBLOCKS ALL

**File**: `pipeline/templates.py:247-251`

```python
FAMILY_TEMPLATES: dict[str, AttackTemplate] = {
    "overwritten": OverwrittenModuleTemplate(),
    "external": ExternalModuleTemplate(),
    "indirect_chain": IndirectChainTemplate(),
    "pypi_injected": PyPIInjectedTemplate(),  # NEW
}
```

Also add to `FAMILY_LABELS` (line 256-261): `"pypi_injected": "shadowpickle_pypi_injected"`.

**Acceptance**: `family_template("pypi_injected")` returns instance; `len(FAMILIES) == 5`.

---

### Phase 1 — Fix Fitness Signal (RQ2) — 2-3 days — CORE CLAIM

**Problem**: `FeedbackController.update()` never uses lexicographic Tier 1 bonus. Reinforces only callables (`+0.2*fit`) and families (`+2.0` for evasion). The winning combination `pypi_injected + splice` lives in neither space precisely.

**Files**:
- `pipeline/feedback.py:160-283` — add combo_weights, tier-based reinforcement
- `scripts/run_fuzzing_campaign.py:549-558` — populate `transport`, `strategies` keys
- `pipeline/db.py` — add `transport`, `strategies` columns to `campaign_fitness` schema (idempotent migration)

**New data structure**:
```python
# In FeedbackController.__init__ (after family_weights):
self.combo_weights: dict[tuple[str, str, frozenset[str]], float] = {}
# key = (family, transport, frozenset(strategies))
```

**Replace `feedback.py:247-256`** (binary `evaded_all` reinforcement) with tier-based:
```python
TIER1_WEIGHT = 5.0   # oracle-confirmed + valid (fit >= 10000)
TIER2_WEIGHT = 2.0   # panel-evading + valid (fit >= 1000)
TIER3_WEIGHT = 0.1   # valid only (fit > 0)

for res in round_results:
    fam = res.get("family")
    transport = res.get("transport", "loads")
    strategies = frozenset(res.get("strategies") or [])
    fit = res.get("fitness", 0.0)
    key = (fam, transport, strategies)
    if fit >= 10000.0:      delta = TIER1_WEIGHT
    elif fit >= 1000.0:     delta = TIER2_WEIGHT
    elif fit > 0.0:         delta = TIER3_WEIGHT
    else:                   delta = 0.0
    if delta > 0:
        self.combo_weights[key] = self.combo_weights.get(key, 1.0) + delta
        if fam in self.family_weights:
            self.family_weights[fam] += delta
```

**Populate `scripts/run_fuzzing_campaign.py:549-558`**:
```python
round_results.append({
    "callable": chosen_callable,
    "family": attack_family,
    "fitness": fit_score,
    "evaded_all": all(v == "benign" for v in panel_verdicts.values()),
    "valid": is_valid,
    "transport": cand_transport or "loads",
    "strategies": list(cand_strategies or []),
    "scanner_verdicts": scanner_verdicts,
    "matched_rules": matched_rules,
})
```

**New method `FeedbackController.get_combo_weights()`** — extended sampling at `scripts/run_fuzzing_campaign.py:271-280` to choose transport+strategies+family as a single weighted sample.

**Acceptance**: guided bypass rate > unguided by ≥2× with Fisher's exact p<0.01, via `run_fitness_ablation_experiment.sh` (≥5 replicates per mode).

---

### Phase 2 — Replace DynaHug gate with ValidityOracle (RQ3) — 1-2 days

**Problem**: AND-gate at `oracle_ensemble.py:297` suppresses true positives because DynaHug's 63.5% FP rate blocks all bypasses. `ValidityOracle._trigger_exists` (`validity.py:21-33`) already provides a deterministic check.

**Files**:
- `scripts/run_fuzzing_campaign.py:205-206, 385` — swap oracle for bypass confirmation
- `pipeline/oracle_ensemble.py` — deprecate `validate_torch`, keep DynaHug as opt-in supplementary
- `pipeline/plausibility.py` (new) — wrapper class

**New file `pipeline/plausibility.py`**:
```python
"""Deterministic bypass confirmation: payload executed + structurally valid."""
from pipeline.validity import ValidityOracle


class PlausibilityOracle:
    def __init__(self, validity_oracle: ValidityOracle):
        self.validity = validity_oracle

    def confirm(self, cand_bytes: bytes, trigger_file: str) -> bool:
        return self.validity.validate_torch(cand_bytes, trigger_file)
```

**Replace `scripts/run_fuzzing_campaign.py:385`**:
```python
# Old:
is_valid = oracle_val.validate_torch(cand_bytes, trigger_file)
# New:
plausibility = PlausibilityOracle(oracle_val)
is_valid = plausibility.confirm(cand_bytes, trigger_file)
```

Keep DynaHug as **supplementary signal** (`decision_score` still flows into `compute_fitness_oracle_aware` for the Tier-1 bonus detection), but bypass confirmation = `_trigger_exists` only.

**Acceptance**: FP rate on benign corpus (`scripts/fp_eval_oracle.py`) drops from 63.5% → <1%. Guided bypass rate improves ≥3× via `run_oracle_dominant_validation.sh`.

---

### Phase 3 — Generation improvements for novel families (RQ1) — 1-2 weeks

**3a. Differential pickle-parser generation** (3 days) — `pipeline/differential.py` (new).
```python
def differential_mutate(pkl_bytes, parsers=(parse_pickle, cloudpickle.loads)) -> list[bytes]:
    """Return variants that parse differently between parsers."""
```
Wire as new mutation operator in `generator.py:124`.

**3b. Family-synthesis mutation** (2 days) — `pipeline/mutators.py`. Add `mutate_family_synthesis`: combine signatures from two families (e.g., `overwritten`+`indirect_chain`).

**3c. MalHug corpus mining** (2 days) — extend `scripts/crawl_malhug.py`. Extract opcode frequency distributions from real malicious models; seed `PickleMutator.sample_strings`/`sample_ints`.

**3d. Plausibility constraints** (1 day) — pre-scan rejection in `pipeline/generator.py`: size ≤ 2× benign base, PyPI module in container image, torch.load returns dict-like state.

**Acceptance**: ≥3 novel `(family, strategy)` combinations evade ≥2 panel scanners. Novelty tracked by existing `NoveltyTracker.signature` method (`feedback.py:147-149`).

---

### Phase 4 — Phase 2 Shelf-life rescans (RQ4/H3) — 3-5 days

**Problem**: `shelf_life.py` and `scripts/shelf_life_rescan.py` exist with full infrastructure but zero rescans performed.

**Files**:
- `pipeline/scanners.py` — add `get_scanner_version(image)` via `podman inspect`
- `scripts/shelf_life_rescan.py` — wire into campaign workflow
- `scripts/generate_disclosure_report.py` (new) — embargo tracking + maintainer notification draft

**Workflow**:
1. `podman pull regenbench/{picklescan,modelscan,fickling}:latest`
2. `scanner.get_scanner_version(image)` → image ID hash
3. Pass versioned overrides to `ShelfLifeTracker.rescan_bypass()`
4. Populate `shelf_life.db` rescans table
5. `compute_decay_curve()` returns retention rate per version

**Acceptance**: ≥10 confirmed bypasses rescanned against ≥3 scanner version snapshots; decay curve plotted; disclosure draft generated.

---

### Phase 5 — Search efficiency — 1 week

**Files**: `scripts/run_fuzzing_campaign.py:73-74, 204-327`; `pipeline/generator.py`.

**Changes**:
1. `--candidates-per-round` default 20→50 (configurable up to 200)
2. Multi-cluster seeds via `--seed-cluster text-generation,text-classification,feature-extraction` (extends `crawl_benign.py`)
3. Wrap `generate_candidate_pt()` in `concurrent.futures.ProcessPoolExecutor` with N=min(cpu_count, 8)

**Acceptance**: same guided vs. unguided ratio in ≤40% wall-clock time.

---

## Critical Files for Implementation

| File | Phases | Why |
|------|--------|-----|
| `pipeline/templates.py:247-261` | P0 | Register `pypi_injected`, add `FAMILY_LABELS` entry |
| `pipeline/feedback.py:160-283` | P1 | Add `combo_weights`, tier-based reinforcement, `get_combo_weights()` |
| `scripts/run_fuzzing_campaign.py:205-558` | P1, P2 | Populate `transport`/`strategies` keys, swap oracle for `PlausibilityOracle` |
| `pipeline/oracle_ensemble.py` | P2 | Deprecate `validate_torch` AND-gate; keep as opt-in |
| `pipeline/validity.py` | P2 | Reuse existing `_trigger_exists` |
| `pipeline/differential.py` (new) | P3a | Cross-parser disagreement generation |
| `pipeline/mutators.py` | P3b | Family-synthesis mutation |
| `scripts/crawl_malhug.py` | P3c | Opcode distribution mining |
| `pipeline/shelf_life.py` | P4 | Wire rescans into workflow |
| `scripts/shelf_life_rescan.py` | P4 | Trigger rescans on scanner pull |
| `CLAUDE.md` (new, project root) | D1 | AI assistant context reference |

---

## Verification Plan

### Per-phase acceptance tests

| Phase | Test Script | Pass Criterion |
|-------|-------------|----------------|
| P0 | `python -c "from pipeline.templates import family_template, FAMILIES; assert family_template('pypi_injected'); assert len(FAMILIES) == 5"` | Pass |
| P1 | `run_fitness_ablation_experiment.sh` | Guided > unguided ≥2×, Fisher p<0.01 |
| P2 | `scripts/fp_eval_oracle.py` + `run_oracle_dominant_validation.sh` | FP<1%; bypass≥3× improvement |
| P3 | `scripts/test_generator_suite.py` (extend) | ≥3 novel `(family, strategy)` evading ≥2 scanners |
| P4 | `scripts/shelf_life_rescan.py --version-delta 3` | Decay curve generated; ≥10 bypasses rescanned |
| P5 | Wall-clock benchmark | ≤40% time for same throughput |

### End-to-end run

```bash
bash run_fitness_ablation_experiment.sh 5
bash run_oracle_dominant_validation.sh
python scripts/run_evaluation_suite.py
python -m pytest tests/ -x
```

---

## Risks and Open Questions

| Risk | Mitigation |
|------|------------|
| Phase 1 doesn't restore guided > unguided | Add per-round diagnostics logging tier transitions; tighten oracle first (Phase 2) if Tier 1 density too low |
| Phase 2 misses true positives | Keep `--ensemble-oracle` as opt-in cross-validation flag |
| Phase 3 novel families scanner-specific | Require novelty across ≥2 of {picklescan, modelscan, fickling} |
| Phase 4 needs image rebuilds | Tag images by date hash; reuse container CI |
| Phase 5 process pool races in validity oracle | Process pool bounded (≤8); unique trigger files per candidate (`tempfile.mkstemp`) |
| Existing `run_evaluation_suite.py` statistical tests fail at low N (per critique §3.5) | Phase 5 candidate count increase raises N; document bootstrap CIs collapse to [0,0] as expected |

### Open question for user

The `runner.py` `pre_filter.is_admitted()` at line 181-185 silently downgrades DynaHug-unfriendly artifacts to a benign verdict before they ever reach the oracle. This is independent of the AND-gate and may need its own fix — should I include this in Phase 2 or treat as a separate phase?

---

## Phase Dependencies

```
Phase 0 (1-line) ──┬── Phase 1 (fitness) ──┬── Phase 3 (generation)
                   │                       │
                   ��── Phase 2 (oracle)  ──┘
                                          │
                                          └── Phase 4 (shelf-life)
                                          │
                                          └── Phase 5 (efficiency)

D1 (CLAUDE.md) ── independent, can be done anytime
```

**Recommended order**: D1 → P0 → P1+P2 (parallel) → P3 → P4 → P5.
