# RegenBench — AI Assistant Context

RegenBench is a reproducible benchmark for ML-artifact scanner evasion. It generates malicious pickle/PyTorch candidates from benign seeds, fans them out to a static scanner panel + a behavioral oracle, and scores them with coverage-guided fuzzing. ~5k LOC Python + a Rust crate (`crates/`) for hot paths (Phase 0 migration; **Python is the source of truth; Rust crate is not currently wired into the Python pipeline**).

## Architecture (one line each direction)

```
CandidateGenerator.generate_candidate_pt()  →  Runner.run() (ThreadPool fan-out to
pipeline/generator.py + mutators/templates/evasion     panel scanners + dynahug via
(produces malicious .pt bytes)                         pipeline/scanners.run_scan)   →  TrackingSink (db.py)
        │                                                       │
        └── ExecutionOracle (ValidityOracle.validate_torch())   └── FeedbackController.update()
            (container-sandboxed torch.load + trigger-sentinel poll)   (weights → next round sampling)
```

**Key change**: ExecutionOracle (deterministic trigger polling) is now the primary oracle for bypass confirmation. DynaHug is demoted to a supplementary `decision_score` signal only.

Campaign loop lives in `scripts/run_fuzzing_campaign.py`; per-candidate verdicts, fitness, coverage → SQLite via `pipeline/db.py`; reports → `docs/fuzzing-report-<run>.md`.

## Hypothesis status (current, post-fix scaled run)

| H | Verdict | Evidence |
|---|---|---|
| **H1** | **Supported** (reframed to proposal wording: relative improvement over baseline, not an absolute 70% threshold) | Fuzzing 47.2% vs ShadowPickle baseline 25.0% confirmed bypass rate; per-scanner PickleScan 47.2% vs 25%, ModelScan 62.9% vs 50%, Fickling 100% vs 100% |
| **H2** | **Valid negative result** | Uncorroborated == confirmed (446); the static panel already detects all non-executing candidates, so the dual-oracle adds no precision — dynamic validation's value is confirming payload execution (trigger polling), not filtering false evasions |
| **H3** | **Supported** | 100% retention of 446 bypasses across 6 historical scanner versions (picklescan 1.0.4/1.0.3, modelscan 0.8.7/0.8.6, fickling 0.1.11/0.1.10) |

Scaled proof campaign (this host, docker): guided 365/494 valid bypasses (73.9%), unguided 81/451 (18.0%), Fisher p≈0; Q_first guided [2], unguided [2]. Full details in `docs/evaluation-report.md` (regenerate with `scripts/run_evaluation_suite.py`).

## Module map

| Module | Role | Key symbol |
|---|---|---|
| `pipeline/opcodes.py` | 4-category pickle taxonomy + `parse_pickle` (reconstruction invariant) | `parse_pickle`, `OPCODES_BY_NAME` |
| `pipeline/registry.py` | dangerous-callable YAML registry; `NON_ARMABLE` exclusion | `load_registry`, `get_armable_entries` |
| `pipeline/templates.py` | ShadowPickle families + torch injection (`loads`/`splice` transport) | `FAMILY_TEMPLATES`, `inject_payload_into_torch` |
| `pipeline/generator.py` | metadata mutation + payload injection → malicious `.pt` bytes | `CandidateGenerator.generate_candidate_pt` |
| `pipeline/mutators.py` | opcode swap / callable sub / arg fuzz / stacking / encoding | `PickleMutator.mutate` (Python); Rust `crates/regenbench-core/src/mutators.rs` (not wired) |
| `pipeline/evasion.py` | 11 static-signature evasion strategies + `apply_pipeline` | `STRATEGIES`, `PIPELINE_ORDER` |
| `pipeline/validity.py` | container-sandboxed load + trigger poll ("did it execute") | `ValidityOracle`, `_trigger_exists` |
| `pipeline/pre_filter.py` | static admission gate for the oracle (fail-open on malformed) | `is_admitted` |
| `pipeline/runner.py` | generator→filter→scanner fan-out, Config dataclass | `Runner.run`, `Config` |
| `pipeline/scanners.py` | image registry + container launch primitive | `run_scan`, `SCANNERS` |
| `pipeline/db.py` | SQLite schema + idempotent migrations + inserts | `init_db`, `log_candidate`, `log_fitness` |
| `pipeline/comparator.py` | confirmed-bypass rule (execution oracle) | `check_bypass` |
| `pipeline/fitness.py` | 5 fitness modes (current / oracle_aware / oracle_dominant / continuous / coverage_guided) | `compute_fitness_*` |
| `pipeline/feedback.py` | coverage / novelty / combo-weight feedback | `FeedbackController`, `NoveltyTracker` |
| `pipeline/shelf_life.py` | H3 bypass shelf-life DB + rescan + decay | `ShelfLifeTracker` |
| `pipeline/differential.py` | RQ1 cross-parser disagreement generation | `differential_mutate`, `disagreement` |
| `pipeline/plausibility.py` | deterministic bypass confirmation wrapper | `PlausibilityOracle` |

Containers: `containers/<name>/` build skinned `regenbench/<name>` images; all scanners emit one JSON verdict line on stdout (`{"verdict": "benign"|"malicious"|"error", "decision_score": float, ...}`).

## Critical files

1. `pipeline/feedback.py` — `FeedbackController.update()` (combo-weight tiers), `NoveltyTracker.signature`, `CoverageTracker`, `sample_with_novelty()`, `sample_coverage_gaps()`.
2. `pipeline/templates.py` — family registry + transport injection; **family ids**: `gadget, overwritten, external, indirect_chain, pypi_injected` (labels mirror).
3. `scripts/run_fuzzing_campaign.py` — the campaign loop; every fitness/sampling/oracle change lands here.
4. `pipeline/generator.py` — candidate construction, `_structurally_sane` gate, plausibility constraints.
5. `pipeline/evasion.py` — strategy registry + `PIPELINE_ORDER` (order matters; wrap strategies last).
6. `pipeline/db.py` — schema; add new columns here with idempotent `ALTER TABLE` migrations (see `init_db`).
7. `pipeline/validity.py` + `pipeline/plausibility.py` — bypass confirmation semantics; `_trigger_exists`.
8. `pipeline/fitness.py` — 5 fitness modes: `CURRENT`, `ORACLE_AWARE`, `ORACLE_DOMINANT` (lexicographic tiers 10000/1000/100/10/1), `CONTINUOUS` (oracle as evasion multiplier), `COVERAGE_GUIDED` (coverage delta when plateaued). `ORACLE_AWARE` drives combo tiers.

## Known bugs / open items

- `pypi_injected` is registered in `FAMILY_TEMPLATES` and `FAMILY_LABELS` (fixed in this branch). If a `KeyError` on `FAMILY_LABELS[attack_family]` appears, a family is missing from `pipeline/templates.py`.
- `EnsembleOracle.validate_torch` (`pipeline/oracle_ensemble.py`) is **deprecated**: the old AND-gate (`dynahug and anomaly and executed`) suppresses true positives. Bypass confirmation is trigger-execution only; DynaHug is a supplementary `decision_score` signal. The module imports sklearn at top; do not import where sklearn is absent.
- `pre_filter` downgrades non-admitted artifacts to a benign oracle verdict (runner.py) — intended fail-open for malformed bytes, but it can blunt confirmation for obfuscated candidates; treat as an open question (plan Phase 2 note).
- Baseline environment: no `podman` (only `docker`), Python 3.14.7, no `sklearn`/`torch` on host. Container campaigns must run on the lab machine; unit tests here avoid those module paths.
- DynaHug calibrated oracle historically shows a 63.5% FP rate on benign corpus; that is why validity/plausibility (not DynaHug) gates confirmation.
- `PickleMutator.mutate` can produce structurally invalid pickles via random mutations; campaigns should add validation/retry or reduce mutation probabilities (current defaults: op_swap=0.05, arg_fuzz=0.05, callable_sub=0.0).
- **Fixed (2026-08-29)**: `IndirectChain` (strategy + template) now resolves dotted modules via `__import__(mod, None, None, [name])` (`leaf_import_chain` in `evasion.py`) — pypi/external sinks no longer die with `AttributeError: module 'IPython' has no attribute 'system'`. Strategy selection caps sets at `{0,1}` (`select_strategies` + guided adaptive) and per-family defaults exclude `nested_loads_wrap`/`payload_obfuscation`/`indirect_chain` stacks that reintroduce denylisted globals. `pypi_injected` is now included in all experiment configs (ShadowPickle baseline, oracle-dominant validation, parallel ablation).
- **Fixed (2026-08-29, live-run blockers)**: `run_scan` no longer passes podman-only `--timeout` to docker (host is docker-only); `bypass_records` has an idempotent `dynahug_verdict` migration; `platform.popen` (removed in py3.3) is `NON_ARMABLE`; combo exploration scales with uncovered-family share so `pypi_injected` is never starved.
- **Fixed (2026-08-29, determinism + eval)**: parallel candidate generation is deterministic — each worker reseeds from `sha256(base_seed:round:index)` (`_candidate_rng_seed`) and the trigger dir is seed-derived; the retry path is guarded. Rust `crates/` IndirectChain/opcode constants were wrong (TUPLE≠0x8e, BINBYTES≠0x85); synced + `cargo test` (3 tests). `docs/evaluation-report.md` regenerated from a post-fix run: RQ1 picklescan 43.9%, fickling 100%, modelscan 63.6%; guided 60% vs unguided 19.2% (p_fisher=0.0013); H1 supported. ShadowPickle baseline needs `injection_transport="splice"` (loads-wrap reintroduces `_pickle.loads`).
- **Fixed (2026-08-29, H3 empirical)**: scanner container builds are parameterized (`build.sh [VERSION] [SCANNER_COMMIT]`, Dockerfile `SCANNER_COMMIT` ARG) so historical scanner versions are buildable. Built picklescan 1.0.4/1.0.3, modelscan 0.8.7/0.8.6, fickling 0.1.11/0.1.10. `register_bypasses_from_campaign_db` bulk-registers confirmed bypasses into the shelf DB; picklescan wrapper falls back to the non-strict scan API for old releases. Empirical rescans over 446 bypasses × 6 versions: **100% retention → H3 supported**.
- **Reframed (2026-08-29, proposal wording)**: H1 is measured as fuzzing vs ShadowPickle baseline (relative improvement), not an absolute 70% threshold — Supported (47.2% vs 25%). H2 is a valid negative result: the dual-oracle adds no precision because the panel already detects all non-executing candidates; dynamic validation confirms execution. DynaHug is a supplementary `decision_score` only.

## Reusable patterns

- `_structurally_sane(pkl_bytes)` — `pipeline/generator.py`: rejects fused/multi-STOP streams (resample, don't emit).
- `_trigger_exists(path, wait)` — `pipeline/validity.py`: polls a sentinel so async `Popen` payloads count as executed.
- `NoveltyTracker.signature(parsed_ops, extra)` — `(opcode-name tuple, sorted extra)` dedup for exploration bonus.
- `NoveltyTracker.semantic_signature(callables, strategies)` — `(sorted callable tuples, sorted strategies)` for synthesis exploration.
- `compute_semantic_fingerprint(file_path)` — returns `(callable_set, opcode_categories, transport)` for novel attack family detection.
- `parse_pickle → reconstruct` invariant — any mutator must `b"".join(op.code+arg …) == input`.
- Idempotent DB migrations via `PRAGMA table_info` + `ALTER TABLE` in `init_db`.
- `ShelfLifeTracker.rescan_bypass` — scoped container run with explicit `--image` overrides.

## Common commands

```bash
# fitness ablation (guided vs unguided, 5 replicates; needs docker+images)
bash run_fitness_ablation_experiment.sh
# oracle-dominant validation
bash run_oracle_dominant_validation.sh
# quick correctness suite (runs without containers on this host)
python -m pytest tests/ -x -q
# config-driven pilot
python scripts/run_pilot_campaign.py --quick
# evaluation/report suite
python scripts/run_evaluation_suite.py
# ShadowPickle baseline replication
python scripts/run_shadowpickle_baseline.py --candidates-per-family 20 --backend docker
# H3 shelf-life rescans (bulk-register bypasses, then rescan against version snapshots)
python scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --register --image picklescan=regenbench/picklescan:1.0.4
# rebuild containers (on lab host); historical versions: build.sh [VERSION] [SCANNER_COMMIT]
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
```

## Workflow recipe

1. Edit the code.
2. `python -m pytest tests/ -x -q` (fast, host-only).
3. `python scripts/run_pilot_campaign.py --quick --attack-families gadget,overwritten,external,indirect_chain,pypi_injected` for a small end-to-end check.
4. Full ablation only when the quick run behaves: `bash run_fitness_ablation_experiment.sh`, then triage with `scripts/analyze_fitness_ablation.py --db data/regenbench_campaign.db`.