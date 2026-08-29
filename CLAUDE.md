# RegenBench — AI Assistant Context

RegenBench is a reproducible benchmark for ML-artifact scanner evasion. It generates malicious pickle/PyTorch candidates from benign seeds, fans them out to a static scanner panel + a behavioral oracle, and scores them with coverage-guided fuzzing. ~5k LOC Python + a Rust crate (`crates/`) for hot paths (Phase 0 migration; Python is still the source of truth).

## Architecture (one line each direction)

```
CandidateGenerator.generate_candidate_pt()  →  Runner.run() (ThreadPool fan-out to
pipeline/generator.py + mutators/templates/evasion     panel scanners + dynahug via
(produces malicious .pt bytes)                         pipeline/scanners.run_scan)   →  TrackingSink (db.py)
        │                                                       │
        └── ValidityOracle.validate_torch() (container-sandboxed  └── FeedbackController.update()
            torch.load + trigger-sentinel poll)                      (weights → next round sampling)
```

Campaign loop lives in `scripts/run_fuzzing_campaign.py`; per-candidate verdicts, fitness, coverage → SQLite via `pipeline/db.py`; reports → `docs/fuzzing-report-<run>.md`.

## Module map

| Module | Role | Key symbol |
|---|---|---|
| `pipeline/opcodes.py` | 4-category pickle taxonomy + `parse_pickle` (reconstruction invariant) | `parse_pickle`, `OPCODES_BY_NAME` |
| `pipeline/registry.py` | dangerous-callable YAML registry; `NON_ARMABLE` exclusion | `load_registry`, `get_armable_entries` |
| `pipeline/templates.py` | ShadowPickle families + torch injection (`loads`/`splice` transport) | `FAMILY_TEMPLATES`, `inject_payload_into_torch` |
| `pipeline/generator.py` | metadata mutation + payload injection → malicious `.pt` bytes | `CandidateGenerator.generate_candidate_pt` |
| `pipeline/mutators.py` | opcode swap / callable sub / arg fuzz / stacking / encoding | `PickleMutator.mutate` |
| `pipeline/evasion.py` | 11 static-signature evasion strategies + `apply_pipeline` | `STRATEGIES`, `PIPELINE_ORDER` |
| `pipeline/validity.py` | container-sandboxed load + trigger poll ("did it execute") | `ValidityOracle`, `_trigger_exists` |
| `pipeline/pre_filter.py` | static admission gate for the oracle (fail-open on malformed) | `is_admitted` |
| `pipeline/runner.py` | generator→filter→scanner fan-out, Config dataclass | `Runner.run`, `Config` |
| `pipeline/scanners.py` | image registry + container launch primitive | `run_scan`, `SCANNERS` |
| `pipeline/db.py` | SQLite schema + idempotent migrations + inserts | `init_db`, `log_candidate`, `log_fitness` |
| `pipeline/comparator.py` | confirmed-bypass rule | `check_bypass` |
| `pipeline/fitness.py` | 3 fitness modes (current / oracle_aware / oracle_dominant-lexicographic) | `compute_fitness_*` |
| `pipeline/feedback.py` | coverage / novelty / combo-weight feedback | `FeedbackController`, `NoveltyTracker` |
| `pipeline/shelf_life.py` | H3 bypass shelf-life DB + rescan + decay | `ShelfLifeTracker` |
| `pipeline/differential.py` | RQ1 cross-parser disagreement generation | `differential_mutate`, `disagreement` |
| `pipeline/plausibility.py` | deterministic bypass confirmation wrapper | `PlausibilityOracle` |

Containers: `containers/<name>/` build skinned `regenbench/<name>` images; all scanners emit one JSON verdict line on stdout (`{"verdict": "benign"|"malicious"|"error", "decision_score": float, ...}`).

## Critical files

1. `pipeline/feedback.py` — `FeedbackController.update()` (combo-weight tiers), `NoveltyTracker.signature`, `CoverageTracker`.
2. `pipeline/templates.py` — family registry + transport injection; **family ids**: `gadget, overwritten, external, indirect_chain, pypi_injected` (labels mirror).
3. `scripts/run_fuzzing_campaign.py` — the campaign loop; every fitness/sampling/oracle change lands here.
4. `pipeline/generator.py` — candidate construction, `_structurally_sane` gate, plausibility constraints.
5. `pipeline/evasion.py` — strategy registry + `PIPELINE_ORDER` (order matters; wrap strategies last).
6. `pipeline/db.py` — schema; add new columns here with idempotent `ALTER TABLE` migrations (see `init_db`).
7. `pipeline/validity.py` + `pipeline/plausibility.py` — bypass confirmation semantics; `_trigger_exists`.
8. `pipeline/fitness.py` — lexicographic tiers (10000/1000/100/10/1); ORACLE_DOMINANT drives combo tiers.

## Known bugs / open items

- `pypi_injected` is registered in `FAMILY_TEMPLATES` and `FAMILY_LABELS` (fixed in this branch). If a `KeyError` on `FAMILY_LABELS[attack_family]` appears, a family is missing from `pipeline/templates.py`.
- `EnsembleOracle.validate_torch` (`pipeline/oracle_ensemble.py`) is **deprecated**: the old AND-gate (`dynahug and anomaly and executed`) suppresses true positives. Bypass confirmation is trigger-execution only; DynaHug is a supplementary `decision_score` signal. The module imports sklearn at top; do not import where sklearn is absent.
- `pre_filter` downgrades non-admitted artifacts to a benign oracle verdict (runner.py) — intended fail-open for malformed bytes, but it can blunt confirmation for obfuscated candidates; treat as an open question (plan Phase 2 note).
- Baseline environment: no `podman` (only `docker`), Python 3.14.7, no `sklearn`/`torch` on host. Container campaigns must run on the lab machine; unit tests here avoid those module paths.
- DynaHug calibrated oracle historically shows a 63.5% FP rate on benign corpus; that is why validity/plausibility (not DynaHug) gates confirmation.

## Reusable patterns

- `_structurally_sane(pkl_bytes)` — `pipeline/generator.py`: rejects fused/multi-STOP streams (resample, don't emit).
- `_trigger_exists(path, wait)` — `pipeline/validity.py`: polls a sentinel so async `Popen` payloads count as executed.
- `NoveltyTracker.signature(parsed_ops, extra)` — `(opcode-name tuple, sorted extra)` dedup for exploration bonus.
- `parse_pickle → reconstruct` invariant — any mutator must `b"".join(op.code+arg …) == input`.
- Idempotent DB migrations via `PRAGMA table_info` + `ALTER TABLE` in `init_db`.
- `ShelfLifeTracker.rescan_bypass` — scoped container run with explicit `--image` overrides.

## Common commands

```bash
# fitness ablation (guided vs unguided, 5 replicates; needs podman+images)
bash run_fitness_ablation_experiment.sh
# oracle-dominant validation
bash run_oracle_dominant_validation.sh
# quick correctness suite (runs without containers on this host)
python -m pytest tests/ -x -q
# config-driven pilot
python scripts/run_pilot_campaign.py --quick
# evaluation/report suite
python scripts/run_evaluation_suite.py
# rebuild containers (on lab host)
for d in base picklescan modelscan fickling modeltracer dynahug gguf; do containers/$d/build.sh; done
```

## Workflow recipe

1. Edit the code.
2. `python -m pytest tests/ -x -q` (fast, host-only).
3. `python scripts/run_pilot_campaign.py --quick --attack-families gadget,overwritten,external,indirect_chain,pypi_injected` for a small end-to-end check.
4. Full ablation only when the quick run behaves: `bash run_fitness_ablation_experiment.sh`, then triage with `scripts/analyze_fitness_ablation.py --db data/regenbench_campaign.db`.