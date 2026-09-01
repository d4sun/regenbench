# ReGenBench — Architecture

Deep-dive on how ReGenBench is built: the end-to-end pipeline, the container
stack, the per-candidate lifecycle, the database schema, the module map, and
the invariants that hold the system together.

See [`README.md`](README.md) for the one-paragraph overview, [`IMPLEMENTATION.md`](IMPLEMENTATION.md)
for how each module works, and [`RESULTS.md`](RESULTS.md) for measured results.

---

## 1. End-to-end pipeline

```
  real benign corpus                malicious candidates             verdicts / feedback
  (100 HF checkpoints,             (.pt bytes, trigger sentinel)     (SQLite + fuzzing reports)
  data/crawled + flat links)               │                                  ▲
        │                                   ▼                                  │
        ▼                          CandidateGenerator                    FeedbackController
  seed selection               pipeline/generator.py                    pipeline/feedback.py
  (smallest zip-valid           (templates + mutators +                 coverage / novelty /
  <cluster>__<repo>.bin)         evasion strategies)                    combo weights
        │                                   │                                  ▲
        │                                   ▼                                  │
        │                          _structurally_sane(pkl)                     │
        │                          (reject fused/multi-STOP)                    │
        │                                   │                                   │
        │                                   ▼                                   │
        │                          Runner.run (ThreadPool fan-out)              │
        │                          pipeline/runner.py + scanners.py             │
        │                                  │                                    │
        │                                  ├──► static panel                     │
        │                                  │    picklescan │ fickling │ modelscan│
        │                                  │    (container, one JSON verdict)     │
        │                                  │                                     │
        │                                  ├──► dynahug oracle                    │
        │                                  │    (decision_score — supplementary)  │
        │                                  │                                     │
        │                                  └──► ExecutionOracle                    │
        │                                       pipeline/validity.py + plausibility.py
        │                                       container torch.load(weights_only=False)
        │                                       + _trigger_exists sentinel poll
        │                                                  │
        │                                                  ▼
        │                                       check_bypass (pipeline/comparator.py)
        │                                       confirmed = executed AND panel all_benign
        │                                                  │
        │                                                  ▼
        └────────────────────────────────► SQLite (pipeline/db.py)
                                            candidates, campaign_fitness,
                                            panel_results, oracle_results,
                                            campaign_coverage, campaign_runs
```

Every candidate in a campaign round flows generate → validate → scan →
score → record. The recorded fitness/coverage feed the next round's family and
callable sampling.

## 2. Container stack

```
  host (Python 3.10+, PyYAML, huggingface_hub; no torch/sklearn)
    │ docker
    ▼
  regenbench/base ─────────────────────────────── base image (torch + runtime)
    ├── regenbench/picklescan ── static pickle scanner (verdict JSON on stdout)
    ├── regenbench/fickling    ── AST/graph analyzer (torch-capable allowlist)
    ├── regenbench/modelscan   ── ML-artifact scanner
    ├── regenbench/modeltracer ── strace-based tracer (NOT used for torch FP)
    ├── regenbench/dynahug     ── behavioral oracle + calibration target
    └── regenbench/gguf        ── GGUF format-complexity demo / reference oracle
```

- Each scanner/oracle emits **one JSON verdict line** on stdout:
  `{"verdict": "benign"|"malicious"|"error", "decision_score": float, ...}`.
  The host parses the last stdout line (`pipeline/scanners.py:run_scan`).
- **`regenbench/gguf` (`ggufref`)** is the GGUF reference oracle (ggml-org
  reader + Jinja2 SSTI render). All GGUF scanning goes through the single
  `run_scan(gguf_ref=True)` path, which isolates the SSTI render: `--network
  none`, container-scoped `--tmpfs /tmp`, no host filesystem access
  (trigger detection happens by polling *inside* the container). On
  SELinux-enforcing hosts the artifact mount may additionally need
  `--security-opt label=disable` (not required on SELinux-absent hosts).
  `Runner` routes `.gguf` → `ggufref` via `SCANNERS` exts; the demos
  (`demo_task3.py`, `run_task3_demo.py`), `validity.validate_gguf`, and
  `run_known_answers._gguf_run` all call the same path.
- Artifacts are mounted read-only with a **shared SELinux label** (`:ro,z`).
  A private relabel (`:ro,Z`) would race under concurrent scans and crash
  containers nondeterministically (`scripts/verify_host.sh` probes this).
- Historical scanner versions (H3 shelf-life) are buildable via
  `containers/<name>/build.sh [VERSION] [SCANNER_COMMIT]`
  (e.g. `regenbench/picklescan:1.0.4`, `regenbench/modelscan:0.8.7`,
  `regenbench/fickling:0.1.11`).

## 3. Per-candidate lifecycle

```
 generate ─► _structurally_sane(pkl_bytes)        reject fused/multi-STOP streams
    │
    ▼
 pre_filter.is_admitted(pkl_bytes)                static admission gate
    │   (fail-open: malformed → synthetic benign oracle verdict)
    ▼
 ExecutionOracle.validate_torch(bytes, trigger)   container torch.load(weights_only=False)
    │                                             + poll trigger sentinel (async Popen counts)
    ▼
 Runner.run → panel: [picklescan, fickling, modelscan] + dynahug
    │          (one docker run per scanner; verdicts + decision_score)
    ▼
 check_bypass(panel_verdicts, execution_verdict)  confirmed = executed AND all_benign
    │
    ▼
 track_candidate → coverage (opcodes, callables, family, entropy)
 compute_fitness → guided / unguided
 log_candidate + log_fitness + panel/oracle results  (pipeline/db.py)
    │
    ▼
 FeedbackController.update(round_results)          weights → next round sampling
```

Bypass confirmation is **execution-gated**: a candidate is a *confirmed bypass*
only when the ExecutionOracle observed the payload actually execute (trigger
file written) **and** every static scanner returned `benign`. An "error" scanner
verdict never counts as evasion.

## 4. Database schema (`data/regenbench_campaign.db`)

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `candidates` | one row per generated candidate (both formats) | `candidate_id`, `filepath`, `round_num`, `seed_model`, `mutation_template` (family), `callables_used`, `run_id`, `panel_verdict`, `format` (`pt`/`gguf`), `attack_primitives` (JSON), `format_specific` (JSON) |
| `campaign_fitness` | per-candidate scoring | `fitness_score`, `is_valid`, `transport`, `strategies`, `consensus_tier` |
| `panel_results` | per-scanner verdict | `(candidate_id, scanner)`, `verdict`, `exit_code`, `findings`, `duration` |
| `oracle_results` | dynahug decision score | `verdict`, `decision_score`, `pre_filtered`, `duration` |
| `campaign_coverage` | per-round coverage | `opcode_coverage`, `callable_coverage`, `family_coverage`, `family_bypass_coverage`, `entropy` |
| `campaign_runs` | run metadata | `run_id`, `campaign_type`, `replicate_num`, `base_checkpoint`, `total_candidates` |

Migrations are idempotent (`PRAGMA table_info` + `ALTER TABLE` in
`pipeline/db.py:init_db`), so re-running a script never breaks an existing DB.

## 5. Module map

| Module | Role |
|--------|------|
| `pipeline/opcodes.py` | 4-category pickle taxonomy + `parse_pickle` (reconstruction invariant) |
| `pipeline/registry.py` | dangerous-callable YAML registry; `NON_ARMABLE` exclusion |
| `pipeline/templates.py` | ShadowPickle families + torch injection (`loads`/`splice` transport) |
| `pipeline/generator.py` | metadata mutation + payload injection → malicious `.pt` bytes |
| `pipeline/mutators.py` | opcode swap / callable sub / arg fuzz / stacking / encoding |
| `pipeline/evasion.py` | 11 static-signature evasion strategies + `PIPELINE_ORDER` |
| `pipeline/validity.py` | container-sandboxed load + trigger poll (`_trigger_exists`) |
| `pipeline/monitor.py` | `StraceOracle` (0% FP strace oracle) + `LoadTimeMonitor` |
| `pipeline/pre_filter.py` | static admission gate (fail-open on malformed) |
| `pipeline/runner.py` | generator→filter→scanner fan-out; `Config` dataclass |
| `pipeline/scanners.py` | image registry + container launch primitive (`run_scan`) |
| `pipeline/db.py` | SQLite schema + idempotent migrations + inserts |
| `pipeline/comparator.py` | confirmed-bypass rule (execution oracle gates) |
| `pipeline/fitness.py` | 5 fitness modes (current / oracle_aware / oracle_dominant / continuous / coverage_guided) |
| `pipeline/feedback.py` | coverage / novelty / combo-weight feedback; family quotas |
| `pipeline/shelf_life.py` | H3 bypass shelf-life DB + rescan + decay |
| `pipeline/defense.py` | defense orchestration (sanitize / repair / quarantine) |
| `pipeline/sanitizer.py` | static sink rewriting (5 direct sinks) |
| `pipeline/repair.py` | repair decision + quarantine policy |
| `pipeline/differential.py` | RQ1 cross-parser disagreement generation |
| `pipeline/gguf_tools.py` | GGUF v3 builder + 7 attack families (SSTI + 6 malformed-header) | `build_gguf`, `benign_gguf`, `generate_candidate_gguf` |

## 6. Key invariants

1. **`parse_pickle → reconstruct`**: any mutator must satisfy
   `b"".join(op.code + arg ...) == input`. A mutation that breaks this is
   rejected before a candidate is emitted.
2. **Fail-open pre-filter**: `is_admitted` downgrades malformed artifacts to a
   synthetic benign oracle verdict rather than failing the run (documented
   open question for obfuscated candidates).
3. **Execution-gated confirmation**: bypasses are confirmed by the ExecutionOracle
   (trigger polling / StraceOracle, 0% FP); DynaHug is a supplementary
   `decision_score` only and never gates confirmation.
4. **Error is never evasion**: a scanner `error` verdict (parse failure,
   timeout) cannot count as "evaded".
5. **Deterministic campaigns**: each worker reseeds from
   `sha256(base_seed:round:index)`; trigger dirs are seed-derived.
6. **Disjoint oracle calibration**: the oracle is fit on the `train` half of a
   deterministic cluster-stratified split; FP evaluation uses only the `eval`
   half (`real_benign_corpus/oracle-split.json`).