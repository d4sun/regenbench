# ReGenBench — Implementation

How each component works, the campaign design, and the oracle model. This is
the implementation reference; for the measured outcomes see
[`RESULTS.md`](RESULTS.md), and for the diagrams + invariants see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 1. Candidate generation

### 1.1 Corpus & seed

- **Corpus**: 100 real benign HuggingFace `pytorch_model.bin` checkpoints,
  5 task clusters × 20, crawled by `scripts/crawl_benign.py` into
  `data/crawled/` and linked flat into `real_benign_corpus/all/` as
  `<cluster>__<repo>.bin`. SHA-256 dedup; provenance in `seed_manifest.json`.
  The crawl is resumable, backfills already-downloaded files into the manifest,
  excludes HF-flagged `danger`/`blocked` artifacts (HF stamps every pickle with
  `caution`, so caution is allowed), and runs in parallel (`--workers`).
- **Seed**: the campaign auto-picks the **smallest zip-valid checkpoint** in the
  matching cluster (`--seed-corpus-dir real_benign_corpus/all --seed-cluster
  text-generation`), so the pilot stays fast on a real model.

### 1.2 Attack families (`pipeline/templates.py`)

| Family | Mechanism |
|--------|-----------|
| `gadget` | Dangerous-callable `GLOBAL`/`REDUCE` injection into the state dict |
| `overwritten` | Overwritten-module (ShadowPickle) template |
| `external` | External-module template (`numpy.testing._private.utils.runstring`, …) |
| `indirect_chain` | `__import__` + `getattr` runtime sink resolution (leaf import chain) |
| `pypi_injected` | PyPI-injected package import (`IPython.utils.process.system`, …) |

Torch transport: `loads` (nested pickle via `_pickle.loads`) or `splice`
(whole-stream splice). The campaign defaults to `splice` (loads-wrap
reintroduces `_pickle.loads` and defeats evasion).

### 1.3 Mutation operators (`pipeline/mutators.py`)

`PickleMutator.mutate` supports opcode swap, callable substitution, argument
fuzzing, stacking, and encoding. Campaign defaults keep mutation conservative
(`op_swap=0.05, callable_sub=0.0, arg_fuzz=0.05`) so candidates stay
structurally valid (the validity oracle rejects the ~8% that break).

### 1.4 Evasion strategies (`pipeline/evasion.py`)

11 static-signature strategies, applied in `PIPELINE_ORDER` (wrap strategies
last): `stack_global_encoding`, `payload_obfuscation`, `indirect_chain`,
`nested_loads_wrap`, etc. Strategy selection caps sets at `{0,1}` and per-family
defaults exclude stacks that reintroduce denylisted globals. Evasion modes:
`adaptive` (guided feedback picks subsets), `random` (unguided ablation),
`off` (legacy).

## 2. Validation & confirmation

### 2.1 ExecutionOracle (`pipeline/validity.py`, `pipeline/plausibility.py`)

The primary oracle for bypass confirmation. `validate_torch(bytes, trigger)`
runs the candidate through a container-sandboxed `torch.load(weights_only=False)`
and polls a trigger sentinel (`_trigger_exists`, async `Popen` payloads count as
executed). A candidate is *valid* only if it loads **and** the sentinel fired.

### 2.2 StraceOracle (`pipeline/monitor.py`)

Containerized `strace -f` syscall analysis; **0% FP** on the benign corpus.
Replaces DynaHug as the deterministic execution signal.

### 2.3 DynaHug (supplementary only)

DynaHug produces a `decision_score` used as a supplementary signal. The
upstream pretrained OCSVM collapses in this container environment (every input
scores ≈ −rho). We recalibrate on this corpus' syscall traces
(`scripts/calibrate_oracle.py` + `scripts/fit_oracle_sweep.py` inside the
dynahug image). Even calibrated, DynaHug retains a high FP rate on benign
traces (~94% on the 100-model corpus) because benign loads are dominated by the
loader's Python/torch startup baseline. This is why bypass confirmation is execution-gated (never gated on the
DynaHug decision score): the statistical oracle's boundary is unreliable on
this environment's benign traces.

## 3. Runner, scanners, verdict schema

`pipeline/runner.py:Runner.run` fans candidates out to a `ThreadPoolExecutor`
and launches one container per (candidate, scanner) via
`pipeline/scanners.py:run_scan`. Each container prints one JSON verdict line:
`{"verdict": "benign"|"malicious"|"error", "decision_score": float,
"matched_rules": [...], ...}`. The host parses the last stdout line.

Panel for torch campaigns: `picklescan`, `fickling`, `modelscan`. `modeltracer`
is strace-based and cannot analyze torch-zip artifacts, so it is excluded from
torch FP checks. `run_scan` never passes the podman-only `--timeout` flag to
docker (hosts may be docker-only).

## 4. Fitness & feedback

### 4.1 Fitness modes (`pipeline/fitness.py`)

| Mode | Behavior |
|------|----------|
| `current` | panel evasion + boundary + novelty |
| `oracle_aware` | oracle confirmation multiplier on evasion (drives combo tiers) |
| `oracle_dominant` | lexicographic tiers 10000/1000/100/10/1 (deprecated: plateaus) |
| `continuous` | smooth multi-objective (evasion × oracle_mult + boundary + novelty + coverage) |
| `coverage_guided` | coverage delta primary when evasion plateaus |

### 4.2 Feedback (`pipeline/feedback.py`)

- `CoverageTracker`: opcode/callable coverage + per-round logging.
- `NoveltyTracker`: signature dedup for exploration bonus.
- `FeedbackController`: per-callable / per-family / combo weights; grey-box
  penalty when a callable's name appears in scanner `matched_rules`.
- **Family quotas** (P1.1): per-round min 15% / max 40% per family, entropy
  target 1.5 — prevents collapse into the `pypi_injected` + `splice` local
  optimum.

## 5. Campaign design

- **Baseline (H1 denominator)**: `scripts/run_shadowpickle_baseline.py`
  generates 3-5 handcrafted families; measured 25.0% bypass rate.
- **Guided**: `--mode guided --fitness-mode oracle_aware --evasion-mode adaptive`
  (25 rounds × 20 = 500 candidates).
- **Unguided**: `--mode unguided --fitness-mode current --evasion-mode random`
  (24 rounds × 20 = 480 candidates, budget-corrected).
- Both seed from the real text-generation checkpoint and append to the same DB.
- `--time-budget-hours` stops a campaign early and corrects
  `campaign_runs.total_candidates`.

## 6. Defense prototype (`pipeline/defense.py`, `sanitizer.py`, `repair.py`)

`PickleSanitizer` rewrites 5 direct sinks (`os.system`, `subprocess.Popen`,
`builtins.exec/eval`, `IPython.utils.process.system` → `builtins.len`);
`indirect_chain` / `numpy.runstring` / `posix.execv` escapes are **quarantined**
(not reserialized). Source artifacts are never mutated; only content that
survives `torch.load(weights_only=True)` in the sandbox is reserialized.
Guaranteed benign preservation; remaining escapes are quarantined.

## 7. Shelf-life (H3, `pipeline/shelf_life.py`)

`register_bypasses_from_campaign_db` bulk-registers confirmed bypasses into
`data/shelf_life.db` (`bypass_records`, `rescans`). `ShelfLifeTracker.rescan_bypass`
re-runs a bypass against an explicit historical image and logs
`evasion_retained`. Six historical images are buildable:
picklescan 1.0.4/1.0.3, modelscan 0.8.7/0.8.6, fickling 0.1.11/0.1.10.

## 8. Corpus & oracle pipeline (reproduce)

```sh
# crawl 100 real checkpoints
python3 scripts/crawl_benign.py --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering --limit-per-cluster 20 --max-size 134217728 --out-dir data/crawled --scan-cap 20000 --workers 8
# link flat corpus
mkdir -p real_benign_corpus/all && while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")"); ln -f "$f" "real_benign_corpus/all/${cluster}__${repo}.bin" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
# oracle validation + disjoint split
python3 scripts/validate_oracle.py real_benign_corpus/all --sample 100 --out real_benign_corpus/oracle-validation.json --backend docker
python3 scripts/check_oracle_disjointness.py --resplit
# recalibrate on the train half (fit inside the dynahug image)
python3 scripts/calibrate_oracle.py real_benign_corpus/all --split-file real_benign_corpus/oracle-split.json --split-role train --out real_benign_corpus/oracle-calibrated/current --sample 50 --backend docker --seed 1337 --traces-only
python3 scripts/fit_oracle_sweep.py --traces real_benign_corpus/oracle-calibrated/current/traces.json --export --gamma 0.1 --nu 0.01 --export-dir real_benign_corpus/oracle-calibrated/current --backend docker
```

## 9. Known limitations (honest notes)

- **Fickling 7% FP** on the 100-model torch corpus (allowlist limitation).
- **DynaHug ~94% FP** on benign traces (supplementary signal only).
- **H1** is measured as relative improvement over the ShadowPickle baseline,
  not an absolute threshold.
- **Repair**: ~30% of escapes are `indirect_chain`/`runstring` and are
  quarantined, not sanitized.
- The Rust crate (`crates/`) is not wired into the Python pipeline (Python is
  the source of truth).