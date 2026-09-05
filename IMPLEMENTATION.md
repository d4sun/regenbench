# ReGenBench — Implementation

How each component works, the campaign design, and the oracle model. This is
the implementation reference; for the measured outcomes see
[`RESULTS.md`](RESULTS.md), and for the diagrams + invariants see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 1. Candidate generation

### 1.1 Corpus & seed

- **Corpus**: 304 real benign HuggingFace checkpoints (179 PT `pytorch_model.bin` + 125 GGUF),
  5 task clusters, crawled by `scripts/crawl_benign.py` and
  `scripts/download_gguf_models.py` into `data/crawled/` and linked flat into
  `real_benign_corpus/all_pt/` and `real_benign_corpus/all_gguf/`. SHA-256 dedup;
  provenance in `seed_manifest.json`.
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
(`scripts/calibrate_oracle.py` — now handles traces + OCSVM fit in one pass)
on the **disjoint train half** of the 50/50 split (`scripts/check_oracle_disjointness.py`).
Differential baseline subtraction (P2.2 Option A: subtract blank `torch.load`
syscalls) is applied at both training and inference time (`blank_baseline.json`
mounted into the container). The recalibrated OCSVM achieves spread=0.07,
74% benign rate on the 100-model validation sample (vs 0% with pretrained).
Even calibrated, DynaHug is supplementary; bypass confirmation is execution-gated
(trigger polling / StraceOracle, 0% FP), never gated on the decision score.

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

## 8. GGUF attack surface (`pipeline/gguf_tools.py`, `containers/gguf/`)

A **format-complexity demo**, not a scanner-robustness claim. It generates 7
GGUF attack families and scans them with the `ggufref` reference oracle versus
modelscan.

### 8.1 Builders

`gguf_tools.build_gguf` / `benign_gguf` / `generate_candidate_gguf` emit GGUF
v3 bytes (metadata-only, zero tensors) for 7 families:

- `ssti_chat_template` — Jinja2 SSTI in `tokenizer.chat_template`
  (CVE-2024-34359); renders through the unsandboxed Jinja2 path and writes a
  trigger file via `os.popen`.
- 6 malformed-header families that reproduce the vellaveto attack
  *technique*: `nkv_overflow`, `ntensors_overflow`, `string_overflow`,
  `path_traversal`, `negative_dims`, `version_zero` — all rejected by the
  ggml-org reference reader and all missed by modelscan 0.8.8.

### 8.2 Reference oracle (`containers/gguf/`)

`loader.py` parses with the ggml-org `gguf==0.19.0` reader in a **single
pass**, classifies the malformed families with a bounded `kv_count` walker
(capped at 100k), and renders `tokenizer.chat_template` through Jinja2 exactly
like llama-cpp-python. `validator.py` normalizes to the unified verdict schema.
A file is only `malicious` when it matches an attack signature — reference-reader
rejection alone stays `benign` (the reader has real bugs on some legitimate
vocab GGUFs, which keeps FP=0 on the real corpus).

### 8.3 Isolation and the single scan path

All GGUF scanning goes through `pipeline.scanners.run_scan(gguf_ref=True)` —
the single owner of the GGUF flags. The SSTI render runs in an isolated,
**network-disabled** container (`--network none`) with a container-scoped
`--tmpfs /tmp` and no host filesystem access. Execution is confirmed by a
**strace-based oracle** (`containers/gguf/loader.py --strace-mode`): the render
runs under `strace -f` and a process spawn (`execve`) marks the payload as
executed — **decoupled** from ggufref's static `SSTI_SIGNALS` / trigger-file
detection (mirroring the pickle-side StraceOracle). Obfuscated SSTI payloads
that avoid every static signal (Jinja2 `attr` + string-split) therefore
produce confirmed bypasses (ggufref benign + executed). `label=disable` is
only needed on SELinux-enforcing hosts. `Runner` routes `.gguf` → `ggufref`
via `SCANNERS` exts; `demo_task3.py`, `run_task3_demo.py`,
`validity.validate_gguf`, and `run_known_answers._gguf_run` all call the same
path (no bespoke subprocess construction).

### 8.4 Corpus and measured results

`scripts/crawl_gguf.py` fetches 24 real TinyLlama + llama.cpp vocab GGUFs into
`data/gguf_benign_corpus/` (regenerable, gitignored). Measured:
**ggufref detects 7/10** attack families (baseline SSTI + 6 malformed),
**modelscan 0/10** (no GGUF rules), benign-synth benign; the 3
`ssti_obfuscated_*` variants are **confirmed bypasses** (ggufref benign +
modelscan benign + strace-executed); **real-corpus FP 0/24 for both**.
`ggufref` is `.gguf`-capable (as is modelscan); picklescan/fickling/
modeltracer/dynahug are not routed to `.gguf` (format gap). See `RESULTS.md`
and the regenerable `docs/demo-report.md#5` / `docs/task3-demo.md`.
Known-answers: `reference/known_answers/gguf_malformed/` covers all 7
malformed/SSTI families.

### 8.5 Unified database & report (cross-format)

The campaign DB schema is format-agnostic: `candidates.format` (`pt`/`gguf`),
`attack_primitives` (JSON), and `format_specific` (JSON) are added by the
idempotent migration in `pipeline/db.py:init_db`. `scripts/insert_gguf_into_campaign.py`
bulk-inserts the GGUF demo surface (10 attacks + synthetic benign + 24 real
GGUFs) as `format='gguf'` candidates, so `generate_evaluation_report.py`
emits a cross-format summary (`GROUP BY format`) with format-native panels.
A format-aware validation dispatcher exists (`validity.validate_torch` /
`validity.validate_gguf`) and `Runner` routes `.gguf` via `SCANNERS` exts.
Follow-on (not yet implemented): format-aware generator dispatch inside the
fuzzing loop and attack-primitive coverage/fitness.

## 9. Corpus & oracle pipeline (reproduce)

```sh
# crawl 304 real checkpoints (179 PT + 125 GGUF, 25 per cluster per format)
python3 scripts/crawl_benign.py --clusters text-generation,text-classification,feature-extraction,token-classification,question-answering --limit-per-cluster 25 --max-size 134217728 --out-dir data/crawled --scan-cap 20000 --workers 8 --format both
# link flat corpus (PT + GGUF)
mkdir -p real_benign_corpus/all_pt real_benign_corpus/all_gguf
while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")"); ln -f "$f" "real_benign_corpus/all_pt/${cluster}__${repo}.bin" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name pytorch_model.bin)
while IFS= read -r f; do repo=$(basename "$(dirname "$f")"); cluster=$(basename "$(dirname "$(dirname "$f")")"); ln -f "$f" "real_benign_corpus/all_gguf/${cluster}__${repo}.gguf" 2>/dev/null; done < <(find data/crawled -mindepth 3 -maxdepth 3 -name "*.gguf")
# oracle validation + disjoint split (PT format)
python3 scripts/validate_oracle.py real_benign_corpus/all_pt --sample 100 --out real_benign_corpus/oracle-validation.json --backend docker --format pt --oracle-model-dir real_benign_corpus/oracle-calibrated/pt
python3 scripts/organize_corpus.py --corpus-pt real_benign_corpus/all_pt --corpus-gguf real_benign_corpus/all_gguf --report real_benign_corpus/oracle-validation.json --out real_benign_corpus
python3 scripts/check_oracle_disjointness.py --resplit
# recalibrate on the train half (traces + OCSVM fit + blank baseline in one call)
python3 scripts/calibrate_oracle.py real_benign_corpus/all_pt --split-file real_benign_corpus/oracle-split.json --split-role train --out real_benign_corpus/oracle-calibrated/pt --sample 50 --backend docker --seed 1337 --format pt
# GGUF (ggufref) does not use OCSVM - no calibration needed
```

## 10. Known limitations (honest notes)

- **Fickling 7% FP** on the 100-model torch corpus (allowlist limitation).
- **DynaHug**: recalibrated OCSVM achieves 74% benign on 100-model validation (spread=0.07); supplementary `decision_score` only, never gates confirmation.
- **H1** is measured as relative improvement over the ShadowPickle baseline,
  not an absolute threshold.
- **Repair**: ~30% of escapes are `indirect_chain`/`runstring` and are
  quarantined, not sanitized.
- **GGUF**: fickling reads GGUF bytes as pickle → 100% FP on any GGUF
  (format gap, not routed to `.gguf`); modelscan has no GGUF header/type rules
  (0/10); the `ggufref` oracle renders untrusted Jinja2 (isolated, see §8.3).
  GGUF candidates are inserted into the campaign DB and report by
  `scripts/insert_gguf_into_campaign.py` (the `gguf-demo` run, 35 candidates)
  but are *not* generated by the fuzzing/fitness loop (static demo surface).
- The Rust crate (`crates/`) is not wired into the Python pipeline (Python is
  the source of truth).