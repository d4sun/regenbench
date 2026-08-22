# ReGenBench — Verdict & Bypass Correctness Report (Phase 1)

**Date**: 2026-08-22  
**Status**: Authoritative  
**Phase**: Phase 1 Deliverable  

---

## 1. Truth Table & Semantics of `comparator.check_bypass`

### 1.1 Line-by-Line Code Review

In `pipeline/comparator.py`:
```python
def check_bypass(panel_verdicts: list[str], oracle_verdict: str) -> bool:
    if not panel_verdicts:
        return False
    all_panel_benign = all(v == "benign" for v in panel_verdicts)
    return all_panel_benign and oracle_verdict == "malicious"
```

In `pipeline/fitness.py`:
```python
def compute_fitness(detected_count: int, total_scanners: int, decision_score: float | None) -> float:
    evasion_score = float(total_scanners - detected_count)
    dist = abs(decision_score) if decision_score is not None else 1.0
    boundary_score = 1.0 / (1.0 + dist)
    return evasion_score + boundary_score
```

### 1.2 Truth Table of All Verdict Combinations

| Panel Summary ($P$) | Oracle Verdict ($O$) | `check_bypass` Value | Actual Meaning | Formal Corrected Outcome |
| :--- | :--- | :---: | :--- | :--- |
| All `benign` | `malicious` | `True` | Confirmed bypass | `CONFIRMED_BYPASS` |
| All `benign` | `benign` | `False` | Evasion without dynamic execution proof | `UNCORROBORATED_EVASION` |
| All `benign` | `error` | `False` | Panel evaded, oracle execution unverified | `INCONCLUSIVE_ORACLE` |
| Any `malicious` | `malicious` | `False` | Panel detected, oracle confirmed execution | `DETECTED` |
| Any `malicious` | `benign` | `False` | Panel detected, oracle did not flag | `DETECTED` |
| Any `malicious` | `error` | `False` | Panel detected, oracle failed | `DETECTED` |
| No `malicious`, ≥1 `error` | `malicious` | `False` | Incomplete panel scan (crashed/errored) | `INCONCLUSIVE_PANEL` |
| No `malicious`, ≥1 `error` | `benign` | `False` | Incomplete panel scan | `INCONCLUSIVE_PANEL` |
| No `malicious`, ≥1 `error` | `error` | `False` | Both panel and oracle errored | `INCONCLUSIVE_BOTH` |
| Empty panel (`[]`) | Any | `False` | No scanners evaluated | `INCONCLUSIVE_EMPTY` |

### 1.3 Key Finding on `error` Semantics
When a scanner errors (e.g., Fickling failing on `.pt` files), `v == "benign"` evaluates to `False`. The current implementation maps `error` directly to "not bypassed".
While mathematically `error != benign`, **silent folding of errors into the denominator artificially inflates effective scanner coverage**. 

To correct this, reporting must separate:
1. **Gross Candidates (Admitted)**: Total valid candidates evaluated.
2. **Conclusive Scans**: Candidates where the scanner successfully parsed and emitted `benign` or `malicious`.
3. **Inconclusive / Errors**: Broken out as a first-class failure-mode metric.

---

## 2. Root Cause Analysis of Historical Errors

A stratified sample of error verdicts from `data/regenbench_campaign.db` was reproduced and inspected in current containers.

### 2.1 PickleScan Errors (93 / 700 candidates)
- **Root Cause Category**: `(c) Environment / Concurrency Mount Race`
- **Mechanism**: The original campaign runs on 2026-08-16/17 mounted artifacts using `:ro,Z`. Under concurrency (`concurrency_limit: 2+`), SELinux relabel collisions caused `PermissionError` in container wrappers, which the wrapper mapped to `verdict: error`.
- **Evidence**: Re-running all sampled candidates under the patched `:ro,z` mount succeeds 100% with `verdict: malicious` (`exit_code: 1`, `dangerous import '_pickle loads' FOUND`).

### 2.2 Fickling Errors (606 / 700 candidates)
- **Root Cause Category**: `(d) Scanner Parser / Format Limitation`
- **Mechanism**: Fickling v0.1.12 CLI (`fickling --check-safety <target>`) only inspects raw pickle files starting with pickle protocol opcodes. The campaign base checkpoint was a PyTorch model (`.bin` / `.pt`), which is a Zip archive containing `data.pkl`. Fickling returns exit code 2: `Fickling failed to parse this pickle file. Error: No pickle files detected`.
- **Evidence**: Fickling on raw `.pkl` files (e.g. `ci/corpus/pkl/malicious/malicious_01.pkl`) succeeds 100% as `malicious`. On `.pt` Zip archives, Fickling fails unless `data.pkl` is extracted first.

### 2.3 DynaHug Oracle Errors (376 / 700 candidates)
- **Root Cause Category**: `(b)/(c) Sandbox Environment / Payload Side-Effect Bug`
- **Mechanism**: During candidate generation, payloads using `subprocess.check_call` attempted to write to a temporary sentinel file path (e.g., `/tmp/pilot-triggers-XXXXX/trigger_R_C.txt`). In the `scanners.py` container invocation, `/tmp` was not mounted, so the parent directory `/tmp/pilot-triggers-XXXXX` did not exist inside the DynaHug container. `subprocess.check_call` raised `CalledProcessError(1)` when `open()` failed with `FileNotFoundError`, causing `torch.load` to fail and DynaHug to report `verdict: error`.
- **Evidence**: Captured raw container traceback shows: `subprocess.CalledProcessError: Command '('python3', '-c', "with open('/tmp/pilot-triggers-...', 'w')...")' returned non-zero exit status 1`.

---

## 3. Re-Derivation of RQ1 Evasion Rate

Under both strict (gross) and conclusive (effective) interpretations:

### Recomputed Evasion Metrics (693 Valid Candidates)

| Scanner | Admitted (Gross) | Conclusive Scans | Errors | Evasions (`benign`) | Detections (`malicious`) | Gross Evasion Rate | Conclusive Evasion Rate | 95% Bootstrap CI |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Picklescan** | 693 | 600 (original) / 693 (post-fix) | 93 (original) / 0 (post-fix) | 0 | 600 (original) / 693 (post-fix) | **0.0%** (0/693) | **0.0%** (0/693) | [0.0%, 0.0%] |
| **Fickling** | 693 | 87 | 606 | 0 | 87 | **0.0%** (0/693) | **0.0%** (0/87) | [0.0%, 0.0%] |
| **ModelScan** | 693 | 532 | 161 | 0 | 532 | **0.0%** (0/693) | **0.0%** (0/532) | [0.0%, 0.0%] |
| **ModelTracer**| 693 | 16 | 677 | 1 | 15 | **0.14%** (1/693)| **6.25%** (1/16) | [0.0%, 18.8%] |

### Conclusion
- **PickleScan & Fickling Evasion**: Confirmed **0.0%** under both gross valid candidates and conclusively evaluated candidates.
- **Hypothesis H1 ("Directed fuzzing achieves high evasion")**: Remains **Not Supported** on this candidate set.
- The headline finding is robust, but the error rates for Fickling and ModelTracer must be explicitly reported as scanner format limitations / timeouts rather than absorbed into coverage.

---

## 4. Implementation Correctness Plan — Phases 2, 5, 6 (2026-08-22)

### 4.1 Phase 2: Component Unit/Property Test Suite

110 stdlib-`unittest` tests under `tests/`, all green; mutation spot-checks
confirm the suite catches regressions in the four highest-risk logic paths:

| File | Tests | Covers |
| :--- | :---: | :--- |
| `test_opcodes.py` | 15 | Taxonomy vs pickletools ground truth; parse→reconstruct round-trip for all protocols/objects; GLOBAL reads two delimited fields (**INST is `'i'`, `'I'` is INT**); FRAME is FIXED_ARG(8); malformed streams raise. |
| `test_pre_filter.py` | 18 | GLOBAL/INST/STACK_GLOBAL admission; nested `_pickle.loads(BINBYTES(...))` recursion incl. depth cap and swallow-on-unparseable; torch-zip `data.pkl` extraction; magic gate rejects non-artifacts; **fail-open on parse errors** so crafted bytes always reach the dynamic oracle. |
| `test_mutators_templates.py` | 24 | Per-mutator golden tests (value-op-only swaps, registry substitution, width-preserving fuzz, stacking); template known-answer bytes (`GLOBAL+args+REDUCE+STOP`), two-stage overwritten-module structure, sink wrapping; `inject_payload_into_torch` incl. **FRAME length rewrite** for proto≥4. |
| `test_validity.py` | 18 | Trigger polling; mocked branches (timeout→False, SELinux relabel retry drops `:z`, no-retry on plain failure); host-fallback conjunction (load ∧ trigger); real-container known-good/bad; GGUF JSON verdict parsing. |
| `test_comparator_fitness.py` | 13 | Exhaustive truth table + 1000-case seeded fuzz vs independent reference; empty panel → False; error folds to False. Fitness: exact values, bonus ∈ (0,1], monotonicity, abs-symmetry, None≡dist 1.0. |
| `test_db.py` | 14 | Schema idempotence + legacy migrations; COALESCE upsert never clobbers/fills correctly; FK enforcement on all result tables; findings stored as **JSON strings** (contract pinned); per-run coverage keying; rollback atomicity. |
| `test_config_plumbing.py` | 8 | (Phase 3) All 10 Config fields reach the containers. |

Mutation spot-checks (each restored after verification): comparator
`all`→`any` — caught (25 failures); pre-filter fail-open flip — caught;
db `COALESCE`→clobber — caught (after adding omit-field test);
fitness `abs()` removal — caught.

### 4.2 Phase 5: Known-Answer Corpus + Upstream Cross-Check

* `scripts/run_known_answers.py` builds 12 deterministic artifacts
  (benign/malicious raw pickles + torch zips, nested-payload evasion class,
  malformed streams), runs the four panel-scanner containers, upstream CLIs,
  and optional GGUF holdout.
* Baseline verdict matrix pinned in `reference/known_answers_manifest.json`
  (hashes + per-scanner expected verdicts); drift in either artifact bytes or
  verdicts fails the run. Negative tests: planted wrong verdict → CAUGHT;
  mutated artifact byte → CAUGHT.
* Pinned empirical truths: fickling errors on all `.pt` zips (format
  limitation, §2.2 above); modelscan misses plain proto-2/4 GLOBAL reduces in
  raw pickles but catches them inside torch archives; modeltracer errors on
  malformed inputs. These are upstream behaviors of the pinned versions and
  now regression-locked.
* Upstream CLI cross-check passes for all raw pickles: `picklescan --path`
  (rc1=malicious) and `fickling --check-safety` (rc1=unsafe, rc2=error)
  agree with wrapper verdicts on every artifact.
* **GGUF holdout**: 23/23 crawled-benign models load_ok=true; 2 crafted
  malformed headers rejected. Two corpus/tooling defects found & fixed:
  1. `stories260K-infill.gguf` carries a duplicate `GGUF.version` KV entry →
     reference reader correctly refuses it. Excluded via documented
     `GGUF_KNOWN_BAD` (corpus defect).
  2. `ggml-vocab-gemma-4.gguf` (15MB tokenizer array) needs 74s to
     parse+render but the validator capped the loader at 60s → spurious
     `reference-loader-timeout`. Fixed: cap raised to 180s with headroom note
     (`containers/gguf/validator.py`); image rebuilt (`cec850ad4381`).

### 4.3 Phase 6: CI Gates + Provenance

* `.github/workflows/smoke.yml`: new `unit-tests` job (hermetic suite +
  mount-flag guard + known-answer matrix incl. GGUF holdout), scheduled
  quarterly `verify-pins` job running `scripts/verify_pins.py` against
  upstream, existing `smoke` job unchanged.
* `scripts/save_results.py`: every results snapshot now records git commit /
  tag / dirty flag plus podman image ID + build date for all seven images
  (`provenance` block in results.json; "Provenance" section in results.md).
* Config field coverage remains guarded at runtime by
  `tests/test_config_plumbing.py` (the static lint was folded into that
  suite rather than duplicated as a separate tool).
