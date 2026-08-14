# Oracle Calibration Deviation

## Status: Adopted (2026-08-13)

## The collapse

The pretrained DynaHug text-generation oracle (`DynaHug-Detector/DynaHug`
@ `8ff8174eaf54175a7fc3b90730faf334fb767e0b`, OCSVM `gamma=0.1 nu=0.01`,
presence+frequency syscall features) is **degenerate in the ReGenBench
container environment**: every real checkpoint we tested — including
`openai-community/gpt2` and 11 other in-distribution text-generation models
across gpt/llama/other families — returns the identical decision score

    -1.3488830680940862  (= -rho)

with spread `0.0` and verdict `malicious`. The oracle-validation gate
(`scripts/validate_oracle.py`) correctly tripped (`collapse_flag=true`).

### Root cause

The wrapper reimplements upstream `classifier/svm.py::predict` faithfully
(verified line-by-line) and the artifacts are the pinned upstream pickles.
The OCSVM is not broken — it scores its own support vectors near 0
(min -0.35, max +0.0005). The failure is **environment mismatch**:

- Our base container (Python 3.13, newer torch) produces syscall counts that
  are ~10-100x the upstream training environment's profile
  (e.g. `newfstatat=13432`, `read=2344`, `fstat=2249`).
- The `StandardScaler(with_mean=False)` was fit on the upstream distribution;
  90% of its `scale_` entries are `1.0` (those syscalls never varied in
  training), so our raw counts pass through essentially unscaled.
- Resulting feature vectors sit at L2 distance ~22,400 from the nearest
  support vector (support vectors are ~5 apart). For the RBF kernel with
  `gamma=0.1`, `exp(-0.1 * d^2) -> 0` for every support vector, so
  `decision_function(x) = sum(alpha_i * K) - rho ~= -rho` for every input:
  a **constant malicious classifier**.

This is a genuine portability limitation of the pretrained artifact, not a
bug in the ReGenBench wrapper.

## The fix: environment-calibrated oracle

`scripts/calibrate_oracle.py` reproduces the paper's training step on *our*
environment:

1. Run the exact sandbox deserialization + `strace -c -f` count pass the
   oracle wrapper uses (same loader, same container image).
2. Build presence+frequency features over the pinned 360-syscall vocabulary.
3. Fit `DictVectorizer` + `StandardScaler(with_mean=False)` (frequency
   columns only) + `OneClassSVM(kernel=rbf, gamma=0.1, nu=0.01)` — the
   upstream hyperparameters.
4. Save artifacts + a calibration report with train/holdout score stats.

Artifacts: `real_benign_corpus/oracle-calibrated/text-generation/`.

## Validation gate outcome (recalibrated)

30 real text-generation checkpoints (seed 99), scored with the calibrated
model:

- spread `0.0776` (vs `0.0` collapsed), `collapse_flag=false` — **gate passes**
- `score_distribution`: min -0.054, median +0.0053, max +0.0237
- verdicts: 21 benign / 5 malicious / 4 error (deserialization failures)
- `positive_rate` (score > 0): 0.70

### Known limitation: benign false-positive rate

The calibrated oracle still flags a substantial share of *real benign*
checkpoints as malicious (~16-30% across validation/calibration holdouts).
Causes: only ~40 training traces (small support region, boundary near 0) and
the OCSVM's one-class objective. Consequences for the experiment:

- **RQ3 (benign FP study)** reports this honestly: the oracle's FP rate on
  the real corpus is measured and reported, not hidden.
- **RQ2 (confirmed bypasses)** requires a scanner bypass to ALSO be benign
  across the panel AND corroborated by the oracle; a high oracle FP rate
  inflates the *unconfirmed* pool, so the dual-oracle "confirmed" definition
  is kept strict.
- Do **not** filter the benign corpus by oracle verdict (provenance-based
  ground truth, per methodology).

### Known limitation: weak discrimination (measured 2026-08-13)

A direct A/B discrimination test on `roneneldan/TinyStories-1M`:

| sample | verdict | decision_score | exec/fork syscalls |
| :--- | :--- | :--- | :--- |
| benign base | malicious | -0.0733 | execve=1, clone3=7 |
| + `os.system` injected payload | malicious | -0.0823 | execve=3, vfork=1, wait4=3, write=3, getpid/getppid |

The injected candidate produces clear observable behavioral deltas (the
subprocess syscalls — vfork/wait4/getpid/write — are absent in the base, and
~500 extra syscalls overall), but the calibrated OCSVM compresses the delta
to ~0.009 in decision score, so both land below zero ("malicious"). Cause:
the trace is dominated by the loader's Python/torch startup baseline
(e.g. newfstatat=13432, read=2344, identical across all models); the
payload's contribution is a small additive shift that the 10-support-vector
boundary does not separate. The oracle therefore has **low discriminative
power in this environment**, independent of its FP rate.

Consequences for RQ2: the oracle cannot serve as a strong independent
corroborator of individual bypasses. "Confirmed bypass" must therefore be
interpreted as *panel-clean + oracle-corroborated under a weak oracle*, and
the panel scanner verdicts carry the primary signal. This is reported
transparently rather than hidden.

## Methodology note

This is a documented deviation: the behavioral oracle is no longer the
*published pretrained* DynaHug model; it is a DynaHug-calibrated-for-this-
environment model. Reports must state this (see `docs/evaluation-report.md`).

## Scanner coverage limitation (real torch checkpoints)

Measured on real 48MB `pytorch_model.bin` checkpoints (and confirmed on the
5KB synthetic torch fixture):

| scanner | real torch (48MB) | small torch (5KB) | verdict |
| :--- | :--- | :--- | :--- |
| picklescan | works (benign) | works | ✓ |
| modelscan | works (benign) | works | ✓ |
| fickling | error: "No pickle files detected" | error (same) | ✗ fundamental |
| modeltracer | hangs >6 min (internal 300s timeout) | works (benign) | ✗ too slow |

Fickling cannot parse torch checkpoint files at all (it expects a raw pickle
stream; torch checkpoints use a different serialization structure) and
modeltracer's full syscall trace (`strace -tt -T -y -yy`) does not complete
on multi-10MB checkpoints. **Decision (2026-08-13):** for the real-corpus
campaigns (RQ2/RQ3), the bypass panel is `picklescan + modelscan + dynahug`;
fickling and modeltracer are excluded as inapplicable to torch artifacts and
this is reported as a scanner-coverage limitation, not as a bypass. The full
4-scanner panel remains available for synthetic `.pkl` experiments where the
scanners are applicable. Errored scanners are always fail-closed ("error",
never "benign").
The calibration is reproducible via `scripts/calibrate_oracle.py`.
