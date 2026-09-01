# Oracle Calibration Deviation

## The problem

The upstream DynaHug pretrained OCSVM (arXiv:2604.19438, default
text-generation model) **collapses in this container environment**: every real
checkpoint traces ~10–100× the syscall counts of upstream's training
environment, so every input lands far outside the learned support region and
the RBF `decision_function` pins to a constant `-rho` (~ −1.3489). The oracle
becomes a constant "malicious" classifier. Recorded in
`reference/oracle-sanity.json` and the `scripts/validate_oracle.py` gate.

## The fix

Recalibrate the OCSVM on **this environment's** traces with the paper's own
hyperparameters (RBF, `gamma=0.1`, `nu=0.01`) and preprocessing
(DictVectorizer + StandardScaler `with_mean=False` on frequency columns). The
calibration runs the exact same sandbox deserialization + strace count
collection the runtime wrapper uses, so the decision boundary matches how the
oracle is consumed. See `scripts/calibrate_oracle.py`.

Fit is done **inside the oracle image** (`scripts/fit_oracle_sweep.py`): the
image pins scikit-learn 1.7.1 / joblib 1.5.2 matching upstream's serialized
artifacts, avoiding host/container serialization skew.

## Remaining honest caveat

Even the environment-calibrated oracle retains a high FP rate on real benign
checkpoints (~63%) because benign load traces are dominated by the loader's
Python/torch startup baseline, so the OCSVM boundary sits close to zero.
Consequences, all handled:

- **DynaHug is a supplementary `decision_score` signal only.** Bypass
  confirmation is gated by the **ExecutionOracle** (deterministic trigger
  polling / `StraceOracle`, 0% FP), not by DynaHug. See `docs/oracle-spec.md`.
- RQ3 reports DynaHug FP honestly; ground truth is provenance-based (verified
  HF repo).

## Disjointness

The FP study and the calibration never share models: `scripts/check_oracle_disjointness.py`
produces a deterministic, cluster-stratified 50/50 train/eval split
(`real_benign_corpus/oracle-split.json`); calibration traces only the train
half, FP evaluation only the eval half.