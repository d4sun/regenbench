# regenbench/dynahug — DynaHug behavioral oracle

Containerized behavioral oracle (T0.7): sandbox execution + strace + feature
extraction + One-Class SVM inference as a single pipeline, based on
[DynaHug](https://github.com/DynaHug-Detector/DynaHug) (Nambiar/Pradhan/Soremekun,
"Malicious ML Model Detection by Learning Dynamic Behaviors", arXiv:2604.19438).

Unlike the static scanners (picklescan/modelscan/fickling) and the dynamic
scanner (modeltracer), which flag a narrow set of suspicious syscalls, this
oracle reproduces DynaHug's learned classifier: it deserializes the target
under strace, summarizes the syscall behavior, and scores it against a
pre-trained One-Class SVM.

## Pipeline (upstream `main.py` → `src/analysis.py` → `src/inference.py` → `src/strace_analyzer.py` → `classifier/svm.py`)

1. **Sandbox execution** — `torch.no_grad(); torch.load(f, weights_only=False, map_location=cpu)`,
   the same deserialization used to collect the upstream training traces.
2. **strace collection** — `timeout --preserve-status 120s strace -c -f` (upstream Run 2
   count summary).
3. **Feature extraction** — `parse_strace_count` over the count summary, projected onto
   `classifier/syscalls.txt` as `presence_<sc>` / `frequency_<sc>` features.
4. **OCSVM inference** — the paper-default model:
   `text-generation/2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best/OneClassSVM/params-gamma_0.1_kernel_rbf_nu_0.01`
   (`vectorizer.transform` → scale `frequency_*` columns → `model.predict` /
   `model.decision_function`).

## Pinning

- Upstream commit `8ff8174eaf54175a7fc3b90730faf334fb767e0b` (main, 2026-04-28).
- The full upstream tree is `5.5 GB` (mostly `classifier/models`); the image pulls
  only the required pinned files via `raw.githubusercontent.com` into `/opt/dynahug`
  (`LICENSE`, `classifier/syscalls.txt`, and the model's
  `oneclass_svm_model.pkl` / `scaler.pkl` / `vectorizer.pkl`).
- `scikit-learn==1.7.1` and `joblib==1.5.2` are pinned to the upstream
  `requirements.txt` versions so the model pickles load reproducibly.

## Build

```sh
./build.sh           # tags regenbench/dynahug:0.7.0 and :latest
```

## Usage

```sh
podman run --rm -v "$PWD/artifact.pt:/target.pt:ro,z" regenbench/dynahug /target.pt
```

Reads one target artifact path (argv[1]) and prints one JSON object to stdout
(`docs/verdict-schema.md`). A top-level `decision_score` (float) carries the
signed OneClassSVM `decision_function` (benign > 0, malicious < 0).

### Exit codes

| code | meaning |
|------|---------|
| 0    | benign — deserialization completed, OCSVM prediction +1 |
| 1    | malicious — OCSVM prediction −1 (anomaly) |
| 2    | error — missing/unreadable target, or deserialization failed (no behavioral signal) |

### Faithfulness caveat

The embedded text-generation OCSVM was trained on 2,000 real HuggingFace model
loads (`2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best`).
The wrapper reproduces the pretrained model's behaviour exactly (sandbox
`torch.load(weights_only=False)`, count-pass `strace -c -f`, presence/frequency
features, `vectorizer → scaler → decision_function`). Because arbitrary local
artifacts produce out-of-distribution, import-dominated syscall profiles, they
typically land far from the model's support region: the RBF decision_function
returns ≈ `-rho` (−1.35) and the verdict is `malicious`. This is the model's own
behaviour, not a wrapper heuristic — `decision_score` is the informative signal,
and only an in-distribution (real-model-like) benign trace yields a positive
score / exit 0.

## Validation

The oracle is validated behaviorally on this hardware:

- garbage file → `error` / exit 2 (`torch.load` raises; no behavioral signal).
- missing path → `error` / exit 2.
- a deserializable `.pt` (benign or `__reduce__` payload) → completes and emits
  `verdict` + `decision_score`; a payload that spawns a process is `malicious`
  / exit 1. Per the caveat above, a locally-traced micro-checkpoint reports
  `malicious` (out-of-distribution), which is the faithful model output.

### T1.3 — pretrained-oracle sanity check on a real model

`scripts/oracle_sanity.py` fetches a real HuggingFace text-generation
checkpoint at runtime (in-distribution for the embedded OCSVM), runs it through
this container, and records the `decision_score` as a working-checkpoint record
(`reference/oracle-sanity.json`). The model file itself is not committed.

```sh
python3 scripts/oracle_sanity.py --model openai-community/gpt2
```

Only a clearly in-distribution (real-model-like) trace yields a positive
`decision_score` / exit 0; a small checkpoint (e.g. `sshleifer/tiny-gpt2`) still
traces import-dominated and returns ≈ `-rho` — the faithful pretrained-model
output, per the caveat above.

## Reference layout in the image

```
/opt/dynahug/
├── LICENSE
└── classifier/
    ├── syscalls.txt
    └── models/text-generation/...new_logs_std_scaler_nomean_best/OneClassSVM/
        └── params-gamma_0.1_kernel_rbf_nu_0.01/
            ├── oneclass_svm_model.pkl
            ├── scaler.pkl
            └── vectorizer.pkl
```