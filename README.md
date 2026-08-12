# RegenBench

A reproducible benchmark harness for security scanning of machine-learning
model artifacts. Each scanner (and a behavioral oracle) is packaged as a
reproducible container and wrapped behind a single
[unified verdict schema](docs/verdict-schema.md).

## Components

| Task | Component | Container / Path | Status |
|----|-----------|-----------|--------|
| T0.1 | Host spec & verification | — | [`docs/t0.1-host-spec.md`](docs/t0.1-host-spec.md) |
| T0.2 | Base image | `regenbench/base` | `containers/base` |
| T0.3 | PickleScan | `regenbench/picklescan` | `containers/picklescan` |
| T0.4 | ModelScan | `regenbench/modelscan` | `containers/modelscan` |
| T0.5 | Fickling | `regenbench/fickling` | `containers/fickling` |
| T0.6 | ModelTracer | `regenbench/modeltracer` | `containers/modeltracer` |
| T0.7 | DynaHug behavioral oracle | `regenbench/dynahug` | `containers/dynahug` |
| T0.8 | Smoke-test corpus + CI | — | `ci/` |
| T0.9 | MLflow experiment tracking | — | `pipeline/tracking.py` |
| T0.10| Local task orchestration | — | `pipeline/runner.py` |
| T1.1 | Published scanner metrics | — | [`reference/published-scanner-metrics.json`](reference/published-scanner-metrics.json) |
| T1.2 | Published DynaHug metrics | — | [`reference/published-dynahug-metrics.json`](reference/published-dynahug-metrics.json) |
| T1.3 | Pretrained DynaHug oracle check | — | [`scripts/oracle_sanity.py`](scripts/oracle_sanity.py) |
| T1.4 | Sanity smoke test | — | [`scripts/sanity_smoke.py`](scripts/sanity_smoke.py) |
| T1.5 | Comparison methodology and caveats | — | [`docs/comparison-methodology.md`](docs/comparison-methodology.md) |
| T2.1 | Parameterized Overwritten-Module template | — | [`pipeline/templates.py`](pipeline/templates.py) |
| T2.2 | Parameterized PyPI-Injected template | — | [`pipeline/templates.py`](pipeline/templates.py) |
| T2.3 | Parameterized External-Module template | — | [`pipeline/templates.py`](pipeline/templates.py) |
| T2.4 | Benign Hugging Face seed corpus | — | `data/crawled/` |
| T2.5 | Seed corpus manifest and versioning | — | [`data/crawled/seed_manifest.json`](data/crawled/seed_manifest.json) |
| T3.1 | Port PickleFuzzer opcode categorization | — | [`pipeline/opcodes.py`](pipeline/opcodes.py) |
| T3.2 | Build dangerous-callable registry | — | [`pipeline/dangerous_callables.yaml`](pipeline/dangerous_callables.yaml) |

Each `containers/<name>/` holds a `Dockerfile`, `wrapper.py`, and `build.sh`
(produces `regenbench/<name>:<version>` and `:latest`).

## Running the smoke suite

Build the panel and validate every artifact against
`ci/corpus/expected.json`:

```sh
./ci/smoke.sh            # build base+panel, generate torch corpus, assert
./ci/smoke.sh --no-build # reuse already-built local images
```

The same run executes on every push/PR to `main` via
`.github/workflows/smoke.yml`. See [`ci/corpus/README.md`](ci/corpus/README.md)
for corpus layout and how to add artifacts.