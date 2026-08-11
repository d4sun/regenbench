# RegenBench

A reproducible benchmark harness for security scanning of machine-learning
model artifacts. Each scanner (and a behavioral oracle) is packaged as a
reproducible container and wrapped behind a single
[unified verdict schema](docs/verdict-schema.md).

## Components

| T0 | Component | Container | Status |
|----|-----------|-----------|--------|
| T0.1 | Host spec & verification | — | [`docs/t0.1-host-spec.md`](docs/t0.1-host-spec.md) |
| T0.2 | Base image | `regenbench/base` | `containers/base` |
| T0.3 | PickleScan | `regenbench/picklescan` | `containers/picklescan` |
| T0.4 | ModelScan | `regenbench/modelscan` | `containers/modelscan` |
| T0.5 | Fickling | `regenbench/fickling` | `containers/fickling` |
| T0.6 | ModelTracer | `regenbench/modeltracer` | `containers/modeltracer` |
| T0.7 | DynaHug behavioral oracle | `regenbench/dynahug` | `containers/dynahug` |
| T0.8 | Smoke-test corpus + CI | — | `ci/` |

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