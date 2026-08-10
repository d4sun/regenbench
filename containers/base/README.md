# ReGenBench base image

Shared, reproducible execution environment for all scanners (T0.3–T0.6) and the
behavioral oracle (T0.7).

## Contents

- Ubuntu 24.04 (noble)
- Python 3.13 (via deadsnakes PPA; not in Ubuntu 24.04 default repos)
- CPU-only PyTorch 2.13.0 (scanner inference does not require a GPU)
- NumPy 2.3.5
- `pickletools` (stdlib — available without installation)
- `strace` 6.8 (syscall tracing for ModelTracer / DynaHug)
- Common tooling: `git`, `curl`, `ca-certificates`

## Build

```sh
./containers/base/build.sh
```

Produces `regenbench/base:0.2.0` and `regenbench/base:latest`.

## Verify

```sh
podman run --rm regenbench/base:0.2.0 \
  python3.13 -c "import torch, pickletools; print('torch', torch.__version__)"
podman run --rm regenbench/base:0.2.0 strace --version
```

## Reproducibility

- Apt packages are pinned to exact Ubuntu 24.04 / deadsnakes versions.
- PyTorch is pinned to `2.13.0+cpu` from `https://download.pytorch.org/whl/cpu`.
- NumPy is pinned to `2.3.5`.

## Convention

Scanner and oracle images live under `containers/<name>/` and each build
`FROM regenbench/base:<version>` (see T0.3–T0.7).