# ModelTracer scanner container

Reproducible container for **ModelTracer** (Casey et al., *"A Large-Scale
Exploit Instrumentation Study of AI/ML Supply Chain Attacks in Hugging Face
Models"*, [arXiv:2410.04490](https://arxiv.org/abs/2410.04490)). The upstream
code lives in [s2e-lab/hf-model-analyzer](https://github.com/s2e-lab/hf-model-analyzer).

ModelTracer is a **dynamic** scanner. Unlike the static scanners (PickleScan,
ModelScan, Fickling), it actually loads the model inside the sandbox while
tracing Python callbacks (`sys.settrace`) and system calls (`strace`), then
flags files that issue suspicious syscalls — `execve`, `connect`, `socket`, or
`chmod` — after the initial benign `execve` of the Python interpreter.

## Pinned version

- Commit: `5725b26f62a1c0e4f22c793761cefb70ead64ee5` (HEAD of `main`,
  2025-08-28). The project has no releases; this is the pinned `HEAD`.

## Build

```sh
./containers/modeltracer/build.sh
```

Produces `regenbench/modeltracer:0.6.0` and `regenbench/modeltracer:latest`.

## Usage

```sh
podman run --rm -v /abs/path/to/model.pkl:/artifacts/model.pkl:ro \
  regenbench/modeltracer:0.6.0 /artifacts/model.pkl
```

An optional second argument overrides serialization-method detection:

```sh
podman run --rm -v /abs/path/model.pt:/artifacts/model.pt:ro \
  regenbench/modeltracer:0.6.0 /artifacts/model.pt torch
```

Methods: `pickle`, `dill`, `joblib`, `torch`, `numpy`, `TorchScript`. Unless
overridden, the method is inferred from magic bytes (`\x93NUMPY` → numpy,
`PK\x03\x04` → torch) or extension (`.pt/.pth/.bin/.ckpt` → torch,
`.npy/.npz` → numpy, `.joblib` → joblib, else pickle), with a fallback chain
until a loader succeeds.

## Output

The wrapper emits the [unified verdict schema](../docs/verdict-schema.md) as a
single JSON object on stdout:

```json
{
  "scanner": "modeltracer",
  "version": "0.1.0",
  "commit": "5725b26",
  "target": "/artifacts/model.pkl",
  "verdict": "malicious",
  "exit_code": 1,
  "findings": [
    {"syscall": "execve", "evidence": "13:11:22.333333 execve(\"/bin/sh\", [\"sh\", \"-c\", \"id\"], 0x... ) = 0"}
  ],
  "summary": {"scanned_files": 1, "infected_files": 1, "dangerous": 1, "suspicious": 0},
  "raw_output": "..."
}
```

Each finding carries the flagged `syscall` and the matching strace line as
`evidence`. `raw_output` sums up per-method trace status and includes the
strace evidence (suspicious lines plus an excerpt). `strace` (6.8) ships in
the base image.

Exit codes: `0` benign, `1` malicious, `2` error (load failed for every
method, or missing path).

## Detection semantics & fidelity

Detection matches upstream `scripts/parse_tracer.py`: after dropping the first
`execve` (the Python launch), any of `execve`/`connect`/`socket`/`chmod` is
suspicious. The wrapper reimplements upstream `model_tracer.py` tracing
(logging + `sys.settrace` callback + `strace -f -tt -T -y -yy -s 2048`) with
corrected loaders:

- upstream passes a path *string* to `pickle.load`/`dill.load` (invalid) —
  fixed to `open(p, "rb")`
- `torch.load` defaults to `weights_only=True` on torch ≥ 2.6 (blocks
  execution) — fixed to `weights_only=False`
- `numpy.load` defaults to `allow_pickle=False` on numpy 2.x — fixed to
  `allow_pickle=True`

## Scope & limitations

- **Dynamic execution**: payloads are deserialized inside the container; the
  container is the sandbox. Run with `--network none` for extra containment
  (network attempts are still traced and flagged).
- **TensorFlow and ONNX are not included**: upstream imports them at module
  top (`modelscan`-style), but TensorFlow 2.16.1 does not support Python 3.13
  (base image) and neither format executes arbitrary code on load. Only the
  pickle-family loaders above are supported.
- The pinned upstream repo is cloned into the image at `/opt/model-tracer` as
  a reference; the wrapper implements the tracing itself.