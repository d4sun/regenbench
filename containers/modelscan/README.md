# ModelScan scanner container

Reproducible container for [ModelScan](https://github.com/protectai/modelscan)
(protectai/modelscan), a scanner detecting unsafe operations across model
serialization formats (pickle/PyTorch, H5, Keras, SavedModel).

## Pinned version

- Release: `v0.8.8`
- Commit: `61fcec9c2a37c24c1fb12d84ede30fe248a364bd`

Pinned per the PickleFuzzer/ShadowPickle practice so scanner behavior is
reproducible across rebuilds.

## Python 3.13 override

ModelScan declares `requires-python: >=3.10,<3.13`, but the shared base image
(T0.2) ships Python 3.13.15. The package is pure Python and is installed with
`pip install --ignore-requires-python`; import and scan behavior are
smoke-tested during the build (`modelscan --version`) and at runtime. If a
future ModelScan release regresses on Python 3.13, install Python 3.12 from the
deadsnakes PPA and install ModelScan under 3.12 instead.

## Build

```sh
./containers/modelscan/build.sh
```

Produces `regenbench/modelscan:0.4.0` and `regenbench/modelscan:latest`.

## Usage

```sh
podman run --rm -v /abs/path/to/model.pkl:/artifacts/model.pkl:ro \
  regenbench/modelscan:0.4.0 /artifacts/model.pkl
```

The target must be mounted into the container; its path is passed as argv.
Directories are scanned recursively.

## Output

The wrapper emits the [unified verdict schema](../docs/verdict-schema.md) as a
single JSON object on stdout:

```json
{
  "scanner": "modelscan",
  "version": "0.8.8",
  "commit": "61fcec9",
  "target": "/artifacts/model.pkl",
  "verdict": "benign",
  "exit_code": 0,
  "findings": [],
  "summary": {"total_issues": 0, "scanned": 1, "errors": 0},
  "raw_output": "{...native modelscan JSON report...}"
}
```

Exit codes: `0` benign, `1` malicious, `2` error, `3` no supported files
(mapped to `benign`).
