# Fickling scanner container

Reproducible container for [Fickling](https://github.com/trailofbits/fickling)
(trailofbits/fickling), a decompiler, static analyzer, and bytecode rewriter
for Python pickle object serializations.

## Pinned version

- Release: `v0.1.12`
- Commit: `c3c695cdcce451c04dfe892802675161614287a2`

Pinned per the PickleFuzzer/ShadowPickle practice so scanner behavior is
reproducible across rebuilds. Fickling requires Python `>=3.10` (no upper
bound), so it runs on the base image's Python 3.13.15 without override.

## Build

```sh
./containers/fickling/build.sh
```

Produces `regenbench/fickling:0.5.0` and `regenbench/fickling:latest`.

## Usage

```sh
podman run --rm -v /abs/path/to/model.pkl:/artifacts/model.pkl:ro \
  regenbench/fickling:0.5.0 /artifacts/model.pkl
```

The target must be mounted into the container; its path is passed as argv.

## Output

The wrapper emits the [unified verdict schema](../docs/verdict-schema.md) as a
single JSON object on stdout:

```json
{
  "scanner": "fickling",
  "version": "0.1.12",
  "commit": "c3c695c",
  "target": "/artifacts/model.pkl",
  "verdict": "benign",
  "exit_code": 0,
  "findings": [],
  "summary": {"scanned": 1, "dangerous": 0, "suspicious": 0},
  "raw_output": "..."
}
```

Each finding carries Fickling's `severity`, `analysis` text, and
`detailed_results`. Fickling appends one JSON object per stacked pickle; the
wrapper parses all of them and maps the highest to the verdict.

Exit codes (ClamAV-compatible): `0` benign, `1` malicious, `2` error.
