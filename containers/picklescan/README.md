# PickleScan scanner container

Reproducible container for [PickleScan](https://github.com/mmaitre314/picklescan)
(mmaitre314/picklescan), a security scanner detecting Python Pickle files that
perform suspicious actions.

## Pinned version

- Release: `v1.0.5`
- Commit: `f15d54da3dec9aa28a87ede82f87882bb80f1023`

Pinned per the PickleFuzzer/ShadowPickle practice so scanner behavior is
reproducible across rebuilds.

## Build

```sh
./containers/picklescan/build.sh
```

Produces `regenbench/picklescan:0.3.0` and `regenbench/picklescan:latest`.

## Usage

```sh
podman run --rm -v /abs/path/to/model.pkl:/artifacts/model.pkl:ro \
  regenbench/picklescan:0.3.0 /artifacts/model.pkl
```

The target must be mounted into the container; its path is passed as argv.
Directories are scanned recursively.

## Output

The wrapper emits the [unified verdict schema](../docs/verdict-schema.md) as a
single JSON object on stdout:

```json
{
  "scanner": "picklescan",
  "version": "1.0.5",
  "commit": "f15d54d",
  "target": "/artifacts/model.pkl",
  "verdict": "benign",
  "exit_code": 0,
  "findings": [],
  "summary": {"scanned_files": 1, "infected_files": 0, "dangerous": 0, "suspicious": 0},
  "raw_output": ""
}
```

Exit codes: `0` benign, `1` malicious, `2` error.
