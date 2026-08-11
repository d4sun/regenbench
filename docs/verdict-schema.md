# Unified Verdict Schema

Shared JSON contract emitted by every scanner container (T0.3–T0.6) and the
behavioral oracle (T0.7). Each wrapper reads a target artifact from an
argv-provided path and prints exactly one JSON object to stdout.

## Fields

| Field | Type | Description |
|---|---|---|
| `scanner` | string | Scanner id, e.g. `picklescan` |
| `version` | string | Scanner release/package version |
| `commit` | string | Short commit hash of the pinned scanner source |
| `target` | string | Path of the scanned artifact (as passed to the wrapper) |
| `verdict` | string | `malicious` \| `benign` \| `error` |
| `exit_code` | int | Scanner-style exit code (0 clean, 1 malware, 2 error) |
| `findings` | array | Structured per-finding records (scanner-specific shape) |
| `summary` | object | Counters: `scanned_files`, `infected_files`, `dangerous`, `suspicious` |
| `raw_output` | string | Captured scanner output (text) for audit/backward compatibility |
| `decision_score` | float\|null | Oracle-only (T0.7, `dynahug`). Signed OneClassSVM `decision_function`; benign > 0, malicious < 0. `null` when the verdict is `error`. |

## Verdict rules

- `malicious` — scanner reported dangerous findings (e.g. PickleScan
  `issues_count > 0`).
- `benign` — scanner completed with no dangerous findings.
- `error` — scanner failed to complete (scan error or exception); `exit_code`
  should be `2`.

`exit_code` mirrors the container's process exit status so callers can use
either the JSON or the process status.

## Findings record

Scanner-specific. For PickleScan, each finding is:

```json
{"module": "builtins", "name": "eval", "safety": "Dangerous"}
```

`safety` is `Dangerous` or `Suspicious` (PickleScan `SafetyLevel`).

## Example

```json
{
  "scanner": "picklescan",
  "version": "1.0.5",
  "commit": "f15d54d",
  "target": "/artifacts/mal.pkl",
  "verdict": "malicious",
  "exit_code": 1,
  "findings": [
    {"module": "builtins", "name": "eval", "safety": "Dangerous"}
  ],
  "summary": {"scanned_files": 1, "infected_files": 1, "dangerous": 1, "suspicious": 0},
  "raw_output": "----------- SCAN SUMMARY -----------\n..."
}
```
