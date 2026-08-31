# Unified Verdict Schema (T0.3–T0.7)

Every scanner and oracle container in `pipeline/scanners.py` emits **one JSON object on the last line of stdout**. The host `run_scan` (`pipeline/scanners.py:run_scan`) parses that line; all other stdout is scanner logs and ignored.

## Schema

```json
{
  "verdict": "benign" | "malicious" | "error",
  "exit_code": 0 | 1 | 2,
  "decision_score": float | null,
  "findings": [string | object],
  "matched_rules": [string],
  "scanner": "picklescan" | "modelscan" | "fickling" | "modeltracer" | "dynahug" | "ggufref",
  "duration": float
}
```

| Field | Type | Meaning |
|---|---|---|
| `verdict` | string | **benign** = scanner saw no malicious signal; **malicious** = scanner asserts malicious; **error** = scanner crashed, artifact not supported, or no verdict produced. `error` is **fail-closed**: never counted as `benign` (see `pipeline/comparator.py:check_bypass`, `pipeline/runner.py:_one`). |
| `exit_code` | int | Container exit code: `0` benign, `1` malicious, `2` error (mirrors `docs/verdict-schema.md` convention). Used for shell triage; `verdict` is authoritative. |
| `decision_score` | float | Oracle-only signal. **DynaHug**: OCSVM decision function (distance to boundary, vs `-rho`); **ggufref**: `1` malicious / `0` benign; **panel scanners**: `0` or omitted. Panel evasion fitness uses `1/(1+|decision_score|)` as boundary proximity (`pipeline/fitness.py:compute_fitness`). |
| `findings` | list | Scanner-specific details (file paths, opcodes, matched GLOBAL strings, strace execve snippets). Logged verbatim to `panel_results.findings` (JSON) and `docs/fuzzing-report-*`. |
| `matched_rules` | list | Rule names that fired (e.g. `global:os.system`, `global:builtins.exec`). Fed to `FeedbackController._ingest_greybox` to down-weight `0.85×` flagged callables. |
| `scanner` | string | Echoes container image name for traceability. |
| `duration` | float | Seconds from `pipeline/runner.py:_one` wall clock, stored in `panel_results.duration` / `oracle_results.duration`. |

## Invocation

Host mounts artifact read-only at `/artifact` with `:ro,z` (shared SELinux relabel) and passes `/artifact` as argv:

```sh
docker run --rm -v /abs/path/model.pt:/artifact:ro,z regenbench/picklescan:latest /artifact
# or ggufref:
docker run --rm --security-opt label=disable -v /abs/model.gguf:/artifact:ro,z -v /tmp:/tmp regenbench/gguf:latest /artifact
```

For DynaHug with a recalibrated model:

```sh
docker run --rm -e DYNAHUG_MODEL_DIR=/opt/dynahug/recalibrated \
  -v /abs/recalibrated:/opt/dynahug/recalibrated:ro,z \
  -v /abs/model.pt:/artifact:ro,z regenbench/dynahug:latest /artifact
```

`pipeline/scanners.py:run_scan` adds `--timeout 90` only for `podman` (docker `run` rejects `--timeout`; host `subprocess.run(timeout=...)` bounds docker instead) and `--security-opt label=disable` only for `ggufref` (needs `/tmp` writes for SSTI trigger).

## Kinds

- **panel** (`picklescan`, `modelscan`, `fickling`, `modeltracer`) — run on any artifact; decision is `all benign → bypass` vs `any malicious/error → not bypass`.
- **oracle** (`dynahug` on `.pt/.pth/.bin`, `ggufref` on `.gguf`) — `dynahug` is **supplementary** `decision_score` only; `ggufref` is authoritative for GGUF. Primary bypass confirmation is `ValidityOracle` / `PlausibilityOracle` trigger poll (`pipeline/validity.py:_trigger_exists`, `StraceOracle` 0% FP), not the statistical oracle (see `CLAUDE.md` Known bugs, `pipeline/comparator.py`).

## Storage

- `panel_results` (`candidate_id`, `scanner`, `verdict`, `exit_code`, `findings`, `duration`)
- `oracle_results` (`candidate_id`, `verdict`, `decision_score`, `duration`, `pre_filtered`)
- `campaign_fitness` (`fitness_score`, `is_valid` via `ValidityOracle`, `transport`, `strategies`)

See `pipeline/db.py:init_db` for idempotent migrations.

## Example

```json
{"verdict": "benign", "exit_code": 0, "decision_score": -0.12, "findings": [], "matched_rules": [], "scanner": "picklescan", "duration": 1.23}
{"verdict": "malicious", "exit_code": 1, "decision_score": 0.87, "findings": ["global:os.system"], "matched_rules": ["global:os.system"], "scanner": "modelscan", "duration": 1.41}
```
