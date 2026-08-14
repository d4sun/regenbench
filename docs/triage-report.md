# ReGenBench Bypass Triage and Syscall Analysis Report

This report documents the triage workflow (T6.4) applied to confirmed scanner
bypasses from the campaign database. Triage verifies that a bypass entry
represents genuine malicious behavior (payload execution during
deserialization) rather than a false alarm, and records the syscall evidence
for each entry.

## Status

- **Total confirmed bypasses in the campaign DB as of this report**: 0
- **Triaged entries**: 0

No bypasses have been confirmed yet, so there is no triage content to present.
This is a truthful statement of the current state of `data/regenbench_campaign.db`;
it is **not** evidence that static scanners cannot be evaded, and this report
must not be read as claiming otherwise.

## Triage workflow (applied once confirmed bypasses exist)

For each confirmed bypass exported by `pipeline/corpus_manager.py`
(`data/bypasses/<run_id>/`):

1. **Re-run the artifact** in the `regenbench/dynahug` sandbox under
   `strace -f` and confirm the expected syscall signature of the injected
   callable:
   - `os.system` / `subprocess.Popen` / `subprocess.run` → `execve`,
     `vfork`, `wait4`, `write`.
   - `builtins.eval` / `builtins.exec` / `pandas.eval` → no subprocess
     syscalls; the payload runs in-process (sentinel file write visible as a
     `open`/`write` syscall from the Python process itself).
2. **Corroborate the sentinel**: the trigger file written by the payload must
   exist after the container exits (this is exactly what the validity oracle
   checks).
3. **Record** per-entry: candidate id, callable, panel verdicts, oracle
   verdict/decision score, and the syscall evidence in `data/bypasses/`.

## Summary Metrics

| Metric | Value |
| :--- | :---: |
| Total Confirmed Bypasses | 0 |
| Triaged Entries | 0 |

## Conclusion

With zero confirmed bypasses, there are currently no entries to triage and no
syscall evidence to report. This report will be regenerated from the campaign
database after a successful pilot run that yields confirmed bypasses.
