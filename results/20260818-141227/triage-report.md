# ReGenBench Bypass Triage and Syscall Analysis Report

This report triages and documents the scanner bypasses discovered during the pilot campaign (T6.4). It verifies that DynaHug's oracle calls represent genuine malicious behavior rather than false alarms.

## Summary Metrics
- **Total Confirmed Bypasses**: 0
- **Evasion Category Distribution**:

## Evasion Profile by Target Callable
| Dangerous Callable | Category | Evaded Scanners | Occurrence Count |
| :--- | :--- | :--- | :---: |
| — | — | — | 0 |

## Syscall Analysis & Oracle Validation
No confirmed bypasses were found in the campaign database, so there are no oracle-corroborated execution profiles to triage. The syscall profile below describes what DynaHug would log for each payload class in a run that produces bypasses; it is **not** a report of observed behavior in the current data.
- **Process Spawning (`execve`)**: `os.system` / `subprocess.Popen` payloads trigger subshells executing `python3 -c` to write sentinel files.
- **Dynamic Compilation (`eval`/`exec`)**: code-execution sinks construct file writers within the active interpreter process.
- **Network Connection Attempt (`connect`)**: reverse-shell payloads attempt TCP handshakes to external ports (caught by strace).

## Conclusion
No confirmed bypasses were found in the current campaign data, so there is no bypass corpus to triage. The static scanners did not miss any oracle-corroborated malicious candidate in the completed runs.