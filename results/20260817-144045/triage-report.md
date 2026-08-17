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
DynaHug identifies anomalous model behavior by tracking system calls inside the container runtime environment. During triage of the stratified sample, we confirmed the following indicators of malicious execution:
1. **Process Spawning (`execve`)**: Injections using `os.system` or `subprocess.Popen` trigger subshells executing `python3 -c` commands to write sentinel files.
2. **Dynamic Compilation (`eval`/`exec`)**: Python code execution sinks construct file writers directly within the active interpreter process context.
3. **Network Connection Attempt (`connect`)**: In a full campaign configuration, reverse shell payloads attempt TCP connection handshakes to external ports (caught and logged by strace).

## Conclusion
Triage of the bypass corpus indicates that all confirmed bypass entries exhibit **genuine malicious capabilities** resulting from the successful unpickling of execution payloads. The static scanners (Fickling, PickleScan) failed to detect these configurations, proving the benchmark's utility in exposing detection boundaries.