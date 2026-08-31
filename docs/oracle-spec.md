# Oracle Spec (P2.1)

**StraceOracle** `pipeline/monitor.py:12` — deterministic, 0% FP.

## Syscall Rubric (1pt per category, ≥2 malicious, 0 benign, 1 suspicious)
- **File:** `openat/open/creat` on sensitive `/etc/`, `/.ssh/`, `/tmp/regenbench`, `/tmp` O_CREAT/O_WRONLY, or `corpus_pwned`/`trigger_` marker `pipeline/monitor.py:27`.
- **Network:** `socket/connect/sendto/recvfrom` `pipeline/monitor.py:45`.
- **Process:** `clone/fork/vfork/execve` excluding benign startup `execve("/usr/bin/python3.13"` `pipeline/monitor.py:68`.

## Implementation
- `strace -f -e trace=execve,openat,open,creat,connect,socket,sendto,recvfrom,clone,fork,vfork -o /monitor/trace.log sh -c 'python3.13 -c "import torch; torch.load(...)" || python3 -c ...'` `pipeline/monitor.py:44` — fallback `python3` if `3.13` missing, full trace kept `-8000` not `-4000`.
- `LoadTimeMonitor` `pipeline/monitor.py:77` same but `execve,openat,connect,sendto,recvfrom` + `files_created` via `Path(td).iterdir()`.

## Target
- 0% FP on 17 HF `real_benign_corpus/all`, 100% on 514 ExecutionOracle `pipeline/validity.py:21` bypasses `docs/evaluation-report.md:77`.

## DynaHug Differential (P2.2)
- `scripts/calibrate_oracle.py:42` → blank `ci/corpus/torch/benign/benign.pt` trace subtracted `scripts/calibrate_oracle.py:85` before `build_features` to remove startup baseline. If blank fails, raw counts used. Report in `calibration-report.json`.
