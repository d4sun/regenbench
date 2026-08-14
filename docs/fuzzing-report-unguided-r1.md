# ReGenBench Fuzzing Report (unguided, replicate 1)

- Mode: **unguided**  
- Base checkpoint: `ci/corpus/torch/benign/benign.pt`  
- Rounds: 2, candidates/round: 6
- DB: `/tmp/opencode/fuzz_unguided.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 5 / 6 | 0 | 1.404 | 44.1% | 27.8% |
| 2 | 6 / 6 | 0 | 1.284 | 44.1% | 55.6% |