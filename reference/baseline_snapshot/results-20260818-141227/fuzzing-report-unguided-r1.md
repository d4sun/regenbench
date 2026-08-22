# ReGenBench Fuzzing Report (unguided, replicate 1)

- Mode: **unguided**  
- Base checkpoint: `ci/corpus/torch/benign/benign.pt`  
- Rounds: 5, candidates/round: 20
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 20 / 20 | 0 | 2.863 | 42.6% | 66.7% |
| 2 | 20 / 20 | 0 | 3.105 | 42.6% | 72.2% |
| 3 | 20 / 20 | 0 | 3.234 | 44.1% | 77.8% |
| 4 | 20 / 20 | 0 | 2.834 | 44.1% | 77.8% |
| 5 | 20 / 20 | 0 | 2.855 | 44.1% | 77.8% |