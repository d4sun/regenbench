# ReGenBench Fuzzing Report (unguided, replicate 2)

- Mode: **unguided**  
- Base checkpoint: `ci/corpus/torch/benign/benign.pt`  
- Rounds: 5, candidates/round: 20
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 20 / 20 | 0 | 3.320 | 44.1% | 66.7% |
| 2 | 20 / 20 | 0 | 2.748 | 44.1% | 77.8% |
| 3 | 20 / 20 | 0 | 3.384 | 44.1% | 77.8% |
| 4 | 20 / 20 | 0 | 3.070 | 44.1% | 77.8% |
| 5 | 20 / 20 | 0 | 2.977 | 44.1% | 77.8% |