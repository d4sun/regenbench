# ReGenBench Fuzzing Report (guided, replicate 2)

- Mode: **guided**  
- Base checkpoint: `ci/corpus/torch/benign/benign.pt`  
- Rounds: 5, candidates/round: 20
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 20 / 20 | 0 | 3.170 | 44.1% | 61.1% |
| 2 | 20 / 20 | 0 | 2.942 | 44.1% | 66.7% |
| 3 | 20 / 20 | 0 | 2.934 | 44.1% | 72.2% |
| 4 | 20 / 20 | 0 | 3.092 | 44.1% | 72.2% |
| 5 | 20 / 20 | 0 | 2.655 | 44.1% | 77.8% |