# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `ci/corpus/torch/benign/benign.pt`  
- Rounds: 5, candidates/round: 20
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 20 / 20 | 0 | 2.648 | 44.1% | 55.6% |
| 2 | 20 / 20 | 0 | 3.263 | 44.1% | 72.2% |
| 3 | 20 / 20 | 0 | 2.998 | 44.1% | 77.8% |
| 4 | 20 / 20 | 0 | 2.942 | 44.1% | 77.8% |
| 5 | 20 / 20 | 0 | 2.641 | 44.1% | 77.8% |