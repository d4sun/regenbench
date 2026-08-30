# ReGenBench Fuzzing Report (guided, replicate 2)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget  
- Rounds: 1, candidates/round: 2
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 2 / 2 | 0 | 16.250 | 42.6% | 12.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 0 |