# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 2, candidates/round: 3
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 3 / 3 | 0 | 1.617 | 41.2% | 20.0% |
| 2 | 3 / 3 | 0 | 1.617 | 41.2% | 20.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 1 |
| overwritten | 0 |
| pypi_injected | 0 |
| external | 2 |
| indirect_chain | 3 |