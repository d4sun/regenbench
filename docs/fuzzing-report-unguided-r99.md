# ReGenBench Fuzzing Report (unguided, replicate 99)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 2, candidates/round: 3
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 3 / 3 | 0 | 2.142 | 42.6% | 16.0% |
| 2 | 3 / 3 | 1 | 2.617 | 42.6% | 20.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 1 |
| overwritten | 0 |
| pypi_injected | 1 |
| external | 2 |
| indirect_chain | 2 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 6 |
| modelscan | 3 |
| picklescan | 1 |