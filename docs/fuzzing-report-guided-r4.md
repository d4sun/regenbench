# ReGenBench Fuzzing Report (guided, replicate 4)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 16 / 20 | 1 | 3550.505 | 42.6% | 24.0% |
| 2 | 9 / 20 | 0 | 3513.433 | 42.6% | 24.0% |
| 3 | 12 / 20 | 0 | 2539.200 | 42.6% | 28.0% |
| 4 | 12 / 20 | 0 | 3032.055 | 42.6% | 28.0% |
| 5 | 18 / 20 | 0 | 7024.103 | 42.6% | 28.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 17 |
| overwritten | 19 |
| pypi_injected | 29 |
| external | 17 |
| indirect_chain | 18 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 8 |
| picklescan | 1 |