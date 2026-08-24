# ReGenBench Fuzzing Report (guided, replicate 5)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 17 / 20 | 3 | 5040.938 | 41.2% | 28.0% |
| 2 | 8 / 20 | 0 | 3013.667 | 41.2% | 32.0% |
| 3 | 10 / 20 | 0 | 3022.343 | 42.6% | 36.0% |
| 4 | 13 / 20 | 0 | 5512.707 | 42.6% | 36.0% |
| 5 | 9 / 20 | 0 | 3016.184 | 42.6% | 36.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 13 |
| overwritten | 13 |
| pypi_injected | 51 |
| external | 9 |
| indirect_chain | 14 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 7 |
| picklescan | 3 |