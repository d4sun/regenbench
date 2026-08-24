# ReGenBench Fuzzing Report (unguided, replicate 4)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 18 / 20 | 0 | 1.513 | 42.6% | 28.0% |
| 2 | 15 / 20 | 1 | 1.499 | 42.6% | 32.0% |
| 3 | 15 / 20 | 1 | 1.392 | 42.6% | 32.0% |
| 4 | 16 / 20 | 0 | 1.570 | 42.6% | 32.0% |
| 5 | 13 / 20 | 1 | 1.299 | 42.6% | 32.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 10 |
| overwritten | 26 |
| pypi_injected | 14 |
| external | 23 |
| indirect_chain | 27 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 12 |
| picklescan | 3 |