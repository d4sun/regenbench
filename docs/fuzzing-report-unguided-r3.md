# ReGenBench Fuzzing Report (unguided, replicate 3)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 16 / 20 | 3 | 1.749 | 42.6% | 32.0% |
| 2 | 13 / 20 | 2 | 1.292 | 42.6% | 36.0% |
| 3 | 15 / 20 | 1 | 1.392 | 42.6% | 48.0% |
| 4 | 11 / 20 | 0 | 1.028 | 42.6% | 52.0% |
| 5 | 15 / 20 | 0 | 1.499 | 42.6% | 56.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 19 |
| overwritten | 17 |
| pypi_injected | 23 |
| external | 20 |
| indirect_chain | 21 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 16 |
| picklescan | 7 |