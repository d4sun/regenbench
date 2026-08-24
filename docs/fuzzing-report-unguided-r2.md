# ReGenBench Fuzzing Report (unguided, replicate 2)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 14 / 20 | 0 | 1.170 | 42.6% | 28.0% |
| 2 | 12 / 20 | 0 | 1.099 | 42.6% | 36.0% |
| 3 | 14 / 20 | 1 | 1.449 | 42.6% | 36.0% |
| 4 | 16 / 20 | 3 | 1.763 | 42.6% | 40.0% |
| 5 | 16 / 20 | 3 | 1.713 | 42.6% | 52.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 23 |
| overwritten | 15 |
| pypi_injected | 23 |
| external | 18 |
| indirect_chain | 21 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 17 |
| picklescan | 7 |