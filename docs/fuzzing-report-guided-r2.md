# ReGenBench Fuzzing Report (guided, replicate 2)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 19 / 20 | 3 | 3.166 | 41.2% | 32.0% |
| 2 | 13 / 20 | 0 | 1.763 | 42.6% | 36.0% |
| 3 | 13 / 20 | 0 | 1.610 | 42.6% | 40.0% |
| 4 | 13 / 20 | 0 | 1.537 | 42.6% | 40.0% |
| 5 | 10 / 20 | 0 | 0.998 | 42.6% | 44.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 12 |
| overwritten | 13 |
| pypi_injected | 45 |
| external | 14 |
| indirect_chain | 16 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 8 |
| picklescan | 3 |