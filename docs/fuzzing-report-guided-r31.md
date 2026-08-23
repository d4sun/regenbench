# ReGenBench Fuzzing Report (guided, replicate 31)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 16 / 20 | 1 | 2.969 | 42.6% | 32.0% |
| 2 | 14 / 20 | 0 | 2.197 | 42.6% | 36.0% |
| 3 | 17 / 20 | 0 | 2.506 | 42.6% | 36.0% |
| 4 | 13 / 20 | 0 | 1.535 | 42.6% | 44.0% |
| 5 | 17 / 20 | 0 | 1.960 | 42.6% | 52.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 20 |
| overwritten | 21 |
| pypi_injected | 14 |
| external | 19 |
| indirect_chain | 26 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 8 |
| picklescan | 1 |