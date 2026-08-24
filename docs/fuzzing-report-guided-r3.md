# ReGenBench Fuzzing Report (guided, replicate 3)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 14 / 20 | 0 | 3.353 | 42.6% | 32.0% |
| 2 | 14 / 20 | 0 | 3.336 | 42.6% | 36.0% |
| 3 | 17 / 20 | 0 | 3.968 | 42.6% | 44.0% |
| 4 | 15 / 20 | 0 | 2.984 | 42.6% | 48.0% |
| 5 | 15 / 20 | 0 | 3.219 | 42.6% | 56.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 15 |
| overwritten | 21 |
| pypi_injected | 16 |
| external | 15 |
| indirect_chain | 33 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 6 |