# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 13 / 20 | 1 | 3040.100 | 41.2% | 24.0% |
| 2 | 12 / 20 | 0 | 4521.000 | 42.6% | 36.0% |
| 3 | 10 / 20 | 0 | 3516.933 | 42.6% | 36.0% |
| 4 | 13 / 20 | 0 | 4522.643 | 42.6% | 44.0% |
| 5 | 13 / 20 | 0 | 4027.208 | 42.6% | 44.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 22 |
| overwritten | 11 |
| pypi_injected | 28 |
| external | 22 |
| indirect_chain | 17 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 10 |
| picklescan | 1 |