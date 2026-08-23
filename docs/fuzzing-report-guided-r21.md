# ReGenBench Fuzzing Report (guided, replicate 21)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 3, candidates/round: 12
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 7 / 12 | 1 | 1.761 | 44.1% | 32.0% |
| 2 | 8 / 12 | 0 | 1.856 | 44.1% | 36.0% |
| 3 | 8 / 12 | 0 | 1.468 | 44.1% | 40.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 7 |
| overwritten | 9 |
| pypi_injected | 7 |
| external | 7 |
| indirect_chain | 6 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 4 |
| picklescan | 1 |