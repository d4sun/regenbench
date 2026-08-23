# ReGenBench Fuzzing Report (guided, replicate 11)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 3, candidates/round: 12
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 11 / 12 | 0 | 2.643 | 41.2% | 24.0% |
| 2 | 8 / 12 | 0 | 1.823 | 44.1% | 24.0% |
| 3 | 10 / 12 | 0 | 1.845 | 44.1% | 28.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 8 |
| overwritten | 6 |
| pypi_injected | 9 |
| external | 6 |
| indirect_chain | 7 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 6 |
| modeltracer | 17 |
| picklescan | 1 |