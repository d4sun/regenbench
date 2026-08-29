# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 4, candidates/round: 10
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 10 / 10 | 3 | 9.304 | 42.6% | 24.0% |
| 2 | 10 / 10 | 4 | 8.082 | 42.6% | 24.0% |
| 3 | 10 / 10 | 7 | 8.810 | 42.6% | 24.0% |
| 4 | 10 / 10 | 10 | 9.531 | 42.6% | 24.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 1 |
| overwritten | 4 |
| external | 6 |
| indirect_chain | 5 |
| pypi_injected | 24 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 40 |
| modelscan | 30 |
| picklescan | 24 |