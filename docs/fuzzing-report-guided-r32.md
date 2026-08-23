# ReGenBench Fuzzing Report (guided, replicate 32)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 14 / 20 | 0 | 2.573 | 42.6% | 24.0% |
| 2 | 12 / 20 | 0 | 2.099 | 42.6% | 32.0% |
| 3 | 18 / 20 | 0 | 2.805 | 42.6% | 48.0% |
| 4 | 12 / 20 | 0 | 1.808 | 42.6% | 56.0% |
| 5 | 16 / 20 | 0 | 2.305 | 42.6% | 60.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 33 |
| overwritten | 14 |
| pypi_injected | 20 |
| external | 18 |
| indirect_chain | 15 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 11 |