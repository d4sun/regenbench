# ReGenBench Fuzzing Report (unguided, replicate 12)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 3, candidates/round: 12
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 9 / 12 | 0 | 0.588 | 42.6% | 24.0% |
| 2 | 9 / 12 | 0 | 0.823 | 44.1% | 32.0% |
| 3 | 9 / 12 | 0 | 0.900 | 44.1% | 36.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 9 |
| overwritten | 6 |
| pypi_injected | 4 |
| external | 6 |
| indirect_chain | 11 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **random**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 6 |
| modeltracer | 12 |
| picklescan | 3 |