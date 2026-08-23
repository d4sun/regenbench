# ReGenBench Fuzzing Report (unguided, replicate 34)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 17 / 20 | 3 | 1.978 | 42.6% | 24.0% |
| 2 | 11 / 20 | 1 | 1.164 | 42.6% | 32.0% |
| 3 | 13 / 20 | 1 | 1.356 | 42.6% | 36.0% |
| 4 | 14 / 20 | 3 | 1.628 | 42.6% | 44.0% |
| 5 | 13 / 20 | 2 | 1.456 | 42.6% | 52.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 24 |
| overwritten | 23 |
| pypi_injected | 24 |
| external | 19 |
| indirect_chain | 10 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **random**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 21 |
| picklescan | 11 |