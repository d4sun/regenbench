# ReGenBench Fuzzing Report (unguided, replicate 33)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 14 / 20 | 3 | 1.592 | 41.2% | 32.0% |
| 2 | 17 / 20 | 2 | 1.713 | 41.2% | 48.0% |
| 3 | 16 / 20 | 0 | 1.334 | 42.6% | 52.0% |
| 4 | 15 / 20 | 1 | 1.363 | 42.6% | 56.0% |
| 5 | 15 / 20 | 1 | 1.470 | 42.6% | 56.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 25 |
| overwritten | 14 |
| pypi_injected | 16 |
| external | 17 |
| indirect_chain | 28 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **random**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 16 |
| picklescan | 7 |