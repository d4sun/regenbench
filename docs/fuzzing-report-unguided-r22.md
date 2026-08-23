# ReGenBench Fuzzing Report (unguided, replicate 22)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 3, candidates/round: 12
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 8 / 12 | 2 | 0.748 | 42.6% | 32.0% |
| 2 | 8 / 12 | 1 | 0.904 | 42.6% | 44.0% |
| 3 | 5 / 12 | 1 | 0.440 | 44.1% | 44.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 10 |
| overwritten | 3 |
| pypi_injected | 10 |
| external | 9 |
| indirect_chain | 4 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **random**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 8 |
| picklescan | 4 |