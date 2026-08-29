# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 100
- Time budget: 24.0h
- DB: `/tmp/opencode/scaled_proof.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 96 / 100 | 31 | 7.452 | 42.6% | 52.0% |
| 2 | 99 / 100 | 71 | 8.555 | 42.6% | 52.0% |
| 3 | 99 / 100 | 87 | 8.972 | 42.6% | 56.0% |
| 4 | 100 / 100 | 83 | 8.946 | 42.6% | 60.0% |
| 5 | 100 / 100 | 93 | 9.253 | 42.6% | 64.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 34 |
| overwritten | 33 |
| external | 37 |
| indirect_chain | 32 |
| pypi_injected | 364 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 500 |
| modelscan | 402 |
| picklescan | 365 |