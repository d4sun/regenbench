# ReGenBench Fuzzing Report (unguided, replicate 1)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/ci/corpus/torch/benign/benign.pt`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 100
- Time budget: 24.0h
- DB: `/tmp/opencode/scaled_proof.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 87 / 94 | 18 | 2.160 | 44.1% | 56.0% |
| 2 | 93 / 96 | 14 | 2.247 | 45.6% | 68.0% |
| 3 | 91 / 95 | 14 | 2.123 | 45.6% | 76.0% |
| 4 | 91 / 98 | 17 | 2.197 | 45.6% | 76.0% |
| 5 | 89 / 92 | 18 | 2.333 | 45.6% | 80.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 100 |
| overwritten | 97 |
| external | 113 |
| indirect_chain | 87 |
| pypi_injected | 103 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 475 |
| modelscan | 196 |
| picklescan | 83 |