# ReGenBench Fuzzing Report (unguided, replicate 1)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__Maykeye_TinyLLama-v0.bin`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 24, candidates/round: 20
- Time budget: 8.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 17 / 18 | 2 | 2.343 | 45.6% | 24.0% |
| 2 | 19 / 20 | 3 | 2.391 | 48.5% | 40.0% |
| 3 | 17 / 19 | 4 | 2.424 | 48.5% | 60.0% |
| 4 | 18 / 20 | 4 | 2.335 | 48.5% | 68.0% |
| 5 | 19 / 19 | 0 | 2.133 | 48.5% | 72.0% |
| 6 | 19 / 20 | 7 | 2.674 | 48.5% | 72.0% |
| 7 | 18 / 19 | 5 | 2.511 | 48.5% | 76.0% |
| 8 | 17 / 20 | 2 | 2.047 | 48.5% | 76.0% |
| 9 | 16 / 19 | 4 | 2.155 | 48.5% | 76.0% |
| 10 | 18 / 20 | 4 | 2.391 | 48.5% | 80.0% |
| 11 | 17 / 19 | 5 | 2.418 | 48.5% | 80.0% |
| 12 | 19 / 20 | 3 | 2.324 | 48.5% | 80.0% |
| 13 | 18 / 19 | 7 | 2.610 | 48.5% | 80.0% |
| 14 | 17 / 17 | 2 | 2.343 | 48.5% | 80.0% |
| 15 | 18 / 18 | 4 | 2.595 | 48.5% | 80.0% |
| 16 | 20 / 20 | 2 | 2.553 | 48.5% | 80.0% |
| 17 | 18 / 19 | 3 | 2.372 | 48.5% | 80.0% |
| 18 | 18 / 20 | 1 | 1.891 | 48.5% | 80.0% |
| 19 | 17 / 19 | 3 | 2.155 | 48.5% | 80.0% |
| 20 | 19 / 19 | 5 | 2.551 | 48.5% | 80.0% |
| 21 | 19 / 20 | 4 | 2.291 | 48.5% | 80.0% |
| 22 | 19 / 19 | 5 | 2.734 | 48.5% | 80.0% |
| 23 | 18 / 19 | 4 | 2.595 | 48.5% | 80.0% |
| 24 | 18 / 20 | 2 | 2.315 | 48.5% | 80.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 102 |
| overwritten | 88 |
| pypi_injected | 95 |
| external | 93 |
| indirect_chain | 102 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **random**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 462 |
| modelscan | 179 |
| picklescan | 85 |