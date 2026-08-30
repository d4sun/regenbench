# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__Maykeye_TinyLLama-v0.bin`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 25, candidates/round: 20
- Time budget: 8.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 20 / 20 | 4 | 8.404 | 45.6% | 28.0% |
| 2 | 20 / 20 | 10 | 8.627 | 45.6% | 36.0% |
| 3 | 20 / 20 | 17 | 9.621 | 45.6% | 40.0% |
| 4 | 19 / 20 | 17 | 9.191 | 45.6% | 48.0% |
| 5 | 19 / 20 | 14 | 8.657 | 45.6% | 52.0% |
| 6 | 20 / 20 | 17 | 9.468 | 45.6% | 52.0% |
| 7 | 20 / 20 | 16 | 9.346 | 45.6% | 52.0% |
| 8 | 20 / 20 | 17 | 9.321 | 45.6% | 52.0% |
| 9 | 20 / 20 | 20 | 9.898 | 45.6% | 52.0% |
| 10 | 20 / 20 | 19 | 9.726 | 45.6% | 56.0% |
| 11 | 20 / 20 | 19 | 9.709 | 45.6% | 56.0% |
| 12 | 20 / 20 | 18 | 9.612 | 45.6% | 56.0% |
| 13 | 20 / 20 | 17 | 9.430 | 45.6% | 56.0% |
| 14 | 20 / 20 | 17 | 9.427 | 45.6% | 56.0% |
| 15 | 20 / 20 | 20 | 9.892 | 45.6% | 56.0% |
| 16 | 20 / 20 | 18 | 9.608 | 45.6% | 56.0% |
| 17 | 20 / 20 | 17 | 9.411 | 45.6% | 56.0% |
| 18 | 20 / 20 | 16 | 9.327 | 45.6% | 56.0% |
| 19 | 20 / 20 | 18 | 9.607 | 45.6% | 56.0% |
| 20 | 20 / 20 | 19 | 9.694 | 45.6% | 56.0% |
| 21 | 20 / 20 | 20 | 9.889 | 45.6% | 56.0% |
| 22 | 20 / 20 | 20 | 9.888 | 45.6% | 56.0% |
| 23 | 20 / 20 | 20 | 9.888 | 45.6% | 56.0% |
| 24 | 19 / 20 | 18 | 9.207 | 45.6% | 60.0% |
| 25 | 20 / 20 | 20 | 9.887 | 45.6% | 60.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 17 |
| overwritten | 14 |
| pypi_injected | 428 |
| external | 19 |
| indirect_chain | 22 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 500 |
| modelscan | 447 |
| picklescan | 428 |