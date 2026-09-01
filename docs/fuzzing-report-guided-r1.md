# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 25, candidates/round: 20
- Time budget: 6.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 19 / 20 | 7 | 8.572 | 50.0% | 24.2% | 20% | 1.54 |
| 2 | 18 / 20 | 9 | 7.738 | 50.0% | 33.3% | 20% | 1.44 |
| 3 | 17 / 20 | 9 | 7.311 | 50.0% | 42.4% | 20% | 1.44 |
| 4 | 19 / 20 | 9 | 7.914 | 50.0% | 51.5% | 20% | 1.44 |
| 5 | 19 / 20 | 9 | 7.959 | 50.0% | 60.6% | 20% | 1.43 |
| 6 | 19 / 20 | 9 | 7.923 | 50.0% | 63.6% | 20% | 1.44 |
| 7 | 19 / 20 | 9 | 7.832 | 50.0% | 66.7% | 20% | 1.44 |
| 8 | 17 / 20 | 9 | 7.201 | 50.0% | 75.8% | 20% | 1.44 |
| 9 | 19 / 20 | 9 | 7.814 | 50.0% | 78.8% | 20% | 1.44 |
| 10 | 20 / 20 | 9 | 8.130 | 50.0% | 81.8% | 20% | 1.44 |
| 11 | 19 / 20 | 9 | 7.893 | 50.0% | 81.8% | 20% | 1.44 |
| 12 | 18 / 20 | 9 | 7.488 | 50.0% | 84.8% | 20% | 1.44 |
| 13 | 18 / 20 | 9 | 7.527 | 50.0% | 87.9% | 20% | 1.44 |
| 14 | 20 / 20 | 9 | 8.090 | 50.0% | 90.9% | 20% | 1.44 |
| 15 | 18 / 20 | 9 | 7.478 | 50.0% | 93.9% | 20% | 1.44 |
| 16 | 19 / 20 | 9 | 7.882 | 50.0% | 93.9% | 20% | 1.44 |
| 17 | 19 / 20 | 9 | 7.872 | 50.0% | 93.9% | 20% | 1.44 |
| 18 | 19 / 20 | 9 | 7.816 | 50.0% | 93.9% | 20% | 1.44 |
| 19 | 19 / 20 | 9 | 7.775 | 50.0% | 97.0% | 20% | 1.44 |
| 20 | 20 / 20 | 9 | 8.259 | 50.0% | 97.0% | 20% | 1.44 |
| 21 | 19 / 20 | 9 | 7.869 | 50.0% | 100.0% | 20% | 1.44 |
| 22 | 19 / 20 | 9 | 7.767 | 50.0% | 100.0% | 20% | 1.44 |
| 23 | 20 / 20 | 9 | 8.112 | 50.0% | 100.0% | 20% | 1.44 |
| 24 | 20 / 20 | 9 | 8.069 | 50.0% | 100.0% | 20% | 1.44 |
| 25 | 20 / 20 | 9 | 8.273 | 50.0% | 100.0% | 20% | 1.43 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 75 |
| overwritten | 72 |
| pypi_injected | 223 |
| external | 76 |
| indirect_chain | 54 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 500 |
| modelscan | 309 |
| picklescan | 229 |