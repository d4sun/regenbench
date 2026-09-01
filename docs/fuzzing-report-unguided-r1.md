# ReGenBench Fuzzing Report (unguided, replicate 1)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 24, candidates/round: 20
- Time budget: 4.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 19 / 20 | 1 | 2.104 | 51.7% | 27.3% | 20% | 1.54 |
| 2 | 17 / 20 | 2 | 2.013 | 53.4% | 42.4% | 20% | 1.52 |
| 3 | 16 / 20 | 4 | 2.108 | 53.4% | 45.5% | 40% | 1.56 |
| 4 | 16 / 20 | 2 | 1.913 | 53.4% | 57.6% | 40% | 1.58 |
| 5 | 17 / 19 | 4 | 2.382 | 53.4% | 66.7% | 40% | 1.56 |
| 6 | 14 / 19 | 4 | 1.904 | 53.4% | 72.7% | 40% | 1.52 |
| 7 | 17 / 20 | 4 | 2.149 | 53.4% | 78.8% | 40% | 1.55 |
| 8 | 18 / 20 | 3 | 2.208 | 53.4% | 81.8% | 40% | 1.60 |
| 9 | 17 / 20 | 4 | 2.258 | 53.4% | 87.9% | 40% | 1.58 |
| 10 | 19 / 20 | 1 | 2.268 | 53.4% | 87.9% | 40% | 1.54 |
| 11 | 16 / 20 | 3 | 2.168 | 53.4% | 87.9% | 40% | 1.57 |
| 12 | 16 / 20 | 1 | 1.722 | 53.4% | 87.9% | 40% | 1.51 |
| 13 | 16 / 20 | 4 | 2.113 | 53.4% | 90.9% | 40% | 1.58 |
| 14 | 18 / 20 | 6 | 2.504 | 53.4% | 90.9% | 40% | 1.51 |
| 15 | 17 / 20 | 4 | 2.113 | 53.4% | 90.9% | 40% | 1.57 |
| 16 | 15 / 18 | 3 | 2.004 | 53.4% | 90.9% | 40% | 1.52 |
| 17 | 18 / 20 | 4 | 2.313 | 53.4% | 97.0% | 40% | 1.57 |
| 18 | 18 / 20 | 3 | 2.308 | 53.4% | 97.0% | 40% | 1.52 |
| 19 | 18 / 20 | 2 | 2.113 | 53.4% | 97.0% | 40% | 1.57 |
| 20 | 15 / 19 | 2 | 1.861 | 53.4% | 97.0% | 40% | 1.54 |
| 21 | 16 / 19 | 3 | 2.282 | 53.4% | 97.0% | 40% | 1.57 |
| 22 | 16 / 19 | 4 | 2.205 | 53.4% | 97.0% | 40% | 1.57 |
| 23 | 15 / 20 | 1 | 1.827 | 53.4% | 100.0% | 40% | 1.54 |
| 24 | 17 / 20 | 5 | 2.313 | 53.4% | 100.0% | 40% | 1.57 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 94 |
| overwritten | 102 |
| pypi_injected | 100 |
| external | 96 |
| indirect_chain | 88 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **random**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 473 |
| modelscan | 176 |
| picklescan | 93 |