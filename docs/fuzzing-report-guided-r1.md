# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, pypi_injected, external, indirect_chain  
- Rounds: 25, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 18 / 20 | 7 | 6.465 | 50.0% | 24.2% | 20% | 1.54 |
| 2 | 19 / 20 | 9 | 6.204 | 50.0% | 33.3% | 20% | 1.44 |
| 3 | 18 / 20 | 9 | 5.863 | 50.0% | 42.4% | 20% | 1.44 |
| 4 | 19 / 20 | 9 | 5.987 | 50.0% | 48.5% | 20% | 1.44 |
| 5 | 18 / 20 | 9 | 5.757 | 50.0% | 54.5% | 20% | 1.44 |
| 6 | 18 / 20 | 9 | 5.821 | 50.0% | 60.6% | 20% | 1.44 |
| 7 | 17 / 20 | 9 | 5.508 | 50.0% | 66.7% | 20% | 1.44 |
| 8 | 19 / 20 | 9 | 6.012 | 50.0% | 72.7% | 20% | 1.44 |
| 9 | 19 / 20 | 9 | 5.809 | 50.0% | 72.7% | 20% | 1.44 |
| 10 | 18 / 20 | 9 | 5.697 | 50.0% | 78.8% | 20% | 1.44 |
| 11 | 19 / 20 | 9 | 5.991 | 50.0% | 78.8% | 20% | 1.44 |
| 12 | 19 / 20 | 9 | 5.891 | 50.0% | 84.8% | 20% | 1.44 |
| 13 | 17 / 20 | 9 | 5.487 | 50.0% | 90.9% | 20% | 1.44 |
| 14 | 19 / 20 | 9 | 5.917 | 50.0% | 93.9% | 20% | 1.44 |
| 15 | 19 / 20 | 9 | 5.895 | 50.0% | 97.0% | 20% | 1.44 |
| 16 | 19 / 20 | 9 | 5.974 | 50.0% | 100.0% | 20% | 1.44 |
| 17 | 19 / 20 | 9 | 5.887 | 50.0% | 100.0% | 20% | 1.44 |
| 18 | 18 / 20 | 9 | 5.674 | 50.0% | 100.0% | 20% | 1.44 |
| 19 | 18 / 20 | 9 | 5.671 | 50.0% | 100.0% | 20% | 1.44 |
| 20 | 18 / 20 | 9 | 5.568 | 50.0% | 100.0% | 20% | 1.44 |
| 21 | 20 / 20 | 9 | 6.073 | 50.0% | 100.0% | 20% | 1.44 |
| 22 | 20 / 20 | 9 | 6.069 | 50.0% | 100.0% | 20% | 1.44 |
| 23 | 19 / 20 | 9 | 5.960 | 50.0% | 100.0% | 20% | 1.44 |
| 24 | 17 / 20 | 9 | 5.466 | 50.0% | 100.0% | 20% | 1.44 |
| 25 | 20 / 20 | 9 | 6.163 | 50.0% | 100.0% | 20% | 1.44 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 76 |
| overwritten | 74 |
| pypi_injected | 223 |
| external | 73 |
| indirect_chain | 54 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 314 |
| picklescan | 237 |