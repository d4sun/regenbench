# ReGenBench Fuzzing Report (unguided, replicate 1)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 17 / 20 | 4 | 1.290 | 51.7% | 30.3% | 20% | 1.51 |
| 2 | 15 / 20 | 4 | 1.213 | 51.7% | 45.5% | 40% | 1.54 |
| 3 | 19 / 20 | 6 | 1.594 | 51.7% | 54.5% | 40% | 1.54 |
| 4 | 17 / 20 | 3 | 1.413 | 53.4% | 60.6% | 40% | 1.51 |
| 5 | 17 / 20 | 4 | 1.354 | 53.4% | 66.7% | 40% | 1.58 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 21 |
| overwritten | 17 |
| external | 18 |
| indirect_chain | 24 |
| pypi_injected | 20 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 43 |
| picklescan | 25 |