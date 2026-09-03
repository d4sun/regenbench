# ReGenBench Fuzzing Report (unguided, replicate 4)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 18 / 20 | 4 | 1.468 | 51.7% | 21.2% | 20% | 1.57 |
| 2 | 16 / 19 | 1 | 1.124 | 53.4% | 36.4% | 20% | 1.58 |
| 3 | 17 / 20 | 4 | 1.404 | 53.4% | 48.5% | 20% | 1.60 |
| 4 | 18 / 20 | 2 | 1.413 | 53.4% | 54.5% | 20% | 1.54 |
| 5 | 13 / 20 | 2 | 0.931 | 53.4% | 69.7% | 20% | 1.43 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 24 |
| overwritten | 21 |
| external | 22 |
| indirect_chain | 17 |
| pypi_injected | 16 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 44 |
| picklescan | 21 |