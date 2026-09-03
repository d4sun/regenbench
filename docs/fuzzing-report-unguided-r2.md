# ReGenBench Fuzzing Report (unguided, replicate 2)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 17 / 20 | 3 | 1.408 | 50.0% | 24.2% | 20% | 1.56 |
| 2 | 16 / 19 | 2 | 1.282 | 50.0% | 33.3% | 20% | 1.57 |
| 3 | 15 / 19 | 3 | 1.167 | 50.0% | 39.4% | 20% | 1.54 |
| 4 | 16 / 20 | 2 | 1.218 | 50.0% | 51.5% | 20% | 1.55 |
| 5 | 14 / 19 | 4 | 1.214 | 51.7% | 57.6% | 20% | 1.51 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 20 |
| overwritten | 17 |
| external | 19 |
| indirect_chain | 23 |
| pypi_injected | 21 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 41 |
| picklescan | 20 |