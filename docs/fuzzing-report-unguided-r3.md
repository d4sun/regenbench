# ReGenBench Fuzzing Report (unguided, replicate 3)

- Mode: **unguided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 16 / 20 | 4 | 1.308 | 51.7% | 27.3% | 20% | 1.58 |
| 2 | 16 / 20 | 3 | 1.163 | 53.4% | 36.4% | 20% | 1.57 |
| 3 | 18 / 20 | 1 | 1.058 | 53.4% | 42.4% | 20% | 1.54 |
| 4 | 17 / 20 | 4 | 1.404 | 53.4% | 51.5% | 20% | 1.60 |
| 5 | 18 / 20 | 4 | 1.558 | 53.4% | 57.6% | 40% | 1.57 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 18 |
| overwritten | 23 |
| external | 18 |
| indirect_chain | 19 |
| pypi_injected | 22 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 41 |
| picklescan | 22 |