# ReGenBench Fuzzing Report (guided, replicate 2)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 16 / 20 | 3 | 2.469 | 50.0% | 27.3% | 20% | 1.58 |
| 2 | 18 / 20 | 4 | 1.771 | 50.0% | 39.4% | 20% | 1.54 |
| 3 | 18 / 20 | 9 | 2.113 | 50.0% | 48.5% | 20% | 1.43 |
| 4 | 18 / 20 | 8 | 2.121 | 50.0% | 57.6% | 20% | 1.44 |
| 5 | 18 / 20 | 8 | 1.938 | 50.0% | 63.6% | 20% | 1.44 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 16 |
| overwritten | 15 |
| external | 17 |
| indirect_chain | 16 |
| pypi_injected | 36 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 57 |
| picklescan | 37 |