# ReGenBench Fuzzing Report (guided, replicate 3)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 14 / 20 | 6 | 5.132 | 48.3% | 30.3% | 20% | 1.52 |
| 2 | 20 / 20 | 9 | 6.445 | 48.3% | 39.4% | 20% | 1.44 |
| 3 | 19 / 20 | 10 | 6.219 | 48.3% | 42.4% | 40% | 1.44 |
| 4 | 19 / 20 | 9 | 6.077 | 50.0% | 45.5% | 40% | 1.44 |
| 5 | 20 / 20 | 9 | 6.277 | 50.0% | 48.5% | 40% | 1.44 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 18 |
| overwritten | 14 |
| external | 13 |
| indirect_chain | 13 |
| pypi_injected | 42 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 59 |
| picklescan | 45 |