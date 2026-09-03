# ReGenBench Fuzzing Report (guided, replicate 4)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, external, indirect_chain, pypi_injected  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage (reachable) | Callable Coverage | Family bypass | Entropy |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 18 / 20 | 3 | 2.268 | 50.0% | 24.2% | 20% | 1.56 |
| 2 | 18 / 20 | 6 | 1.938 | 50.0% | 33.3% | 20% | 1.57 |
| 3 | 18 / 20 | 9 | 2.359 | 50.0% | 48.5% | 20% | 1.40 |
| 4 | 18 / 20 | 6 | 1.829 | 50.0% | 57.6% | 20% | 1.44 |
| 5 | 17 / 20 | 9 | 1.968 | 50.0% | 63.6% | 20% | 1.43 |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 18 |
| overwritten | 14 |
| external | 16 |
| indirect_chain | 16 |
| pypi_injected | 36 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| modelscan | 55 |
| picklescan | 38 |