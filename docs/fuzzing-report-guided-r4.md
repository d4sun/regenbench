# ReGenBench Fuzzing Report (guided, replicate 4)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 15 / 20 | 0 | 4536.500 | 45.6% | 56.0% |
| 2 | 9 / 20 | 0 | 4504.500 | 45.6% | 60.0% |
| 3 | 13 / 20 | 0 | 6506.500 | 45.6% | 60.0% |
| 4 | 14 / 20 | 0 | 7006.000 | 45.6% | 64.0% |
| 5 | 18 / 20 | 0 | 8513.333 | 45.6% | 64.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 100 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 12 |
| picklescan | 15 |