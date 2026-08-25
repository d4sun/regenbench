# ReGenBench Fuzzing Report (guided, replicate 2)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 14 / 20 | 0 | 4530.933 | 44.1% | 44.0% |
| 2 | 12 / 20 | 1 | 6006.000 | 44.1% | 52.0% |
| 3 | 13 / 20 | 0 | 6011.500 | 45.6% | 60.0% |
| 4 | 11 / 20 | 0 | 5505.167 | 45.6% | 60.0% |
| 5 | 13 / 20 | 0 | 6010.167 | 45.6% | 68.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 100 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 19 |
| picklescan | 16 |