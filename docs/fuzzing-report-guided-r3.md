# ReGenBench Fuzzing Report (guided, replicate 3)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 10 / 20 | 1 | 4014.667 | 44.1% | 52.0% |
| 2 | 13 / 20 | 1 | 6506.500 | 45.6% | 60.0% |
| 3 | 11 / 20 | 0 | 5505.500 | 45.6% | 64.0% |
| 4 | 15 / 20 | 0 | 7012.500 | 45.6% | 64.0% |
| 5 | 10 / 20 | 0 | 4509.667 | 45.6% | 68.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 100 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 15 |
| picklescan | 15 |