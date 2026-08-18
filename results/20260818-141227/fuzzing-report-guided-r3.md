# ReGenBench Fuzzing Report (guided, replicate 3)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, pypi_injected, external  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 20 / 20 | 0 | 3.035 | 44.1% | 33.3% |
| 2 | 20 / 20 | 0 | 3.064 | 45.6% | 44.4% |
| 3 | 20 / 20 | 0 | 3.493 | 45.6% | 50.0% |
| 4 | 20 / 20 | 0 | 3.235 | 45.6% | 55.6% |
| 5 | 20 / 20 | 0 | 3.343 | 45.6% | 61.1% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 27 |
| overwritten | 23 |
| pypi_injected | 22 |
| external | 28 |