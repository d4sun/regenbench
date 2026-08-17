# ReGenBench Fuzzing Report (guided, replicate 1)

- Mode: **guided**  
- Base checkpoint: `/home/d4sun/Projects/PhD/regenbench/real_benign_corpus/all/text-generation__HuggingFaceM4_tiny-random-LlamaForCausalLM.bin`  
- Attack families: gadget, overwritten, pypi_injected, external  
- Rounds: 1, candidates/round: 4
- Time budget: 24.0h
- DB: `regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 4 / 4 | 0 | 3.500 | 30.9% | 11.1% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 0 |
| overwritten | 0 |
| pypi_injected | 2 |
| external | 2 |