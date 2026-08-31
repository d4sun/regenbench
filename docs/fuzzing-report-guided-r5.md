# ReGenBench Fuzzing Report (guided, replicate 5) — ARCHIVAL (pre-fix pilot, not in live DB `data/regenbench_campaign.db`)

- Mode: **guided**  
- Base checkpoint: `real_benign_corpus/all/text-generation__Maykeye_TinyLLama-v0.bin`  
- Attack families: gadget  
- Rounds: 5, candidates/round: 20
- Time budget: 24.0h
- DB: `data/regenbench_campaign.db`

| Round | Valid / Generated | Confirmed Bypasses | Mean Fitness | Opcode Coverage | Callable Coverage |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 15 / 20 | 0 | 3547.167 | 44.1% | 48.0% |
| 2 | 14 / 20 | 0 | 6512.000 | 45.6% | 56.0% |
| 3 | 14 / 20 | 0 | 6511.667 | 45.6% | 64.0% |
| 4 | 14 / 20 | 1 | 7006.667 | 45.6% | 72.0% |
| 5 | 9 / 20 | 1 | 4008.833 | 45.6% | 72.0% |

## Attack-family distribution

| Family | Candidates |
| :--- | :---: |
| gadget | 100 |

## Per-scanner evasions (verdict=benign on valid candidates)

Evasion mode: **adaptive**

| Scanner | Evasions |
| :--- | :---: |
| fickling | 100 |
| modelscan | 18 |
| picklescan | 19 |