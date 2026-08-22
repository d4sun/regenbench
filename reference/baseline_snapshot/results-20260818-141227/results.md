# ReGenBench Results

- Generated: 20260818-141227
- Campaign DB: `data/regenbench_campaign.db`
- Benign PyTorch/SafeTensors corpus files: 96
- Benign GGUF corpus files: 24
- MalHug real malicious corpus files: 73

## Campaigns

| Run | Type | Replicate | Candidates | Valid | Confirmed Bypasses |
| :--- | :--- | :---: | :---: | :---: | :---: |
| pilot-20260816T030153Z | guided | 1 | 100 | 93 | 0 |
| guided-r1 | guided | 1 | 100 | 100 | 0 |
| guided-r2 | guided | 2 | 100 | 100 | 0 |
| unguided-r1 | unguided | 1 | 100 | 100 | 0 |
| unguided-r2 | unguided | 2 | 100 | 100 | 0 |
| pilot-20260817T101219Z | guided | 1 | 100 | 100 | 0 |
| guided-r3 | guided | 3 | 100 | 100 | 0 |

## Panel verdicts (all runs)

- **fickling**: malicious=94, benign=0, error=606
- **modelscan**: malicious=539, benign=0, error=161
- **modeltracer**: malicious=15, benign=1, error=684
- **picklescan**: malicious=607, benign=0, error=93

## Oracle verdicts (all runs)

- error: 376
- malicious: 324

## Task 3: GGUF Attack Surface & MalHug Corpus

- **Benign GGUF Models**: 24 real crawled models (TinyLlama series + llama.cpp tokenizers)
- **MalHug Real Malicious Models**: 73 artifacts from Hugging Face repositories (ASE 2024)
- **Task 3 Report**: [`task3-demo.md`](task3-demo.md)
