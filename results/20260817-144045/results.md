# ReGenBench Results

- Generated: 20260817-144045
- Campaign DB: `data/regenbench_campaign.db`
- Benign corpus files: 96

## Campaigns

| Run | Type | Replicate | Candidates | Valid | Confirmed Bypasses |
| :--- | :--- | :---: | :---: | :---: | :---: |
| pilot-20260816T030153Z | guided | 1 | 100 | 93 | 0 |
| guided-r1 | guided | 1 | 100 | 100 | 0 |
| guided-r2 | guided | 2 | 100 | 100 | 0 |
| unguided-r1 | unguided | 1 | 100 | 100 | 0 |
| unguided-r2 | unguided | 2 | 100 | 100 | 0 |

## Panel verdicts (all runs)

- **fickling**: malicious=74, benign=0, error=426
- **modelscan**: malicious=377, benign=0, error=123
- **modeltracer**: malicious=15, benign=1, error=484
- **picklescan**: malicious=424, benign=0, error=76

## Oracle verdicts (all runs)

- error: 209
- malicious: 291
