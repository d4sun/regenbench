# Reference dataset (Phase 1)

Published baseline numbers transcribed from the source papers, used for
**directional** comparison only — see
[`docs/comparison-methodology.md`](../docs/comparison-methodology.md).

| File | Contents |
|---|---|
| [`published-scanner-metrics.json`](published-scanner-metrics.json) | Machine-readable: ShadowPickle Tables IV/VI/XII + PickleFuzzer Table I (T1.1) |
| [`published-dynahug-metrics.json`](published-dynahug-metrics.json) | Machine-readable: DynaHug Tables 5/6/7/8 (T1.2) |
| [`oracle-sanity.json`](oracle-sanity.json) | Pretrained-oracle working-checkpoint record (T1.3) |
| [`sanity-verdict-log.json`](sanity-verdict-log.json) | 6-model panel+oracle smoke verdict log (T1.4) |

Human-readable tables: [`../docs/reference-scanner-metrics.md`](../docs/reference-scanner-metrics.md)
and [`../docs/reference-dynahug-metrics.md`](../docs/reference-dynahug-metrics.md).

## T1.4 sanity smoke test

`scripts/sanity_smoke.py` runs the full panel (picklescan/modelscan/fickling/
modeltracer) plus the DynaHug oracle against a 6-model sanity set (3 obviously
benign, 3 obviously malicious — the committed corpus plus one real
text-generation model fetched at runtime) and writes
`sanity-verdict-log.json`. The real model file is not committed.

```sh
python3 scripts/sanity_smoke.py --model openai-community/gpt2
```