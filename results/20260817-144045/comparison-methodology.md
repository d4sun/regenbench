# Comparison methodology and caveats (T1.5)

This note states the comparison caveat once and is referenced by every
downstream evaluation table in this repository. Read it before interpreting
any number labelled "vs. published".

## The core caveat

The numbers transcribed in [`reference/`](../reference/) are **NOT
re-derivations** of the papers' published numbers. They are:

- reported by the original authors on **their** corpus, at **their** snapshot
  in time, under **their** harness — transcribed verbatim for directional
  reference; and
- our own measurements come from **a different corpus and a snapshot in time**
  (whatever we fetched/built locally), under our own container harness.

Therefore any side-by-side comparison is **directional**, never
apples-to-apples. A scanner that scores 90% precision in a paper and 85% on our
run cannot be claimed to have "regressed" — the denominators differ.

## What that means in practice

1. **No attribution of deltas.** Differences between a published table cell
   and one of our cells may be entirely due to corpus/snapshot effects and are
   not evidence of a claim about the tool itself.
2. **Scanner verdicts are per-artifact, not per-paper.** Our local verdicts
   show only that a tool "runs and returns a well-formed verdict on this
   artifact" (the T1.4 smoke-test purpose), not that it reproduces a paper's
   aggregate.
3. **The DynaHug oracle caveat applies throughout.** The embedded text-generation
   OCSVM was trained on ~2,000 real HuggingFace model loads (see
   [`containers/dynahug/README.md`](../containers/dynahug/README.md)). Local
   micro-checkpoints are out-of-distribution and typically score ≈ `-rho`
   (`malicious`); only a real-model-like trace yields a positive score. Any
   oracle number must be read against that documented behaviour.
4. **Bypass/evaluation numbers** produced later in this project (Phase 5-7) are
   measured against our corpus + harness configuration and must be labelled as
   such wherever they are compared with published results.

## How to cite this file

Put a one-line pointer at the top of each downstream table or results section:

> "Comparison vs. published values is directional only; see
> [`docs/comparison-methodology.md`](comparison-methodology.md) (T1.5)."