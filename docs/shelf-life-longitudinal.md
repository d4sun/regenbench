# Shelf-Life Longitudinal (P4.1)

**Problem:** Historical 514×6 100% retention `docs/evaluation-report.md:113` is blind-spot persistence, not patch-resilience.

## Coordinated Disclosure Pipeline
- Select 5 bypasses (one per family) → file disclosures with PickleScan, ModelScan, Fickling maintainers.
- `scripts/rescan_bypasses.py` (new) — weekly `docker pull` latest tags, re-run 514 via `pipeline/shelf_life.py:ShelfLifeTracker` + `pipeline/runner.py`, log `data/shelf_life.db` `rescans` retention, track time-to-patch (TTP).

```bash
python3 scripts/rescan_bypasses.py --db data/regenbench_campaign.db --weekly --backend docker
```

## Synthetic Patch Simulation (P4.2)
- Forks `containers/picklescan-patched/Dockerfile` (FROM `regenbench/picklescan:latest` + rule `IPython.utils.process.system`) and `containers/modelscan-patched/Dockerfile` (splice `STACK_GLOBAL` detection).
- Measure retention drops 100%→<50% to validate benchmark killability.
- Build: `containers/picklescan-patched/build.sh` → `regenbench/picklescan:patched`

## Deliverable
- Retention curves + TTP in this file; measured retention reported in `docs/evaluation-report.md` (H3).
