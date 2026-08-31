# Synthetic Patch Evaluation (P4.2)

**Goal:** Retention drops measurably (e.g. 100%→<50%) against patched forks, proving benchmark killability.

## Patched Scanners
- `containers/picklescan-patched/Dockerfile`:
```dockerfile
FROM regenbench/picklescan:latest
# Add rule for IPython.utils.process.system
COPY patched-rules.yaml /opt/picklescan/rules/
```
- `containers/modelscan-patched/Dockerfile`:
```dockerfile
FROM regenbench/modelscan:latest
COPY gguf-header-check.py /opt/modelscan/checks/gguf_patch.py
```

## Evaluation
```bash
for img in picklescan-patched modelscan-patched; do
  docker build -t regenbench/$img:patched containers/$img/
  python3 scripts/shelf_life_rescan.py --db data/regenbench_campaign.db --image $img=regenbench/$img:patched
done
sqlite3 data/shelf_life.db "SELECT new_version, retention_rate FROM rescans GROUP BY new_version;"
```

## Expected
- Picklescan-patched: 510 pypi_injected → 0 retained (100%→0% for that family)
- Modelscan-patched: splice transport detection → 514→<50
- Document in `docs/evaluation-report.md` H3 as synthetic vs longitudinal.
