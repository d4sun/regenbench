# Disclosure: Panel bypass via external / numpy.testing._private.utils.runstring

## Reproduction
1. `ExternalModuleTemplate` `pipeline/templates.py:152` `numpy.testing._private.utils.runstring` with `(payload, {})` `pipeline/templates.py:42` → `GLOBAL numpy.testing._private.utils runstring` + `REDUCE`
2. Panel `modelscan` 623/990 evaded `docs/evaluation-report.md:22`, `picklescan` 514/990 `docs/evaluation-report.md:20` — this family is part of 514 but less frequent than pypi (only 1 gadget in test_diversity 3/20)
3. `StraceOracle` confirms `process` + `file`

## Root Cause
Scanners denylist `numpy` but not `numpy.testing._private.utils.runstring` (test helper, not top-level). `TEMPLATE_FAMILY_SINKS` `pipeline/templates.py:266` `external` 2 alts shows diversity but not yet rewarded.

## Suggested Fix
Add `numpy.testing._private.utils.runstring` to scanners' denylists; consider module provenance checker `pipeline/sanitizer.py:48` `_is_pypi_injected_suspicious` (if module not in seed `sys.modules` snapshot, quarantine).

## Artifact
`ExternalModuleTemplate().generate_pickle_payload("print(1)")` → `python3 -m pipeline.runner --scanner modelscan --artifact /tmp/ext.pt`
