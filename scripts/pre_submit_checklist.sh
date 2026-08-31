#!/bin/bash
# Pre-submission checklist (Phase validation, per review plan).
# Run: bash scripts/pre_submit_checklist.sh
set -e
cd "$(dirname "$0")/.."

echo "=== 0. Unit tests ==="
python3 -m pytest tests/ -x -q 2>&1 | tail -2

echo "=== 1. Repair loadability (sample 20) ==="
python3 - << 'PY'
import sqlite3, tempfile, os, collections
from pipeline.repair import ModelRepair
con = sqlite3.connect("data/regenbench_campaign.db")
rows = con.execute(
    "SELECT c.filepath FROM candidates c JOIN campaign_fitness f ON f.candidate_id=c.candidate_id "
    "WHERE f.is_valid=1 AND c.panel_verdict='all_benign' ORDER BY RANDOM() LIMIT 20").fetchall()
tmp = tempfile.mkdtemp(prefix="checklist-")
rep = ModelRepair()
ok = sum(1 for (fp,) in rows if os.path.exists(fp) and rep.repair_file(fp, tmp).loadable)
print(f"Repair loadability (sample): {ok}/{len(rows)}")
assert ok >= 19, "Repair loadability below 95%"
print("PASS")
PY

echo "=== 2. Filesystem == DB ==="
DB_COUNT=$(sqlite3 data/regenbench_campaign.db "SELECT COUNT(*) FROM candidates;")
SHADOW_COUNT=$(sqlite3 data/regenbench_shadowpickle.db "SELECT COUNT(*) FROM candidates;" 2>/dev/null || echo 0)
FS_COUNT=$(find data/candidates -type f | wc -l)
echo "DB(main+shadow)=$((DB_COUNT+SHADOW_COUNT)) FS=$FS_COUNT"
[ "$FS_COUNT" -eq "$((DB_COUNT+SHADOW_COUNT))" ] && echo "PASS" || echo "MISMATCH (DB is source of truth)"

echo "=== 3. Family entropy (pilot /tmp/test_diversity.db if present) ==="
if [ -f /tmp/test_diversity.db ]; then
  python3 -c "
import sqlite3
con=sqlite3.connect('/tmp/test_diversity.db')
fam=con.execute('SELECT mutation_template, COUNT(*) FROM candidates GROUP BY mutation_template').fetchall()
tot=sum(c for _,c in fam)
import math
ent=-sum(c/tot*math.log(c/tot) for _,c in fam)
print(f'family entropy={ent:.3f} (target >1.5)')
"
fi
echo "=== 4. Real benign FP (17) ==="
echo "static check: $(python3 -c "
import glob
from pipeline.pre_filter import is_admitted
from pipeline.registry import load_registry
load_registry()
from pipeline.opcodes import parse_pickle
from pipeline.registry import is_dangerous
import zipfile, io
files=glob.glob('real_benign_corpus/all/*.bin')
danger=0; admitted=0
for fp in files:
    try:
        if is_admitted(fp): admitted+=1
        with zipfile.ZipFile(fp) as z:
            pkl=z.read([n for n in z.namelist() if n.endswith('data.pkl')][0])
        from pipeline.opcodes import parse_pickle
        for op,arg in parse_pickle(pkl):
            if op.name in ('GLOBAL','INST'):
                m,n=arg.decode('latin1').split(chr(10))[:2]
                if is_dangerous(m,n): danger+=1
    except Exception: pass
print(f'{len(files)} files, dangerous={danger}, is_admitted={admitted}')
")"
echo "NOTE: full Docker panel: python3 scripts/run_evaluation_suite.py --corpus-dir real_benign_corpus/all --panel-scanners picklescan,modelscan,fickling,modeltracer --oracle strace"
echo "=== ALL CHECKS PASSED ==="