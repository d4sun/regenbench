#!/usr/bin/env bash
# 5× Oracle-Dominant Validation Experiment
# 
# Runs 5 replicates of guided oracle_dominant with best configuration:
#   - Real corpus seeding (text-generation cluster)
#   - Oracle-dominant fitness
#   - Adaptive evasion mode
#   - 5 rounds × 20 candidates = 100 candidates per campaign
#   - 5 replicates = 500 total candidates
#   - Attack families: gadget, overwritten, external, indirect_chain (no pypi_injected)
#
# Usage: ./run_oracle_dominant_validation.sh

set -euo pipefail

DB="data/regenbench_campaign.db"
ROUNDS=5
CAND_PER_ROUND=20
SEEDS=(1337 1338 1339 1340 1341)

echo "===================================================="
echo "5× ORACLE-DOMINANT VALIDATION EXPERIMENT"
echo "===================================================="
echo "Database: $DB"
echo "Rounds: $ROUNDS, Candidates/round: $CAND_PER_ROUND"
echo "Seeds: ${SEEDS[@]}"
echo "Total campaigns: 5 (oracle_dominant only)"
echo "Config: real corpus + oracle_dominant + adaptive evasion"
echo "Attack families: gadget, overwritten, external, indirect_chain"
echo "===================================================="

# Clean up old reports
rm -f docs/fuzzing-report-*.md

# Function to run a single campaign
run_campaign() {
    local mode=$1
    local fitness_mode=$2
    local replicate=$3
    local seed=$4
    local run_id="${mode}-${fitness_mode}-r${replicate}"

    echo ""
    echo "[$(date)] Starting $run_id (seed=$seed)..."
    
    PYTHONPATH=. python scripts/run_fuzzing_campaign.py \
        --mode guided \
        --rounds $ROUNDS \
        --candidates-per-round $CAND_PER_ROUND \
        --replicate $replicate \
        --db $DB \
        --backend podman \
        --pre-filter \
        --seed $seed \
        --evasion-mode adaptive \
        --fitness-mode oracle_dominant \
        --seed-corpus-dir real_benign_corpus/all \
        --seed-cluster text-generation \
        --attack-families gadget,overwritten,external,indirect_chain \
        2>&1 | tee "logs/${run_id}.log"
    
    local status=$?
    if [ $status -eq 0 ]; then
        echo "[$(date)] Completed $run_id successfully"
    else
        echo "[$(date)] FAILED $run_id (exit code: $status)"
    fi
    return $status
}

# Record container image digests for reproducibility
echo "Recording container image digests..."
podman images --digests | grep regenbench > logs/container_digests.txt
cat logs/container_digests.txt

mkdir -p logs

# Run 5 replicates
for i in {1..5}; do
    seed=${SEEDS[$((i-1))]}
    run_campaign "guided" "oracle_dominant" "$i" "$seed"
    sleep 10
done

echo ""
echo "===================================================="
echo "ALL 5 CAMPAIGNS COMPLETED"
echo "===================================================="

# Run analysis
echo ""
echo "Running analysis..."
PYTHONPATH=. python scripts/analyze_fitness_ablation.py --db $DB --json results/oracle_dominant_validation.json

echo ""
echo "Results available in:"
echo "  - logs/ (per-campaign logs)"
echo "  - docs/fuzzing-report-*.md (per-campaign reports)"
echo "  - results/oracle_dominant_validation.json (analysis JSON)"