#!/usr/bin/env bash
# 5×5 Replication Baseline Experiment Runner
# 
# Runs 20 campaigns total:
#   - 5 replicates × 4 configurations (current, oracle_aware, oracle_dominant, unguided)
#   - 5 rounds × 20 candidates = 100 candidates per campaign
#   - ~2000 candidates total
#
# Usage: ./run_fitness_ablation_experiment.sh

set -euo pipefail

DB="data/regenbench_campaign.db"
ROUNDS=5
CAND_PER_ROUND=20
SEEDS=(1337 1338 1339 1340 1341)

echo "===================================================="
echo "5×5 FITNESS ABLATION EXPERIMENT"
echo "===================================================="
echo "Database: $DB"
echo "Rounds: $ROUNDS, Candidates/round: $CAND_PER_ROUND"
echo "Seeds: ${SEEDS[@]}"
echo "Total campaigns: 20 (5 per config)"
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
    
    if [ "$mode" = "unguided" ]; then
        PYTHONPATH=. python scripts/run_fuzzing_campaign.py \
            --mode unguided \
            --rounds $ROUNDS \
            --candidates-per-round $CAND_PER_ROUND \
            --replicate $replicate \
            --db $DB \
            --backend podman \
            --pre-filter \
            --seed $seed \
            --evasion-mode adaptive \
            --fitness-mode current \
            2>&1 | tee "logs/${run_id}.log"
    else
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
            --fitness-mode $fitness_mode \
            2>&1 | tee "logs/${run_id}.log"
    fi
    
    local status=$?
    if [ $status -eq 0 ]; then
        echo "[$(date)] Completed $run_id successfully"
    else
        echo "[$(date)] FAILED $run_id (exit code: $status)"
    fi
    return $status
}

# Create logs directory
mkdir -p logs

# Record container image digests for reproducibility
echo "Recording container image digests..."
podman images --digests | grep regenbench > logs/container_digests.txt
cat logs/container_digests.txt

# Run order: counterbalanced to avoid temporal bias
# Replicate 1: current, oracle_aware, oracle_dominant, unguided
# Replicate 2: oracle_aware, oracle_dominant, unguided, current
# Replicate 3: oracle_dominant, unguided, current, oracle_aware
# Replicate 4: unguided, current, oracle_aware, oracle_dominant
# Replicate 5: current, oracle_aware, oracle_dominant, unguided

configs_order=(
    "guided:current"
    "guided:oracle_aware"
    "guided:oracle_dominant"
    "unguided:current"
)

for rep_idx in {1..5}; do
    seed=${SEEDS[$((rep_idx-1))]}
    
    # Rotate order for counterbalancing
    offset=$(( (rep_idx - 1) % 4 ))
    
    for i in {0..3}; do
        idx=$(( (offset + i) % 4 ))
        config=${configs_order[$idx]}
        
        IFS=':' read -r mode fitness <<< "$config"
        
        run_campaign "$mode" "$fitness" "$rep_idx" "$seed"
        
        # Brief pause between campaigns to let containers clean up
        sleep 10
    done
done

echo ""
echo "===================================================="
echo "ALL CAMPAIGNS COMPLETED"
echo "===================================================="

# Run analysis
echo ""
echo "Running analysis..."
PYTHONPATH=. python scripts/analyze_fitness_ablation.py --db $DB --json results/fitness_ablation_results.json

echo ""
echo "Results available in:"
echo "  - logs/ (per-campaign logs)"
echo "  - docs/fuzzing-report-*.md (per-campaign reports)"
echo "  - results/fitness_ablation_results.json (analysis JSON)"