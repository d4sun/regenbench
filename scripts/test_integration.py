#!/usr/bin/env python3
"""T4.5 — E2E Integration Test Suite.

Verifies E2E execution over 10 known cases (5 benign, 5 malicious), checks database
schema linkage, pre-filter bypass logic, and fitness score registration.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import sqlite3

from pipeline.runner import Runner, Config
from pipeline.db import get_candidate_summary, log_fitness
from pipeline.registry import load_registry


def run_integration_test():
    print("====================================================")
    print("STARTING E2E INTEGRATION TEST (T4.5)")
    print("====================================================")
    
    load_registry()
    
    # 1. Create a temporary folder for the SQLite database and copy test files
    temp_dir = tempfile.mkdtemp()
    corpus_dir = os.path.join(temp_dir, "corpus")
    os.makedirs(corpus_dir)
    db_path = os.path.join(temp_dir, "campaign.db")
    
    # Source corpus directories
    src_pkl_benign = "ci/corpus/pkl/benign"
    src_pkl_malicious = "ci/corpus/pkl/malicious"
    src_pt_benign = "ci/corpus/torch/benign"
    src_pt_malicious = "ci/corpus/torch/malicious"
    
    try:
        # Copy 3 benign pickle files
        benign_paths = []
        for i in range(1, 4):
            src_file = os.path.join(src_pkl_benign, f"benign_{i:02d}.pkl")
            dest_file = os.path.join(corpus_dir, f"benign_pkl_{i}.pkl")
            shutil.copy(src_file, dest_file)
            benign_paths.append(dest_file)
            
        # Copy 2 benign torch files (reusing benign.pt twice under different names to make 5 total)
        for i in range(1, 3):
            src_file = os.path.join(src_pt_benign, "benign.pt")
            dest_file = os.path.join(corpus_dir, f"benign_torch_{i}.pt")
            shutil.copy(src_file, dest_file)
            benign_paths.append(dest_file)
            
        # Copy 3 malicious pickle files
        malicious_paths = []
        for i in range(1, 4):
            src_file = os.path.join(src_pkl_malicious, f"malicious_{i:02d}.pkl")
            dest_file = os.path.join(corpus_dir, f"malicious_pkl_{i}.pkl")
            shutil.copy(src_file, dest_file)
            malicious_paths.append(dest_file)
            
        # Copy 2 malicious torch files
        for i in range(1, 3):
            src_file = os.path.join(src_pt_malicious, "malicious.pt")
            dest_file = os.path.join(corpus_dir, f"malicious_torch_{i}.pt")
            shutil.copy(src_file, dest_file)
            malicious_paths.append(dest_file)
            
        print(f"Prepared 5 benign candidates: {[os.path.basename(p) for p in benign_paths]}")
        print(f"Prepared 5 malicious candidates: {[os.path.basename(p) for p in malicious_paths]}")
            
        # 2. Run the runner on all 10 candidates
        print("\nExecuting E2E runner...")
        config = Config(backend="podman", tag=":latest", max_workers=4, timeout=60, oracle=True)
        # Run picklescan, fickling, and the dynahug oracle
        runner = Runner(config, scanners=["picklescan", "fickling", "dynahug"])
        
        all_paths = benign_paths + malicious_paths
        results = runner.run(all_paths, db_path=db_path)
        
        print(f"Runner completed. Scan result count: {len(results)}")
        
        # 3. Assert Database Persistence & Linkages
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check candidates table count
        cursor.execute("SELECT COUNT(*) FROM candidates")
        cnt = cursor.fetchone()[0]
        assert cnt == 10, f"Expected 10 candidates, found {cnt}"
        
        # Verify pre-filtering: benign candidates should be pre-filtered (pre_filtered = 1)
        # and malicious ones should be admitted and evaluated.
        cursor.execute("SELECT candidate_id, filepath FROM candidates")
        cands = cursor.fetchall()
        for cand_id, filepath in cands:
            is_benign = "benign_" in filepath
            
            # Query oracle result only for torch checkpoints
            if "_torch_" in filepath:
                cursor.execute("SELECT verdict, pre_filtered FROM oracle_results WHERE candidate_id = ?", (cand_id,))
                oracle_row = cursor.fetchone()
                assert oracle_row is not None, f"No oracle record for {filepath}"
                verdict, pre_filtered = oracle_row
                
                if is_benign:
                    assert pre_filtered == 1, f"Expected benign candidate {filepath} to be pre-filtered"
                    assert verdict == "benign", f"Expected benign candidate {filepath} to be labeled benign"
                else:
                    assert pre_filtered == 0, f"Expected malicious torch candidate {filepath} to not be pre-filtered"
                
            # Log a fitness score for each candidate (to test T4.4 fitness scoring table)
            # Fitness = number of panel scanner bypasses (label == 'benign')
            cursor.execute("SELECT verdict FROM panel_results WHERE candidate_id = ?", (cand_id,))
            panels = cursor.fetchall()
            bypasses = sum(1 for (v,) in panels if v == "benign")
            fitness_val = float(bypasses)
            
            log_fitness(db_path, cand_id, fitness_val, is_valid=True)
            
            # Fetch E2E summary from database for verification
            summary = get_candidate_summary(db_path, cand_id)
            assert summary is not None
            assert summary["filepath"] == filepath
            assert "scanner_results" in summary
            assert "oracle_result" in summary
            assert "fitness" in summary
            assert summary["fitness"]["fitness_score"] == fitness_val
            
        conn.close()
        print("\n====================================================")
        print("INTEGRATION TEST PASSED SUCCESSFULLY!")
        print("====================================================")
        
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    run_integration_test()
