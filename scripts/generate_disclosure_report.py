#!/usr/bin/env python3
"""Generate responsible disclosure report for confirmed bypasses.

Produces a structured disclosure draft with:
- Embargo tracking (discovery date, notification date, deadline)
- Affected scanner versions and vendors
- Bypass details (family, strategies, trigger code)
- Remediation guidance
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.db import _connect


# Scanner maintainer contacts (publicly available)
SCANNER_CONTACTS = {
    "picklescan": {
        "name": "picklescan",
        "repo": "https://github.com/picklescan/picklescan",
        "security_email": "security@github.com",  # GitHub security reporting
        "issue_template": "https://github.com/picklescan/picklescan/issues/new?template=security.md"
    },
    "modelscan": {
        "name": "ModelScan",
        "repo": "https://github.com/protectai/modelscan",
        "security_email": "security@protectai.com",
        "issue_template": "https://github.com/protectai/modelscan/issues/new?template=security_report.md"
    },
    "fickling": {
        "name": "Fickling",
        "repo": "https://github.com/trailofbits/fickling",
        "security_email": "security@trailofbits.com",
        "issue_template": "https://github.com/trailofbits/fickling/issues/new?template=security.md"
    },
}


DEFAULT_EMBARGO_DAYS = 90


def fetch_bypasses(db_path: str, since_days: int | None = None) -> list[dict]:
    """Fetch confirmed bypasses from the campaign database."""
    conn = _connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT c.candidate_id, c.run_id, c.mutation_template, c.callables_used,
               c.mutation_strategy, c.created_at, c.oracle_verdict, c.panel_verdict,
               f.fitness_score, f.is_valid
        FROM candidates c
        JOIN campaign_fitness f ON c.candidate_id = f.candidate_id
        WHERE f.is_valid = 1 AND c.oracle_verdict != 'error'
    """
    if since_days:
        query += " AND c.created_at >= datetime('now', ?)"
        cursor.execute(query, (f'-{since_days} days',))
    else:
        cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_rescan_data(shelf_db_path: str) -> dict:
    """Fetch shelf-life rescan data for decay curve."""
    conn = sqlite3.connect(shelf_db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get bypass records
    bypasses = cursor.execute("SELECT * FROM bypass_records").fetchall()
    
    # Get rescan results
    rescans = cursor.execute("SELECT * FROM rescans ORDER BY rescanned_at").fetchall()
    
    conn.close()
    
    return {
        "bypasses": [dict(r) for r in bypasses],
        "rescans": [dict(r) for r in rescans]
    }


def compute_decay_summary(rescans: list[dict]) -> dict:
    """Compute summary statistics from rescan data."""
    if not rescans:
        return {"message": "No rescan data available"}
    
    from collections import defaultdict
    scanner_stats = defaultdict(lambda: {"total": 0, "retained": 0})
    
    for r in rescans:
        scanner_stats[r["scanner"]]["total"] += 1
        if r["evasion_retained"]:
            scanner_stats[r["scanner"]]["retained"] += 1
    
    summary = {}
    for scanner, stats in scanner_stats.items():
        summary[scanner] = {
            "total_rescans": stats["total"],
            "retained": stats["retained"],
            "retention_rate": stats["retained"] / stats["total"] if stats["total"] > 0 else 0.0
        }
    
    return summary


def generate_disclosure_report(
    db_path: str,
    shelf_db_path: str | None = None,
    embargo_days: int = DEFAULT_EMBARGO_DAYS,
    output_dir: str = "docs/disclosure",
    notify: bool = False
) -> dict:
    """Generate disclosure report and draft notifications."""
    
    os.makedirs(output_dir, exist_ok=True)
    
    bypasses = fetch_bypasses(db_path)
    shelf_data = fetch_rescan_data(shelf_db_path or os.path.join(os.path.dirname(db_path), "shelf_life.db"))
    decay_summary = compute_decay_summary(shelf_data["rescans"])
    
    discovery_date = datetime.now(timezone.utc)
    notification_date = discovery_date + timedelta(days=1)  # Next business day
    embargo_deadline = discovery_date + timedelta(days=embargo_days)
    
    report = {
        "metadata": {
            "report_id": f"REGENBENCH-DISC-{discovery_date.strftime('%Y%m%d-%H%M%S')}",
            "generated_at": discovery_date.isoformat() + "Z",
            "embargo_deadline": embargo_deadline.isoformat() + "Z",
            "embargo_days": embargo_days,
            "total_bypasses": len(bypasses),
            "bypasses_with_rescans": len(shelf_data["bypasses"])
        },
        "embargo_timeline": {
            "discovery_date": discovery_date.isoformat() + "Z",
            "notification_date": notification_date.isoformat() + "Z",
            "embargo_deadline": embargo_deadline.isoformat() + "Z",
            "status": "EMBARGOED"
        },
        "affected_scanners": {},
        "bypasses": [],
        "decay_summary": decay_summary,
        "remediation_guidance": {
            "general": "Update static signature rules to detect obfuscated GLOBAL/STACK_GLOBAL imports. Add behavioral validation for torch.load() that checks for post-deserialization side effects.",
            "picklescan": "Enhance opcode pattern matching for STACK_GLOBAL and nested pickle streams. Add heuristic for size/entropy anomalies.",
            "modelscan": "Extend dangerous import detection to cover indirect chains (builtins.__import__ + getattr). Add payload execution sandboxing.",
            "fickling": "Improve deserialization analysis to track data flow from pickle opcodes to dangerous callables."
        }
    }
    
    # Aggregate bypasses by affected scanner
    scanner_bypasses = {}
    for bypass in bypasses:
        # Determine which scanners were evaded
        for scanner in ["picklescan", "modelscan", "fickling"]:
            if scanner not in scanner_bypasses:
                scanner_bypasses[scanner] = []
            scanner_bypasses[scanner].append(bypass)
    
    for scanner, bps in scanner_bypasses.items():
        contact = SCANNER_CONTACTS.get(scanner, {})
        report["affected_scanners"][scanner] = {
            "name": contact.get("name", scanner),
            "repo": contact.get("repo", ""),
            "security_email": contact.get("security_email", ""),
            "issue_template": contact.get("issue_template", ""),
            "bypass_count": len(bps)
        }
    
    # Detailed bypass info
    for bp in bypasses:
        report["bypasses"].append({
            "candidate_id": bp["candidate_id"][:12],
            "run_id": bp["run_id"],
            "family": bp["mutation_template"],
            "callable": bp["callables_used"],
            "strategies": bp["mutation_strategy"],
            "discovered_at": bp["created_at"],
            "oracle_verdict": bp["oracle_verdict"],
            "panel_verdict": bp["panel_verdict"],
            "fitness_score": bp["fitness_score"],
            "valid": bool(bp["is_valid"])
        })
    
    # Write JSON report
    report_path = os.path.join(output_dir, f"disclosure_{report['metadata']['report_id']}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    # Generate markdown report
    md_path = os.path.join(output_dir, f"disclosure_{report['metadata']['report_id']}.md")
    with open(md_path, "w") as f:
        f.write(f"# RegenBench Responsible Disclosure Report\n\n")
        f.write(f"**Report ID:** {report['metadata']['report_id']}  \n")
        f.write(f"**Generated:** {report['metadata']['generated_at']}  \n")
        f.write(f"**Embargo Deadline:** {report['metadata']['embargo_deadline']}  \n")
        f.write(f"**Total Bypasses:** {report['metadata']['total_bypasses']}  \n")
        f.write(f"**Status:** {report['embargo_timeline']['status']}  \n\n")
        
        f.write(f"## Embargo Timeline\n\n")
        f.write(f"- **Discovery:** {report['embargo_timeline']['discovery_date']}\n")
        f.write(f"- **Notification:** {report['embargo_timeline']['notification_date']}\n")
        f.write(f"- **Embargo Deadline:** {report['embargo_timeline']['embargo_deadline']}\n\n")
        
        f.write(f"## Affected Scanners\n\n")
        for scanner, info in report["affected_scanners"].items():
            f.write(f"### {info['name']} ({scanner})\n")
            f.write(f"- Repository: {info['repo']}\n")
            f.write(f"- Security Contact: {info['security_email']}\n")
            f.write(f"- Bypasses Found: {info['bypass_count']}\n\n")
        
        f.write(f"## Decay Summary (Shelf-Life)\n\n")
        for scanner, stats in decay_summary.items():
            if isinstance(stats, dict):
                f.write(f"- **{scanner}**: {stats['retained']}/{stats['total_rescans']} retained ({stats['retention_rate']*100:.1f}%)\n")
            else:
                f.write(f"- {scanner}: {stats}\n")
        f.write("\n")
        
        f.write(f"## Bypass Details\n\n")
        for bp in report["bypasses"]:
            f.write(f"### `{bp['candidate_id']}`\n")
            f.write(f"- Run: {bp['run_id']}\n")
            f.write(f"- Family: {bp['family']}\n")
            f.write(f"- Callable: {bp['callable']}\n")
            f.write(f"- Strategies: {bp['strategies']}\n")
            f.write(f"- Discovered: {bp['discovered_at']}\n")
            f.write(f"- Oracle: {bp['oracle_verdict']}, Panel: {bp['panel_verdict']}\n")
            f.write(f"- Fitness: {bp['fitness_score']:.2f}\n\n")
        
        f.write(f"## Remediation Guidance\n\n")
        for scanner, guidance in report["remediation_guidance"].items():
            f.write(f"### {scanner}\n{guidance}\n\n")
    
    # Generate notification drafts
    if notify:
        for scanner, info in report["affected_scanners"].items():
            draft_path = os.path.join(output_dir, f"notification_{scanner}_{report['metadata']['report_id']}.md")
            with open(draft_path, "w") as f:
                f.write(f"# Security Notification Draft for {info['name']}\n\n")
                f.write(f"**Report ID:** {report['metadata']['report_id']}\n")
                f.write(f"**Embargo Deadline:** {report['embargo_timeline']['embargo_deadline']}\n\n")
                f.write(f"## Summary\n")
                f.write(f"RegenBench has identified {info['bypass_count']} bypass(es) affecting {info['name']}. ")
                f.write(f"These bypasses exploit static signature evasion techniques in pickle deserialization.\n\n")
                f.write(f"## Technical Details\n\n")
                for bp in scanner_bypasses.get(scanner, []):
                    f.write(f"- **Candidate:** {bp['candidate_id']}\n")
                    f.write(f"  - Family: {bp['family']}\n")
                    f.write(f"  - Callable: {bp['callable']}\n")
                    f.write(f"  - Strategies: {bp['strategies']}\n")
                    f.write(f"  - Fitness: {bp['fitness_score']:.2f}\n\n")
                f.write(f"## Requested Action\n")
                f.write(f"1. Acknowledge receipt within 7 days\n")
                f.write(f"2. Provide remediation timeline\n")
                f.write(f"3. Coordinate disclosure date (after {embargo_deadline.strftime('%Y-%m-%d')})\n\n")
                f.write(f"## Contact\n")
                f.write(f"RegenBench Security Team\n")
                f.write(f"Reference: {report['metadata']['report_id']}\n")
    
    print(f"Disclosure report written to {report_path}")
    print(f"Markdown report written to {md_path}")
    if notify:
        print(f"Notification drafts written to {output_dir}/")
    
    return report


def main():
    ap = argparse.ArgumentParser(prog="generate_disclosure_report", description=__doc__)
    ap.add_argument("--db", default="data/regenbench_campaign.db")
    ap.add_argument("--shelf-db", default=None, help="shelf_life.db path (default: alongside campaign db)")
    ap.add_argument("--embargo-days", type=int, default=DEFAULT_EMBARGO_DAYS)
    ap.add_argument("--output-dir", default="docs/disclosure")
    ap.add_argument("--notify", action="store_true", help="generate notification drafts")
    ap.add_argument("--since-days", type=int, default=None, help="only include bypasses from last N days")
    args = ap.parse_args()
    
    generate_disclosure_report(
        db_path=args.db,
        shelf_db_path=args.shelf_db,
        embargo_days=args.embargo_days,
        output_dir=args.output_dir,
        notify=args.notify
    )


if __name__ == "__main__":
    main()