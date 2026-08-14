#!/usr/bin/env python3
"""
KALPA: AI Kavach Benchmarking & Evaluation Suite
Executes KALPA CRS across multiple target codebases (Python + C/C++) and computes AI Kavach scoring metrics:
- Vulnerability Discovery Rate (%)
- Patch Success Rate / Non-regression Rate (%)
- Mean Time to Repair (MTTR) (seconds)
- Resource Efficiency Index (CPU %, RAM MB, LLM Tokens per fix)
"""

import sys
import os
import json
import time
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kalpa.config import KalpaConfig
from kalpa.orchestrator.controller import KalpaController
from kalpa.models import normalize_to_utc_naive

def run_evaluation(targets_dir: str, output_report: str):
    targets_dir = os.path.abspath(targets_dir)
    if not os.path.exists(targets_dir):
        print(f"Error: Targets directory '{targets_dir}' does not exist.")
        sys.exit(1)

    target_folders = [
        os.path.join(targets_dir, f) for f in os.listdir(targets_dir)
        if os.path.isdir(os.path.join(targets_dir, f))
    ]

    print("============================================================")
    print(" AI Kavach Benchmarking & Evaluation Suite - KALPA CRS")
    print(f" Targets Evaluated: {len(target_folders)}")
    print("============================================================")

    overall_start = time.time()
    results_per_target = []
    total_found = 0
    total_fixed = 0
    total_repair_time = 0.0
    total_llm_calls = 0
    total_llm_tokens = 0

    for target in target_folders:
        target_name = os.path.basename(target)
        print(f"\n[EVAL] Running KALPA CRS on target: {target_name}")
        
        config = KalpaConfig(project_root=target, llm_provider="rule_based")
        controller = KalpaController(target, config)
        
        t_start = time.time()
        bundles = controller.run_autonomous_loop()
        t_duration = time.time() - t_start
        
        found = len(bundles)
        fixed = sum(1 for b in bundles if b.patch_result.applied_successfully)
        
        total_found += found
        total_fixed += fixed
        total_repair_time += t_duration
        
        for b in bundles:
            total_llm_calls += b.metrics.llm_calls_made
            total_llm_tokens += b.metrics.llm_tokens_used

        results_per_target.append({
            "target_name": target_name,
            "vulnerabilities_found": found,
            "vulnerabilities_fixed": fixed,
            "patch_success_rate": (fixed / found * 100) if found > 0 else 100.0,
            "duration_seconds": round(t_duration, 2)
        })

    overall_duration = round(time.time() - overall_start, 2)
    overall_psr = (total_fixed / total_found * 100) if total_found > 0 else 100.0
    mttr = round(total_repair_time / total_found, 2) if total_found > 0 else 0.0

    eval_summary = {
        "evaluation_timestamp": normalize_to_utc_naive(datetime.datetime.now(datetime.timezone.utc)).isoformat(),
        "total_targets_evaluated": len(target_folders),
        "total_vulnerabilities_found": total_found,
        "total_vulnerabilities_fixed": total_fixed,
        "patch_success_rate_percent": round(overall_psr, 2),
        "mean_time_to_repair_seconds": mttr,
        "total_evaluation_time_seconds": overall_duration,
        "resource_efficiency": {
            "total_llm_calls": total_llm_calls,
            "total_llm_tokens": total_llm_tokens,
            "avg_tokens_per_fix": round(total_llm_tokens / total_fixed, 1) if total_fixed > 0 else 0
        },
        "target_breakdown": results_per_target
    }

    # Write report JSON
    with open(output_report, "w", encoding="utf-8") as f:
        json.dump(eval_summary, f, indent=2)

    # Write Markdown summary report
    md_path = output_report.rsplit(".", 1)[0] + ".md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# AI Kavach Benchmark & Evaluation Report\n\n")
        f.write(f"**Timestamp**: `{eval_summary['evaluation_timestamp']}`\n\n")
        f.write("## Key Performance Indicators (KPIs)\n")
        f.write(f"- **Vulnerabilities Found**: {total_found}\n")
        f.write(f"- **Vulnerabilities Fixed**: {total_fixed}\n")
        f.write(f"- **Patch Success Rate (PSR)**: **{overall_psr:.1f}%**\n")
        f.write(f"- **Mean Time to Repair (MTTR)**: **{mttr}s**\n")
        f.write(f"- **Total Duration**: {overall_duration}s\n\n")
        f.write("## Target Breakdown\n")
        f.write("| Target Name | Found | Fixed | PSR (%) | Duration (s) |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: |\n")
        for t in results_per_target:
            f.write(f"| `{t['target_name']}` | {t['vulnerabilities_found']} | {t['vulnerabilities_fixed']} | {t['patch_success_rate']:.1f}% | {t['duration_seconds']}s |\n")

    print("\n============================================================")
    print(" AI Kavach Benchmark Execution Summary")
    print(f" Vulnerabilities Found: {total_found} | Fixed: {total_fixed}")
    print(f" Patch Success Rate (PSR): {overall_psr:.1f}%")
    print(f" Mean Time to Repair (MTTR): {mttr}s")
    print(f" Reports Generated: {output_report} & {md_path}")
    print("============================================================")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Kavach Evaluation Suite for KALPA CRS")
    parser.add_argument("--targets-dir", default="targets", help="Directory containing target codebases")
    parser.add_argument("--output", default="eval_report.json", help="Output report JSON file path")
    args = parser.parse_args()

    run_evaluation(args.targets_dir, args.output)
