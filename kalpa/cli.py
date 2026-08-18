#!/usr/bin/env python3
"""
KALPA CLI Entrypoint module for setuptools package scripts ('kalpa' command).
"""

import sys
import argparse
import os

from kalpa.config import KalpaConfig
from kalpa.orchestrator.controller import KalpaController

def main():
    parser = argparse.ArgumentParser(
        prog="kalpa",
        description="KALPA: Autonomous Cyber Reasoning System (CRS) for AI Kavach"
    )
    parser.add_argument(
        "--target",
        "-t",
        default="targets/vulnerable_service",
        help="Target codebase repository or directory path (default: targets/vulnerable_service)"
    )
    parser.add_argument(
        "--sarif",
        "-s",
        default=None,
        help="Optional path to pre-generated SARIF static analysis report"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="evidence_bundles",
        help="Directory to save generated evidence bundles and reports"
    )
    parser.add_argument(
        "--provider",
        choices=["auto", "openai", "anthropic", "gemini", "ollama", "vllm", "rule_based"],
        default="auto",
        help="LLM provider mode for Causal Reasoning Engine"
    )
    parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434",
        help="Ollama or local vLLM endpoint URL (default: http://localhost:11434)"
    )
    parser.add_argument(
        "--model",
        default="deepseek-coder",
        help="Model name for local or API LLM reasoning engine (default: deepseek-coder)"
    )
    parser.add_argument(
        "--max-fuzz-time",
        type=int,
        default=30,
        help="Maximum fuzzing duration budget per vulnerability in seconds"
    )

    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the interactive KALPA Defense Operations Web Dashboard (FastAPI server on port 8000)"
    )

    parser.add_argument(
        "--export-cicd",
        action="store_true",
        help="Export GitHub Actions CI/CD Security Contract workflow (.github/workflows/kalpa_contracts.yml)"
    )

    args = parser.parse_args()

    if args.dashboard:
        import uvicorn
        print("============================================================")
        print(" Launching KALPA Defense Operations Web Dashboard...")
        print(" URL: http://127.0.0.1:8000")
        print("============================================================")
        uvicorn.run("kalpa.dashboard.app:app", host="127.0.0.1", port=8000, reload=False)
        sys.exit(0)

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    config = KalpaConfig(
        project_root=target_path,
        output_dir=args.output_dir,
        llm_provider=args.provider
    )
    config.budget.max_fuzz_seconds = args.max_fuzz_time

    controller = KalpaController(target_path, config)
    bundles = controller.run_autonomous_loop(args.sarif)

    if args.export_cicd:
        from kalpa.contract_compiler.cicd_exporter import CICDContractExporter
        contracts = [b.security_contract for b in bundles if b.security_contract]
        exporter = CICDContractExporter(target_path)
        wf_path = exporter.export_github_action(contracts)
        print(f"[CI/CD EXPORT] Workflow written to: {wf_path}")

    successful_patches = sum(1 for b in bundles if b.patch_result.applied_successfully)
    print(f"\n[KALPA SUMMARY] Target: {os.path.basename(target_path)} | Vulnerabilities: {len(bundles)} | Fixed: {successful_patches}")
    
    sys.exit(0)

if __name__ == "__main__":
    main()
