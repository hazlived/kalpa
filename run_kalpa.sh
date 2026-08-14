#!/usr/bin/env bash
# KALPA: Autonomous Cyber Reasoning System (AI Kavach) Execution Script

set -e

TARGET_DIR="${1:-targets/vulnerable_service}"
OUTPUT_DIR="${2:-evidence_bundles}"

echo "============================================================"
echo " Starting KALPA Autonomous CRS"
echo " Target: $TARGET_DIR"
echo " Output: $OUTPUT_DIR"
echo "============================================================"

python3 run_kalpa.py --target "$TARGET_DIR" --output-dir "$OUTPUT_DIR"
