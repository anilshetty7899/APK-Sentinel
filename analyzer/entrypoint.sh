#!/bin/bash
# APK Sentinel Analyzer Entrypoint
# This script orchestrates APKTool, JADX, and Python analysis scripts.
# It receives the analysis workspace path as an argument.
#
# SECURITY: This container never executes the APK. APKTool and JADX
# only decode/decompile it as input data.

set -euo pipefail

echo "[Sentinel Analyzer] Starting analysis..."

INPUT_DIR="/analysis/input"
OUTPUT_DIR="/analysis/output"
APK_FILE="${INPUT_DIR}/application.apk"

# Validate APK exists
if [ ! -f "${APK_FILE}" ]; then
    echo "[ERROR] APK file not found at ${APK_FILE}"
    exit 1
fi

# Create output directories
mkdir -p "${OUTPUT_DIR}/apktool" \
         "${OUTPUT_DIR}/jadx" \
         "${OUTPUT_DIR}/findings" \
         "${OUTPUT_DIR}/logs" \
         /tmp/apktool-framework

echo "[Sentinel Analyzer] Running APKTool..."
apktool d "${APK_FILE}" -o "${OUTPUT_DIR}/apktool" -f --no-src \
    --frame-path /tmp/apktool-framework 2>&1 | tee "${OUTPUT_DIR}/logs/apktool.log" || {
    echo "[WARNING] APKTool decoding failed or partially failed"
}

echo "[Sentinel Analyzer] Running JADX..."
jadx "${APK_FILE}" -d "${OUTPUT_DIR}/jadx" --no-res --show-bad-code 2>&1 | tee "${OUTPUT_DIR}/logs/jadx.log" || {
    echo "[WARNING] JADX decompilation failed or partially failed"
}

echo "[Sentinel Analyzer] Running analysis scripts..."
python3 /opt/analyzer/scripts/run_analysis.py \
    --input "${INPUT_DIR}" \
    --output "${OUTPUT_DIR}" \
    2>&1 | tee "${OUTPUT_DIR}/logs/analysis.log"

echo "[Sentinel Analyzer] Analysis complete."
