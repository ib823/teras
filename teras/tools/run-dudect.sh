#!/bin/bash
# tools/run-dudect.sh
# EXACT SCRIPT - USE AS IS

set -euo pipefail

echo "=== TERAS Timing Verification (dudect) ==="

THRESHOLD=4.5
MEASUREMENTS=1000000

echo "Running constant-time verification..."
echo "Threshold: t < $THRESHOLD"
echo "Measurements: $MEASUREMENTS"

# Run dudect tests
cargo test --release ct_timing_ -- --ignored --nocapture 2>&1 | tee /tmp/dudect_output.txt

# Check for failures
if grep -q "FAILED" /tmp/dudect_output.txt; then
    echo "ERROR: Timing leaks detected!"
    exit 1
fi

if grep -q "t-value.*[5-9]\." /tmp/dudect_output.txt; then
    echo "ERROR: t-value exceeds threshold!"
    exit 1
fi

echo "=== Timing verification passed ==="
