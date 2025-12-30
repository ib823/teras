#!/bin/bash
# tools/verify-audit-chain.sh
# EXACT SCRIPT - USE AS IS

set -euo pipefail

echo "=== TERAS Audit Chain Verification ==="

# Run audit chain tests
echo "[1/2] Running audit chain tests..."
cargo test --release audit_chain_ || {
    echo "ERROR: Audit chain tests failed"
    exit 1
}

# Verify chain integrity
echo "[2/2] Verifying chain integrity..."
cargo run --release --bin verify-chain -- /var/log/teras/audit.log || {
    echo "ERROR: Audit chain integrity verification failed"
    exit 1
}

echo "=== Audit chain verification passed ==="
