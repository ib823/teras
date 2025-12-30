#!/bin/bash
# tools/verify-build.sh
# EXACT SCRIPT - USE AS IS

set -euo pipefail

echo "=== TERAS Build Verification ==="

# Step 1: Clean
echo "[1/7] Cleaning..."
cargo clean

# Step 2: Check formatting
echo "[2/7] Checking format..."
cargo fmt --check || {
    echo "ERROR: Code not formatted. Run 'cargo fmt'"
    exit 1
}

# Step 3: Clippy
echo "[3/7] Running clippy..."
cargo clippy -- -D warnings || {
    echo "ERROR: Clippy warnings found"
    exit 1
}

# Step 4: Tests
echo "[4/7] Running tests..."
cargo test || {
    echo "ERROR: Tests failed"
    exit 1
}

# Step 5: Release tests
echo "[5/7] Running release tests..."
cargo test --release || {
    echo "ERROR: Release tests failed"
    exit 1
}

# Step 6: Check unsafe count
echo "[6/7] Checking unsafe blocks..."
UNSAFE_COUNT=$(grep -r "unsafe" --include="*.rs" crates/ | grep -v "// SAFETY:" | wc -l)
MAX_UNSAFE=15
if [ "$UNSAFE_COUNT" -gt "$MAX_UNSAFE" ]; then
    echo "ERROR: Too many unsafe blocks without SAFETY comment: $UNSAFE_COUNT (max: $MAX_UNSAFE)"
    exit 1
fi

# Step 7: Check for debug prints in crypto code
echo "[7/7] Checking for debug prints..."
DEBUG_PRINTS=$(grep -rE "(println!|dbg!|eprintln!)" --include="*.rs" crates/teras-kunci crates/teras-lindung 2>/dev/null | wc -l)
if [ "$DEBUG_PRINTS" -gt 0 ]; then
    echo "ERROR: Debug prints found in crypto code"
    grep -rE "(println!|dbg!|eprintln!)" --include="*.rs" crates/teras-kunci crates/teras-lindung
    exit 1
fi

echo "=== All checks passed ==="
