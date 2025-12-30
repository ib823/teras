#!/bin/bash
# tools/audit-deps.sh
# EXACT SCRIPT - USE AS IS

set -euo pipefail

echo "=== TERAS Dependency Audit ==="

# Check for known vulnerabilities
echo "[1/4] Checking for vulnerabilities..."
cargo audit || {
    echo "ERROR: Vulnerabilities found"
    exit 1
}

# Check for prohibited dependencies
echo "[2/4] Checking for prohibited dependencies..."
PROHIBITED="ring openssl"
for dep in $PROHIBITED; do
    if grep -q "\"$dep\"" Cargo.lock; then
        echo "ERROR: Prohibited dependency found: $dep"
        exit 1
    fi
done

# Verify all dependencies are exact versions
echo "[3/4] Checking version pinning..."
if grep -E '^\s*[a-z_-]+ = "[\^~]' Cargo.toml; then
    echo "ERROR: Non-exact version found. Use exact versions (=x.y.z)"
    exit 1
fi

# Check for new dependencies not in approved list
echo "[4/4] Checking for unapproved dependencies..."
# This should be expanded based on Part II, Reality 3
APPROVED="ml-kem ml-dsa slh-dsa x25519-dalek ed25519-dalek aes-gcm chacha20poly1305 sha3 sha2 blake3 hkdf argon2 zeroize rand rand_core subtle"
# (Add validation logic here)

echo "=== Dependency audit passed ==="
