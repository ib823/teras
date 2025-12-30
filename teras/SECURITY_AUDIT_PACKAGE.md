# TERAS Security Audit Package

**For External Security Auditors**

Version: 0.1.0
Date: 2025-12-30

---

## 1. Overview

TERAS (Trusted Encryption, Resilient Authentication System) is a post-quantum secure cryptographic platform. This document provides auditors with critical security information.

---

## 2. Security-Critical Code Locations

### 2.1 Cryptographic Primitives (`teras-kunci`)

| File | Security Function | Priority |
|------|-------------------|----------|
| `src/kem/kyber768.rs` | Post-quantum key encapsulation | HIGH |
| `src/kem/x25519.rs` | Classical key agreement | HIGH |
| `src/kem/hybrid.rs` | Hybrid KEM (both must succeed) | CRITICAL |
| `src/sign/mldsa.rs` | Dilithium3 signatures | HIGH |
| `src/sign/ed25519_sign.rs` | Ed25519 signatures | HIGH |
| `src/sign/hybrid.rs` | Hybrid signatures (both required) | CRITICAL |
| `src/ct.rs` | Constant-time operations | CRITICAL |

### 2.2 Memory Protection (`teras-lindung`)

| File | Security Function | Priority |
|------|-------------------|----------|
| `src/secret.rs` | Secret<T> wrapper with zeroization | CRITICAL |
| `src/zeroize_util.rs` | Memory zeroization utilities | HIGH |

### 2.3 Biometric Security (`teras-benteng`)

| File | Security Function | Priority |
|------|-------------------|----------|
| `src/types.rs` | BiometricProof (hash-only) | CRITICAL |
| `src/template.rs` | Constant-time hash comparison | CRITICAL |
| `src/liveness.rs` | Liveness detection threshold | HIGH |
| `src/device.rs` | Device binding verification | HIGH |

### 2.4 Audit System (`teras-jejak`)

| File | Security Function | Priority |
|------|-------------------|----------|
| `src/chain.rs` | Hash-chained audit log | HIGH |
| `src/verification.rs` | Chain integrity verification | HIGH |

---

## 3. Security Invariants to Verify

### 3.1 LAW 1: Biometric Data Never Leaves Device

**Check**: `BiometricProof` contains ONLY 32-byte hash

```
Location: teras-benteng/src/types.rs

pub struct BiometricProof {
    pub biometric_type: BiometricType,
    pub template_hash: [u8; 32],  // <-- MUST be hash only
    ...
}
```

**Verify**:
- No raw biometric fields exist
- Hash is SHA3-256 (32 bytes)
- Template reconstruction is impossible

### 3.2 LAW 3: Constant-Time Operations

**Check**: All secret comparisons use `ct_eq`

```
Location: teras-kunci/src/ct.rs

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Uses subtle::ConstantTimeEq
}
```

**Verify**:
- No early-exit on comparison failure
- Uses `subtle` crate primitives
- Template hash comparison in `teras-benteng/src/template.rs`

### 3.3 LAW 4: Secret Zeroization

**Check**: `Secret<T>` zeroizes on drop

```
Location: teras-lindung/src/secret.rs

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}
```

**Verify**:
- All key material wrapped in `Secret<T>`
- `Zeroize` trait implemented correctly
- No secret data escapes wrapper

### 3.4 LAW 5: Hybrid Cryptography

**Check**: BOTH algorithms must succeed

```
Location: teras-kunci/src/sign/hybrid.rs

pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> TerasResult<()> {
    self.dilithium_vk.verify(message, &signature.dilithium_sig)?;  // Must pass
    self.ed25519_vk.verify(message, &signature.ed25519_sig)?;      // Must pass
    Ok(())
}
```

**Verify**:
- No bypass for either algorithm
- Both components required
- Failure in either = total failure

### 3.5 LAW 6: Liveness Detection

**Check**: Minimum 70% confidence required

```
Location: teras-benteng/src/liveness.rs

pub const MIN_LIVENESS_CONFIDENCE: u8 = 70;

if proof.confidence < self.min_confidence {
    result.is_valid = false;
}
```

**Verify**:
- Threshold is enforced
- No bypass possible
- Low confidence = enrollment rejected

---

## 4. Attack Surface Analysis

### 4.1 Timing Attacks

**Mitigations**:
- `ct_eq()` for all secret comparisons
- `subtle` crate for constant-time operations
- `TemplateHash::matches()` uses constant-time

**Files to audit**:
- `teras-kunci/src/ct.rs`
- `teras-benteng/src/template.rs`

### 4.2 Memory Disclosure

**Mitigations**:
- `Secret<T>` wrapper
- Automatic zeroization on drop
- No raw secrets in logs

**Files to audit**:
- `teras-lindung/src/secret.rs`
- All files using `Secret<T>`

### 4.3 Cryptographic Downgrade

**Mitigations**:
- Hybrid mode mandatory (DECISION 4)
- Both algorithms must verify
- No fallback to single algorithm

**Files to audit**:
- `teras-kunci/src/kem/hybrid.rs`
- `teras-kunci/src/sign/hybrid.rs`

### 4.4 Biometric Replay

**Mitigations**:
- Liveness detection required
- Device binding
- Challenge-response proof

**Files to audit**:
- `teras-benteng/src/liveness.rs`
- `teras-benteng/src/device.rs`

### 4.5 Audit Log Tampering

**Mitigations**:
- Hash-chained entries
- Previous hash included in each entry
- Chain verification function

**Files to audit**:
- `teras-jejak/src/chain.rs`
- `teras-jejak/src/verification.rs`

---

## 5. Dependency Security

All dependencies pinned to exact versions:

```toml
# Post-Quantum (NIST approved algorithms)
pqcrypto-kyber = "=0.8.1"
pqcrypto-dilithium = "=0.5.0"

# Classical (vetted implementations)
x25519-dalek = "=2.0.1"
ed25519-dalek = "=2.1.1"
aes-gcm = "=0.10.3"

# Security utilities
zeroize = "=1.7.0"
subtle = "=2.5.0"
```

**Verify**:
- All deps from trusted sources (crates.io)
- No unmaintained dependencies
- Version pinning prevents supply chain attacks

---

## 6. Test Coverage

### Unit Tests

| Crate | Tests | Coverage |
|-------|-------|----------|
| teras-lindung | 21 | Memory protection |
| teras-kunci | 59 | Crypto operations |
| teras-jejak | 38 | Audit logging |
| teras-suap | 51 | Threat feeds |
| teras-integrasi | 33 | Integration |
| teras-sandi | 50 | Digital signatures |
| teras-benteng | 88 | eKYC |

### Security-Specific Tests

```
test_law1_no_raw_biometric_fields
test_law3_constant_time_comparison
test_law4_secret_zeroization
test_law5_hybrid_signature_uses_both_algorithms
test_law6_liveness_minimum_confidence
test_law7_device_binding_verification
test_law8_audit_log_hash_chained
```

---

## 7. Known Limitations

1. **Placeholder Device Signature**: `DeviceBindingVerifier::verify_signature()` accepts 64-byte signatures without cryptographic verification (TODO: implement Ed25519 verification)

2. **In-Memory Storage**: Default storage implementations are in-memory; production requires persistent storage

3. **No HSM Integration**: Private keys stored in software; production should use HSM

4. **Timestamp Authority**: Uses local timestamp; production should use external TSA

---

## 8. Audit Checklist

- [ ] Verify `ct_eq` implementation is constant-time
- [ ] Verify `Secret<T>` zeroizes all bytes on drop
- [ ] Verify hybrid crypto requires BOTH algorithms
- [ ] Verify `BiometricProof` contains no raw data
- [ ] Verify liveness threshold cannot be bypassed
- [ ] Verify audit chain is tamper-evident
- [ ] Verify no secret data in error messages
- [ ] Verify all dependencies are trusted
- [ ] Fuzz test cryptographic operations
- [ ] Test timing characteristics

---

## 9. Contact

For questions about this audit package, contact the development team.

---

*Document generated: 2025-12-30*
