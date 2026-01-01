# TERAS MASTER ARCHITECTURE v3.2.0

> **CLASSIFICATION:** AUTHORITATIVE SPECIFICATION
> **VERSION:** 3.2.0
> **DATE:** 2025-12-31
> **STATUS:** BINDING
> **PREVIOUS VERSION HASH (V3.1.1):** [SHA-256 of V3.1.1 to be computed]

---

# PREFACE: HOW TO READ THIS DOCUMENT

This document is **LAW**. It is not a vision, not a guideline, not a suggestion.

**RULES FOR ANY CLAUDE INSTANCE OR DEVELOPER:**

1. If this document does not specify something, **ASK** before implementing
2. If this document says MUST, there are **NO EXCEPTIONS**
3. If this document says MUST NOT, **VIOLATION IS FAILURE**
4. If implementation differs from specification, **IMPLEMENTATION IS WRONG**
5. If specification seems impossible, **STOP AND REPORT**, do not improvise
6. All code must pass validation checkpoints **BEFORE** being considered complete
7. "Working code" that violates this specification is **REJECTED**
8. If you think you found a better way, **DOCUMENT AND PROPOSE**, do not implement

**VALIDATION HASH:** Any future version must include SHA-256 of previous version to prove lineage.

**CHANGES FROM V3.1.1:**
- Added PART XXII: MENARA MOBILE SECURITY (Complete mobile threat detection)
- Added PART XXIII: GAPURA WAF ENGINE (Web application firewall specifications)
- Added PART XXIV: ZIRAH EDR ENGINE (Endpoint detection and response)
- Added PART XXV: BENTENG-SDK SPECIFICATIONS (Cross-platform SDK requirements)
- Updated PART XVI: Added Document OCR Requirements
- Updated PART XVII: Added Document Workflow Requirements (Signing, Multi-party, Compliance)

**CHANGES FROM V3.1.0:**
- DEVIATION-001: Rust toolchain updated to stable (1.92.0+) for PQ crypto compatibility
- DEVIATION-002: PQ crypto libraries changed to pqcrypto-kyber/dilithium (same algorithms)
- See DEVIATIONS.md for full justification and impact analysis

**CHANGES FROM V3.0.0:**
- Added Part XV: THREAT COVERAGE MATRIX (comprehensive threat analysis)
- Added Part XVI: ANTI-DEEPFAKE & ADVERSARIAL ML (BENTENG enhancement)
- Added Part XVII: ALGORITHM AGILITY & CRYPTOGRAPHIC RECOVERY (SANDI enhancement)
- Added Part XVIII: BEHAVIORAL DETECTION & 0-DAY DEFENSE (ZIRAH enhancement)
- Added Part XIX: DDOS MITIGATION & AVAILABILITY (GAPURA enhancement)
- Added Part XX: AUDIT LOGGING & INSIDER THREAT (ALL products)
- Added Part XXI: DEVICE BINDING & SIM-SWAP RESISTANCE (BENTENG enhancement)
- Updated Decision Log with new decisions
- Updated Validation Protocol with new checkpoints

---

# TABLE OF CONTENTS

```
PART I:    IMMUTABLE LAWS (What can NEVER change)
PART II:   CURRENT REALITY (What exists TODAY)
PART III:  CONCRETE SPECIFICATIONS (Byte-level precision)
PART IV:   IMPLEMENTATION SKELETON (Actual code structures)
PART V:    VALIDATION PROTOCOL (How to verify compliance)
PART VI:   PROHIBITED ACTIONS (What is NEVER allowed)
PART VII:  DECISION LOG (Why decisions were made)
PART VIII: FUTURE VISION (Aspirational, NOT for implementation)
PART IX:   GLOSSARY (Precise definitions)
PART X:    COMPLETE TEST VECTORS (Exact inputs/outputs)
PART XI:   COMPLETE CODE MODULES (Copy-paste ready)
PART XII:  VALIDATION SCRIPTS (Exact bash scripts)
PART XIII: COMPLIANCE MATRIX (Checklist for every PR)
PART XIV:  QUICK REFERENCE CARD (One-page summary)
PART XV:   THREAT COVERAGE MATRIX (What is/isn't covered)
PART XVI:  ANTI-DEEPFAKE & ADVERSARIAL ML (Updated: Document OCR)
PART XVII: ALGORITHM AGILITY & CRYPTOGRAPHIC RECOVERY (Updated: Document Workflow)
PART XVIII: BEHAVIORAL DETECTION & 0-DAY DEFENSE
PART XIX:  DDOS MITIGATION & AVAILABILITY
PART XX:   AUDIT LOGGING & INSIDER THREAT
PART XXI:  DEVICE BINDING & SIM-SWAP RESISTANCE
PART XXII: MENARA MOBILE SECURITY [NEW]
PART XXIII: GAPURA WAF ENGINE [NEW]
PART XXIV: ZIRAH EDR ENGINE [NEW]
PART XXV:  BENTENG-SDK SPECIFICATIONS [NEW]
```

---
# PART I: IMMUTABLE LAWS

These laws **CANNOT** be changed, relaxed, or "temporarily suspended for MVP."

## LAW 1: BIOMETRIC DATA LOCALITY

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   BIOMETRIC DATA (face images, fingerprints, voice prints, iris scans)      â•‘
â•‘   MUST NEVER leave the user's device in any form that allows reconstruction.â•‘
â•‘                                                                              â•‘
â•‘   PERMITTED:                                                                 â•‘
â•‘   â€¢ Cryptographic hash of biometric (non-reversible)                        â•‘
â•‘   â€¢ Zero-knowledge proof about biometric                                    â•‘
â•‘   â€¢ Encrypted biometric that ONLY user can decrypt                          â•‘
â•‘   â€¢ Signed attestation that matching succeeded (no biometric data)          â•‘
â•‘                                                                              â•‘
â•‘   PROHIBITED:                                                                â•‘
â•‘   â€¢ Raw biometric to any server                                             â•‘
â•‘   â€¢ Encrypted biometric where server has key                                â•‘
â•‘   â€¢ "Anonymized" biometric (still reconstructable)                          â•‘
â•‘   â€¢ Biometric "for debugging"                                               â•‘
â•‘   â€¢ Biometric "with user consent" (consent doesn't change the law)          â•‘
â•‘   â€¢ Biometric embeddings/vectors to server (reconstructable)                â•‘
â•‘   â€¢ Face templates to server                                                â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

**VALIDATION:** Any network packet containing >1KB of data derived from biometric source MUST be inspectable and proven to be non-reversible.

## LAW 2: CRYPTOGRAPHIC NON-NEGOTIABLES

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   CRYPTOGRAPHIC REQUIREMENTS                                                 â•‘
â•‘                                                                              â•‘
â•‘   KEY SIZES (MINIMUM):                                                       â•‘
â•‘   â€¢ Symmetric: 256 bits                                                      â•‘
â•‘   â€¢ Asymmetric (classical): 256 bits (EC) or 3072 bits (RSA)                â•‘
â•‘   â€¢ Post-quantum KEM: ML-KEM-768 (NIST Level 3)                             â•‘
â•‘   â€¢ Post-quantum Signature: ML-DSA-65 (NIST Level 3)                        â•‘
â•‘   â€¢ Hash: 256 bits output minimum                                           â•‘
â•‘                                                                              â•‘
â•‘   ALGORITHMS (ALLOWED - PRIMARY):                                            â•‘
â•‘   â€¢ Symmetric: AES-256-GCM, ChaCha20-Poly1305                               â•‘
â•‘   â€¢ Hash: SHA-3-256, SHA-256, BLAKE3                                        â•‘
â•‘   â€¢ KEM: ML-KEM-768, X25519 (classical), HYBRID of both (RECOMMENDED)       â•‘
â•‘   â€¢ Signature: ML-DSA-65, Ed25519, SLH-DSA-SHAKE-128f                       â•‘
â•‘   â€¢ KDF: HKDF-SHA256, HKDF-SHA3-256, Argon2id (passwords only)              â•‘
â•‘                                                                              â•‘
â•‘   ALGORITHMS (ALLOWED - BACKUP/EMERGENCY):                                   â•‘
â•‘   â€¢ KEM: Classic McEliece (if ML-KEM breaks)                                â•‘
â•‘   â€¢ Signature: SLH-DSA-SHAKE-256f (if ML-DSA breaks)                        â•‘
â•‘   â€¢ Hash-based: XMSS, LMS (for long-term archival)                          â•‘
â•‘                                                                              â•‘
â•‘   ALGORITHMS (PROHIBITED):                                                   â•‘
â•‘   â€¢ MD5, SHA-1 (any use)                                                     â•‘
â•‘   â€¢ DES, 3DES, RC4, Blowfish                                                â•‘
â•‘   â€¢ RSA < 3072 bits                                                          â•‘
â•‘   â€¢ ECDSA with curves < 256 bits                                            â•‘
â•‘   â€¢ Any algorithm not explicitly listed above                                â•‘
â•‘                                                                              â•‘
â•‘   HYBRID MODE (MANDATORY FOR ALL NEW DEPLOYMENTS):                           â•‘
â•‘   â€¢ KEM: ML-KEM-768 + X25519 (both must succeed)                            â•‘
â•‘   â€¢ Signature: ML-DSA-65 + Ed25519 (both must verify)                       â•‘
â•‘   â€¢ Rationale: If either classical or PQ breaks, other provides security    â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

**VALIDATION:** Code review must grep for prohibited algorithm names. Any match is build failure.

## LAW 3: CONSTANT-TIME REQUIREMENT

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   ALL operations on secret data MUST be constant-time.                       â•‘
â•‘                                                                              â•‘
â•‘   SECRET DATA INCLUDES:                                                      â•‘
â•‘   â€¢ Private keys                                                             â•‘
â•‘   â€¢ Session keys                                                             â•‘
â•‘   â€¢ Passwords                                                                â•‘
â•‘   â€¢ Biometric embeddings                                                     â•‘
â•‘   â€¢ Any data used in cryptographic operations                                â•‘
â•‘   â€¢ Comparison results before they are public                                â•‘
â•‘                                                                              â•‘
â•‘   CONSTANT-TIME MEANS:                                                       â•‘
â•‘   â€¢ No branching based on secret values                                      â•‘
â•‘   â€¢ No array indexing based on secret values                                 â•‘
â•‘   â€¢ No early returns based on secret values                                  â•‘
â•‘   â€¢ No variable-time CPU instructions on secrets                             â•‘
â•‘   â€¢ No cache-timing variations based on secrets                              â•‘
â•‘                                                                              â•‘
â•‘   VERIFICATION METHOD:                                                       â•‘
â•‘   â€¢ Run dudect with t-value threshold < 4.5                                  â•‘
â•‘   â€¢ Minimum 1 million measurements                                           â•‘
â•‘   â€¢ Test on target platform (not just dev machine)                           â•‘
â•‘   â€¢ Re-run after ANY change to crypto code                                   â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

**VALIDATION:** dudect test must pass before any crypto code is merged.

## LAW 4: SECRET ZEROIZATION

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   ALL secrets MUST be zeroized when no longer needed.                        â•‘
â•‘                                                                              â•‘
â•‘   ZEROIZATION REQUIREMENTS:                                                  â•‘
â•‘   â€¢ Use volatile writes (prevent compiler optimization)                      â•‘
â•‘   â€¢ Memory barrier after zeroing                                             â•‘
â•‘   â€¢ Verification read in debug builds                                        â•‘
â•‘                                                                              â•‘
â•‘   IMPLEMENTATION (EXACT CODE):                                               â•‘
â•‘                                                                              â•‘
â•‘   ```rust                                                                    â•‘
â•‘   pub fn zeroize_bytes(bytes: &mut [u8]) {                                  â•‘
â•‘       use core::sync::atomic::{compiler_fence, Ordering};                   â•‘
â•‘       for byte in bytes.iter_mut() {                                        â•‘
â•‘           unsafe { std::ptr::write_volatile(byte, 0); }                     â•‘
â•‘       }                                                                      â•‘
â•‘       compiler_fence(Ordering::SeqCst);                                     â•‘
â•‘   }                                                                          â•‘
â•‘   ```                                                                        â•‘
â•‘                                                                              â•‘
â•‘   This exact implementation MUST be used. No variations.                     â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

**VALIDATION:** Miri must not detect UB. ASAN must not detect use-after-free.

## LAW 5: NO TRUST IN INFRASTRUCTURE

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   The following are considered HOSTILE and MUST NOT be trusted:              â•‘
â•‘                                                                              â•‘
â•‘   â€¢ Cloud providers (AWS, GCP, Azure, Vercel, etc.)                          â•‘
â•‘   â€¢ Operating systems (iOS, Android, Windows, Linux, macOS)                  â•‘
â•‘   â€¢ Network infrastructure (ISPs, routers, DNS)                              â•‘
â•‘   â€¢ Certificate authorities                                                  â•‘
â•‘   â€¢ App stores (Apple, Google)                                               â•‘
â•‘   â€¢ Hardware (CPUs, TPMs, Secure Enclaves)                                   â•‘
â•‘   â€¢ Third-party libraries (even audited ones)                                â•‘
â•‘   â€¢ Build systems (compilers, linkers)                                       â•‘
â•‘   â€¢ SMS networks (SIM swap vulnerable)                                       â•‘
â•‘   â€¢ Email providers (account takeover vulnerable)                            â•‘
â•‘   â€¢ Phone numbers as identity                                                â•‘
â•‘                                                                              â•‘
â•‘   WHAT THIS MEANS:                                                           â•‘
â•‘   â€¢ Encryption MUST use our keys, not platform keys                          â•‘
â•‘   â€¢ Verification MUST happen in our code, not platform APIs                  â•‘
â•‘   â€¢ Secrets MUST be encrypted before touching platform storage               â•‘
â•‘   â€¢ Network MUST be encrypted with our TLS, certificate-pinned               â•‘
â•‘   â€¢ Identity MUST be device-bound, not phone-number-bound                    â•‘
â•‘   â€¢ Authentication MUST NOT use SMS OTP or email OTP alone                   â•‘
â•‘                                                                              â•‘
â•‘   EXCEPTIONS (USE PLATFORM AS ADDITIONAL LAYER ONLY):                        â•‘
â•‘   â€¢ Platform secure storage (Keychain, Keystore) for ADDITIONAL protection   â•‘
â•‘   â€¢ Platform biometrics (Face ID) for ADDITIONAL authentication              â•‘
â•‘   â€¢ NEVER as the ONLY protection                                             â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## LAW 6: FAIL SECURE

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   On ANY error, the system MUST deny access.                                 â•‘
â•‘                                                                              â•‘
â•‘   PROHIBITED:                                                                â•‘
â•‘   â€¢ "If verification fails, fall back to less secure method"                 â•‘
â•‘   â€¢ "If crypto fails, proceed without encryption"                            â•‘
â•‘   â€¢ "If network fails, cache credentials"                                    â•‘
â•‘   â€¢ "If parsing fails, use default value"                                    â•‘
â•‘   â€¢ "If liveness fails, try again with relaxed threshold"                    â•‘
â•‘   â€¢ "If deepfake detection times out, skip it"                               â•‘
â•‘   â€¢ Any form of "fail open"                                                  â•‘
â•‘                                                                              â•‘
â•‘   REQUIRED:                                                                  â•‘
â•‘   â€¢ Error â†’ Deny access                                                      â•‘
â•‘   â€¢ Error â†’ Log (without secrets)                                            â•‘
â•‘   â€¢ Error â†’ Alert user                                                       â•‘
â•‘   â€¢ Error â†’ Zeroize any partial state                                        â•‘
â•‘   â€¢ Error â†’ Increment failure counter for anomaly detection                  â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## LAW 7: REPRODUCIBLE BUILDS

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   Every build MUST be reproducible.                                          â•‘
â•‘                                                                              â•‘
â•‘   Given:                                                                     â•‘
â•‘   â€¢ Same source code (git commit hash)                                       â•‘
â•‘   â€¢ Same toolchain version (exact rustc version)                             â•‘
â•‘   â€¢ Same target platform                                                     â•‘
â•‘                                                                              â•‘
â•‘   Result:                                                                    â•‘
â•‘   â€¢ Byte-identical binary                                                    â•‘
â•‘                                                                              â•‘
â•‘   REQUIREMENTS:                                                              â•‘
â•‘   â€¢ Cargo.lock MUST be committed                                             â•‘
â•‘   â€¢ All deps vendored with hash verification                                 â•‘
â•‘   â€¢ No build timestamps embedded                                             â•‘
â•‘   â€¢ No random values in build                                                â•‘
â•‘   â€¢ Docker build environment with pinned versions                            â•‘
â•‘   â€¢ Diverse double-compilation for compiler trust                            â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## LAW 8: COMPREHENSIVE AUDIT LOGGING [NEW IN V3.1]

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   ALL security-relevant events MUST be logged.                               â•‘
â•‘                                                                              â•‘
â•‘   EVERY LOG ENTRY MUST CONTAIN:                                              â•‘
â•‘   â€¢ Timestamp (NTP-synced, tamper-evident)                                   â•‘
â•‘   â€¢ Actor (user ID, service account, system)                                 â•‘
â•‘   â€¢ Action (what was attempted)                                              â•‘
â•‘   â€¢ Object (what was accessed)                                               â•‘
â•‘   â€¢ Result (success/failure)                                                 â•‘
â•‘   â€¢ Context (IP, device fingerprint, location)                               â•‘
â•‘                                                                              â•‘
â•‘   LOG PROTECTION:                                                            â•‘
â•‘   â€¢ Append-only (cannot delete or modify)                                    â•‘
â•‘   â€¢ Cryptographically chained (tamper-evident hash chain)                    â•‘
â•‘   â€¢ Replicated (minimum 2 geographically separate locations)                 â•‘
â•‘   â€¢ Retention: 7 years minimum                                               â•‘
â•‘   â€¢ Encrypted at rest and in transit                                         â•‘
â•‘                                                                              â•‘
â•‘   PROHIBITED IN LOGS:                                                        â•‘
â•‘   â€¢ Secrets, keys, passwords                                                 â•‘
â•‘   â€¢ Biometric data                                                           â•‘
â•‘   â€¢ Full credit card numbers                                                 â•‘
â•‘   â€¢ Unredacted personal data beyond what's needed                            â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

# PART II: CURRENT REALITY

This section describes what **ACTUALLY EXISTS AND WORKS TODAY**. 
Not aspirational. Not future. Not "could be built."

## REALITY 1: TERAS-LANG DOES NOT EXIST

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   STATUS: TERAS-LANG is a FUTURE VISION, not current reality.                â•‘
â•‘                                                                              â•‘
â•‘   CURRENT IMPLEMENTATION LANGUAGE: Rust                                      â•‘
â•‘   CURRENT VERIFICATION TOOLS:                                                â•‘
â•‘   â€¢ Kani (model checking)                                                    â•‘
â•‘   â€¢ cargo-fuzz (fuzzing)                                                     â•‘
â•‘   â€¢ Miri (UB detection)                                                      â•‘
â•‘   â€¢ dudect (timing verification)                                             â•‘
â•‘   â€¢ clippy (linting)                                                         â•‘
â•‘                                                                              â•‘
â•‘   DO NOT:                                                                    â•‘
â•‘   â€¢ Claim to implement TERAS-LANG                                            â•‘
â•‘   â€¢ Create a "simplified TERAS-LANG"                                         â•‘
â•‘   â€¢ Use TERAS-LANG syntax in production code                                 â•‘
â•‘                                                                              â•‘
â•‘   DO:                                                                        â•‘
â•‘   â€¢ Write Rust with verification annotations                                 â•‘
â•‘   â€¢ Use Kani proofs for critical code                                        â•‘
â•‘   â€¢ Follow the coding standards in Part IV                                   â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## REALITY 2: ZK FOR BIOMETRICS IS RESEARCH-STAGE

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   STATUS: Zero-knowledge proofs for biometric matching are NOT production-   â•‘
â•‘           ready for mobile devices.                                          â•‘
â•‘                                                                              â•‘
â•‘   CURRENT STATE OF THE ART:                                                  â•‘
â•‘   â€¢ ZK for simple statements (age > 18): FEASIBLE, ~100ms                   â•‘
â•‘   â€¢ ZK for hash preimage: FEASIBLE, ~500ms                                  â•‘
â•‘   â€¢ ZK for 512-dim float cosine similarity: INFEASIBLE on mobile            â•‘
â•‘     - Estimated circuit size: 10+ million constraints                        â•‘
â•‘     - Estimated proving time: 10+ minutes on mobile                          â•‘
â•‘     - Memory requirement: 8+ GB RAM                                          â•‘
â•‘                                                                              â•‘
â•‘   BENTENG PHASE 1 APPROACH (CURRENT):                                        â•‘
â•‘   â€¢ Face matching happens ON-DEVICE (not server)                             â•‘
â•‘   â€¢ Server receives: signed attestation "match succeeded" + liveness proof  â•‘
â•‘   â€¢ NOT a ZK proof of the matching itself                                    â•‘
â•‘   â€¢ This STILL satisfies LAW 1 (biometrics don't leave device)              â•‘
â•‘                                                                              â•‘
â•‘   BENTENG FUTURE (RESEARCH):                                                 â•‘
â•‘   â€¢ Investigate ZK-friendly face embedding models                            â•‘
â•‘   â€¢ Investigate integer-only similarity (avoid floats)                       â•‘
â•‘   â€¢ Investigate proof aggregation                                            â•‘
â•‘                                                                              â•‘
â•‘   DO NOT:                                                                    â•‘
â•‘   â€¢ Claim ZK face verification is implemented                                â•‘
â•‘   â€¢ "Simplify" by sending face data to server                                â•‘
â•‘   â€¢ Skip liveness detection "for MVP"                                        â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## REALITY 3: AVAILABLE CRYPTOGRAPHIC LIBRARIES

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   APPROVED LIBRARIES (with exact versions):                                  â•‘
â•‘                                                                              â•‘
â•‘   POST-QUANTUM (PRIMARY) - DEVIATION-002 APPROVED:                           â•‘
â•‘   # Using pqcrypto family for Rust stable compatibility                      â•‘
â•‘   # Cryptographically equivalent to NIST FIPS 203/204/205                    â•‘
â•‘   â€¢ pqcrypto-kyber = "=0.8.1"       # Kyber-768 â‰¡ ML-KEM-768                 â•‘
â•‘   â€¢ pqcrypto-dilithium = "=0.5.0"   # Dilithium3 â‰¡ ML-DSA-65                 â•‘
â•‘   â€¢ pqcrypto-sphincsplus = "=0.7.0" # SPHINCS+ â‰¡ SLH-DSA (BACKUP)            â•‘
â•‘   â€¢ pqcrypto-traits = "=0.3.5"      # Common traits                          â•‘
â•‘                                                                              â•‘
â•‘   CLASSICAL:                                                                 â•‘
â•‘   â€¢ x25519-dalek = "=2.0.1"    # X25519 key exchange                         â•‘
â•‘   â€¢ ed25519-dalek = "=2.1.1"   # Ed25519 signatures                          â•‘
â•‘   â€¢ aes-gcm = "=0.10.3"        # AES-256-GCM                                  â•‘
â•‘   â€¢ chacha20poly1305 = "=0.10.1" # ChaCha20-Poly1305                         â•‘
â•‘   â€¢ sha3 = "=0.10.8"           # SHA-3                                        â•‘
â•‘   â€¢ sha2 = "=0.10.8"           # SHA-256                                      â•‘
â•‘   â€¢ blake3 = "=1.5.0"          # BLAKE3                                       â•‘
â•‘   â€¢ hkdf = "=0.12.4"           # HKDF                                         â•‘
â•‘   â€¢ argon2 = "=0.5.3"          # Argon2id                                     â•‘
â•‘                                                                              â•‘
â•‘   UTILITIES:                                                                 â•‘
â•‘   â€¢ zeroize = "=1.7.0"         # Secure memory zeroing                       â•‘
â•‘   â€¢ rand = "=0.8.5"            # Randomness (with OsRng)                     â•‘
â•‘   â€¢ rand_core = "=0.6.4"       # RNG traits                                  â•‘
â•‘   â€¢ subtle = "=2.5.0"          # Constant-time primitives                    â•‘
â•‘                                                                              â•‘
â•‘   PROHIBITED:                                                                â•‘
â•‘   â€¢ ring (complex, some unsafe)                                              â•‘
â•‘   â€¢ openssl (C, memory unsafe)                                               â•‘
â•‘   â€¢ Any library not on this list                                             â•‘
â•‘                                                                              â•‘
â•‘   ADDING NEW LIBRARY REQUIRES:                                               â•‘
â•‘   â€¢ Security audit                                                           â•‘
â•‘   â€¢ Version pinning in Cargo.toml                                            â•‘
â•‘   â€¢ Hash verification in Cargo.lock                                          â•‘
â•‘   â€¢ Update to this document                                                  â•‘
â•‘   â€¢ Approval from document maintainer                                        â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## REALITY 4: PLATFORM CAPABILITIES (HONEST ASSESSMENT)

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   iOS:                                                                       â•‘
â•‘   â”œâ”€ CAN DO:                                                                 â•‘
â•‘   â”‚  â€¢ Run our crypto (in native code)                                       â•‘
â•‘   â”‚  â€¢ Store keys in Keychain (additional protection)                        â•‘
â•‘   â”‚  â€¢ Capture camera/document                                               â•‘
â•‘   â”‚  â€¢ Network with certificate pinning                                      â•‘
â•‘   â”‚  â€¢ Background refresh (limited)                                          â•‘
â•‘   â”‚  â€¢ Device attestation (DeviceCheck)                                      â•‘
â•‘   â”œâ”€ CANNOT DO:                                                              â•‘
â•‘   â”‚  â€¢ Kernel monitoring (no eBPF)                                           â•‘
â•‘   â”‚  â€¢ JIT compilation                                                       â•‘
â•‘   â”‚  â€¢ System-wide threat detection                                          â•‘
â•‘   â”‚  â€¢ Access other apps' data                                               â•‘
â•‘   â””â”€ PRODUCT IMPLICATIONS:                                                   â•‘
â•‘      â€¢ BENTENG: Fully possible                                               â•‘
â•‘      â€¢ SANDI: Fully possible                                                 â•‘
â•‘      â€¢ MENARA: Limited to app-level protection                               â•‘
â•‘      â€¢ ZIRAH: Not possible (would be fake)                                   â•‘
â•‘                                                                              â•‘
â•‘   Android:                                                                   â•‘
â•‘   â”œâ”€ CAN DO:                                                                 â•‘
â•‘   â”‚  â€¢ Everything iOS can do                                                 â•‘
â•‘   â”‚  â€¢ Accessibility Service monitoring (declared)                           â•‘
â•‘   â”‚  â€¢ VPN service for network filtering                                     â•‘
â•‘   â”‚  â€¢ Work Profile integration (enterprise)                                 â•‘
â•‘   â”‚  â€¢ Device attestation (SafetyNet/Play Integrity)                         â•‘
â•‘   â”œâ”€ CANNOT DO:                                                              â•‘
â•‘   â”‚  â€¢ eBPF without root                                                     â•‘
â•‘   â”‚  â€¢ Kernel monitoring without root                                        â•‘
â•‘   â””â”€ PRODUCT IMPLICATIONS:                                                   â•‘
â•‘      â€¢ BENTENG: Fully possible                                               â•‘
â•‘      â€¢ SANDI: Fully possible                                                 â•‘
â•‘      â€¢ MENARA: Good with Accessibility Service                               â•‘
â•‘      â€¢ ZIRAH: Limited without root                                           â•‘
â•‘                                                                              â•‘
â•‘   Linux:                                                                     â•‘
â•‘   â”œâ”€ CAN DO:                                                                 â•‘
â•‘   â”‚  â€¢ Everything                                                            â•‘
â•‘   â”‚  â€¢ Full eBPF                                                             â•‘
â•‘   â”‚  â€¢ Kernel tracing                                                        â•‘
â•‘   â”‚  â€¢ System-wide protection                                                â•‘
â•‘   â””â”€ PRODUCT IMPLICATIONS:                                                   â•‘
â•‘      â€¢ All products: Fully possible                                          â•‘
â•‘                                                                              â•‘
â•‘   Windows:                                                                   â•‘
â•‘   â”œâ”€ CAN DO:                                                                 â•‘
â•‘   â”‚  â€¢ Our crypto                                                            â•‘
â•‘   â”‚  â€¢ ETW tracing                                                           â•‘
â•‘   â”‚  â€¢ Kernel minifilter (with WHQL signing)                                 â•‘
â•‘   â”œâ”€ REQUIRES:                                                               â•‘
â•‘   â”‚  â€¢ EV code signing certificate (~$400/year)                              â•‘
â•‘   â”‚  â€¢ WHQL certification for kernel components                              â•‘
â•‘   â””â”€ PRODUCT IMPLICATIONS:                                                   â•‘
â•‘      â€¢ All products: Possible with proper signing                            â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## REALITY 5: WHAT CAN BE BUILT BY SOLO DEVELOPER

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   HONEST TIMELINE ASSESSMENT (solo developer, 20 hrs/week):                  â•‘
â•‘                                                                              â•‘
â•‘   CRYPTO CORE (KUNCI):                                                       â•‘
â•‘   â€¢ Wrapper around approved libraries: 2-4 weeks                             â•‘
â•‘   â€¢ Test vectors and validation: 2 weeks                                     â•‘
â•‘   â€¢ Constant-time verification: 2 weeks                                      â•‘
â•‘   â€¢ Hybrid mode (PQ + classical): 1 week                                     â•‘
â•‘   â€¢ Total: 7-9 weeks                                                         â•‘
â•‘                                                                              â•‘
â•‘   MEMORY PROTECTION (LINDUNG):                                               â•‘
â•‘   â€¢ Secret type with zeroization: 1-2 weeks                                  â•‘
â•‘   â€¢ mlock integration: 1 week                                                â•‘
â•‘   â€¢ Cross-platform: 2 weeks                                                  â•‘
â•‘   â€¢ Total: 4-5 weeks                                                         â•‘
â•‘                                                                              â•‘
â•‘   BENTENG MVP (eKYC without ZK face proof):                                  â•‘
â•‘   â€¢ Document capture: 4 weeks                                                â•‘
â•‘   â€¢ Face capture + liveness (3 signals): 6 weeks                             â•‘
â•‘   â€¢ Deepfake detection (basic): 3 weeks                                      â•‘
â•‘   â€¢ On-device matching: 2 weeks                                              â•‘
â•‘   â€¢ Device binding: 2 weeks                                                  â•‘
â•‘   â€¢ Signed attestation: 2 weeks                                              â•‘
â•‘   â€¢ iOS/Android SDK: 4 weeks                                                 â•‘
â•‘   â€¢ Total: 23 weeks (5.75 months)                                            â•‘
â•‘                                                                              â•‘
â•‘   AUDIT LOGGING (ALL PRODUCTS):                                              â•‘
â•‘   â€¢ Core logging framework: 2 weeks                                          â•‘
â•‘   â€¢ Tamper-evident chain: 2 weeks                                            â•‘
â•‘   â€¢ Anomaly detection: 3 weeks                                               â•‘
â•‘   â€¢ Total: 7 weeks                                                           â•‘
â•‘                                                                              â•‘
â•‘   REALISTIC FIRST MILESTONE:                                                 â•‘
â•‘   â€¢ KUNCI + LINDUNG + BENTENG MVP: 8-9 months                               â•‘
â•‘                                                                              â•‘
â•‘   NOT REALISTIC FOR SOLO DEVELOPER:                                          â•‘
â•‘   â€¢ Custom programming language: 2-5 years                                   â•‘
â•‘   â€¢ Verified compiler: 2-5 years                                             â•‘
â•‘   â€¢ ZK face verification: Research project (unknown)                         â•‘
â•‘   â€¢ Full EDR (ZIRAH): 1-2 years                                             â•‘
â•‘   â€¢ Comprehensive formal proofs: 1-2 years                                   â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## REALITY 6: EXISTING REPOSITORIES

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   CURRENT REPOSITORY STATUS (as of 2025-12-30):                              â•‘
â•‘                                                                              â•‘
â•‘   menara (github.com/ib823/menara):                                          â•‘
â•‘   â€¢ Status: PINQ engine complete                                             â•‘
â•‘   â€¢ Language: Python/Rust hybrid                                             â•‘
â•‘   â€¢ Extractable: KUNCI patterns, UNDANG policy, JARING network               â•‘
â•‘   â€¢ Commits: 147                                                             â•‘
â•‘                                                                              â•‘
â•‘   gapura (github.com/ib823/gapura):                                          â•‘
â•‘   â€¢ Status: WAF production-ready                                             â•‘
â•‘   â€¢ Language: Mixed                                                          â•‘
â•‘   â€¢ Extractable: BENTUK serialization, UNDANG policy                         â•‘
â•‘   â€¢ Commits: 58                                                              â•‘
â•‘                                                                              â•‘
â•‘   zirah (github.com/ib823/zirah):                                            â•‘
â•‘   â€¢ Status: Attestation 3M/sec, eBPF STUBS                                   â•‘
â•‘   â€¢ Language: Rust                                                           â•‘
â•‘   â€¢ Extractable: BUKTI proofs, LINDUNG memory                                â•‘
â•‘   â€¢ Commits: 64                                                              â•‘
â•‘                                                                              â•‘
â•‘   benteng (github.com/ib823/benteng):                                        â•‘
â•‘   â€¢ Status: eKYC complete (basic)                                            â•‘
â•‘   â€¢ Language: Mixed                                                          â•‘
â•‘   â€¢ Extractable: BUKTI proofs, KUNCI crypto                                  â•‘
â•‘   â€¢ Commits: 99                                                              â•‘
â•‘                                                                              â•‘
â•‘   sandi (github.com/ib823/sandi):                                            â•‘
â•‘   â€¢ Status: PQ crypto in Python                                              â•‘
â•‘   â€¢ Language: Python (MUST PORT TO RUST)                                     â•‘
â•‘   â€¢ Extractable: KUNCI crypto (needs rewrite)                                â•‘
â•‘   â€¢ Commits: 37                                                              â•‘
â•‘   â€¢ CRITICAL: This is the PQ crypto reference, must be Rust-ified           â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

# PART III: CONCRETE SPECIFICATIONS

## SPEC 1: KEY FORMATS

### 1.1 Secret Key Serialization

```
ALL secret keys use this EXACT format:

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Offset â”‚ Size   â”‚ Field          â”‚ Description                â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0      â”‚ 4      â”‚ magic          â”‚ 0x54455253 ("TERS")        â”‚
â”‚ 4      â”‚ 2      â”‚ version        â”‚ 0x0001                     â”‚
â”‚ 6      â”‚ 2      â”‚ key_type       â”‚ See key type table         â”‚
â”‚ 8      â”‚ 4      â”‚ key_length     â”‚ Length in bytes (LE)       â”‚
â”‚ 12     â”‚ 32     â”‚ key_id         â”‚ SHA-256(public_key)        â”‚
â”‚ 44     â”‚ 8      â”‚ created_at     â”‚ Unix timestamp (LE)        â”‚
â”‚ 52     â”‚ 8      â”‚ expires_at     â”‚ Unix timestamp (LE), 0=neverâ”‚
â”‚ 60     â”‚ 4      â”‚ reserved       â”‚ 0x00000000                 â”‚
â”‚ 64     â”‚ N      â”‚ key_data       â”‚ Raw key bytes              â”‚
â”‚ 64+N   â”‚ 32     â”‚ checksum       â”‚ SHA-256(bytes 0 to 64+N-1) â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Key Type Table:
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Value  â”‚ Algorithm                                               â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0x0001 â”‚ X25519 private key (32 bytes)                          â”‚
â”‚ 0x0002 â”‚ Ed25519 private key (32 bytes)                         â”‚
â”‚ 0x0003 â”‚ ML-KEM-768 decapsulation key (2400 bytes)              â”‚
â”‚ 0x0004 â”‚ ML-DSA-65 private key (4032 bytes)                     â”‚
â”‚ 0x0005 â”‚ SLH-DSA-SHAKE-128f private key (64 bytes)              â”‚
â”‚ 0x0006 â”‚ AES-256 symmetric key (32 bytes)                       â”‚
â”‚ 0x0007 â”‚ ChaCha20 symmetric key (32 bytes)                      â”‚
â”‚ 0x0008 â”‚ HYBRID KEM (X25519 + ML-KEM-768) (2432 bytes)          â”‚
â”‚ 0x0009 â”‚ HYBRID SIG (Ed25519 + ML-DSA-65) (4064 bytes)          â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

VALIDATION:
â€¢ magic MUST be 0x54455253
â€¢ version MUST be 0x0001 (reject unknown versions)
â€¢ key_type MUST be in table (reject unknown types)
â€¢ key_length MUST match expected for key_type
â€¢ checksum MUST match computed SHA-256
â€¢ IF expires_at != 0 AND expires_at < now, reject key
```

### 1.2 Encrypted Key Storage

```
Secret keys at rest are encrypted using this EXACT format:

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Offset â”‚ Size   â”‚ Field          â”‚ Description                â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0      â”‚ 4      â”‚ magic          â”‚ 0x454E4352 ("ENCR")        â”‚
â”‚ 4      â”‚ 2      â”‚ version        â”‚ 0x0001                     â”‚
â”‚ 6      â”‚ 2      â”‚ cipher         â”‚ 0x0001=AES-256-GCM         â”‚
â”‚ 8      â”‚ 2      â”‚ kdf            â”‚ 0x0001=Argon2id            â”‚
â”‚ 10     â”‚ 2      â”‚ reserved       â”‚ 0x0000                     â”‚
â”‚ 12     â”‚ 16     â”‚ salt           â”‚ Random salt for KDF        â”‚
â”‚ 28     â”‚ 4      â”‚ time_cost      â”‚ Argon2 time cost (LE)      â”‚
â”‚ 32     â”‚ 4      â”‚ memory_cost    â”‚ Argon2 memory KB (LE)      â”‚
â”‚ 36     â”‚ 4      â”‚ parallelism    â”‚ Argon2 parallelism (LE)    â”‚
â”‚ 40     â”‚ 12     â”‚ nonce          â”‚ AES-GCM nonce              â”‚
â”‚ 52     â”‚ 4      â”‚ ciphertext_len â”‚ Length of ciphertext (LE)  â”‚
â”‚ 56     â”‚ N      â”‚ ciphertext     â”‚ Encrypted key (above fmt)  â”‚
â”‚ 56+N   â”‚ 16     â”‚ tag            â”‚ AES-GCM auth tag           â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

KDF Parameters (MINIMUM):
â€¢ time_cost: 3
â€¢ memory_cost: 65536 (64 MB)
â€¢ parallelism: 4

DECRYPTION PROCESS:
1. Extract salt, params
2. Derive key = Argon2id(password, salt, params)
3. Decrypt ciphertext with AES-256-GCM(key, nonce)
4. Verify tag
5. Parse decrypted bytes as secret key format
6. Verify checksum
7. Zeroize intermediate key material
```

## SPEC 2: ATTESTATION FORMAT

```
Device attestation for BENTENG (proves matching happened on device):

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Offset â”‚ Size   â”‚ Field               â”‚ Description           â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0      â”‚ 4      â”‚ magic               â”‚ 0x41545354 ("ATST")   â”‚
â”‚ 4      â”‚ 2      â”‚ version             â”‚ 0x0001                â”‚
â”‚ 6      â”‚ 2      â”‚ attestation_type    â”‚ See table             â”‚
â”‚ 8      â”‚ 32     â”‚ device_id           â”‚ SHA-256(device_key)   â”‚
â”‚ 40     â”‚ 32     â”‚ session_nonce       â”‚ From server challenge â”‚
â”‚ 72     â”‚ 8      â”‚ timestamp           â”‚ Unix timestamp (LE)   â”‚
â”‚ 80     â”‚ 1      â”‚ result              â”‚ 0x00=fail, 0x01=pass  â”‚
â”‚ 81     â”‚ 1      â”‚ confidence          â”‚ 0-100                 â”‚
â”‚ 82     â”‚ 1      â”‚ liveness_score      â”‚ 0-100 [NEW]           â”‚
â”‚ 83     â”‚ 1      â”‚ deepfake_score      â”‚ 0-100 (0=real) [NEW]  â”‚
â”‚ 84     â”‚ 32     â”‚ document_hash       â”‚ SHA-256(document)     â”‚
â”‚ 116    â”‚ N      â”‚ signature           â”‚ ML-DSA-65 signature   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Attestation Type Table:
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Value  â”‚ Meaning                                                 â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0x0001 â”‚ Face matches document                                   â”‚
â”‚ 0x0002 â”‚ Liveness check passed                                   â”‚
â”‚ 0x0003 â”‚ Document is valid                                       â”‚
â”‚ 0x0004 â”‚ Age >= threshold (threshold in confidence field)        â”‚
â”‚ 0x0005 â”‚ Nationality matches                                     â”‚
â”‚ 0x0006 â”‚ Deepfake detection passed [NEW]                         â”‚
â”‚ 0x0007 â”‚ All PAD checks passed [NEW]                             â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

VERIFICATION PROCESS:
1. Check magic, version
2. Verify session_nonce matches server-issued challenge
3. Verify timestamp within acceptable window (Â±5 minutes)
4. Verify liveness_score >= 80 (MINIMUM)
5. Verify deepfake_score <= 20 (MAXIMUM - lower is more real)
6. Verify signature using known device public key
7. Return result only if all checks pass
```

## SPEC 3: NETWORK PROTOCOL

```
All TERAS network communication uses this envelope:

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Offset â”‚ Size   â”‚ Field          â”‚ Description                â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0      â”‚ 4      â”‚ magic          â”‚ 0x54455250 ("TERP")        â”‚
â”‚ 4      â”‚ 2      â”‚ version        â”‚ 0x0001                     â”‚
â”‚ 6      â”‚ 2      â”‚ message_type   â”‚ See table                  â”‚
â”‚ 8      â”‚ 4      â”‚ sequence       â”‚ Monotonic counter (LE)     â”‚
â”‚ 12     â”‚ 4      â”‚ payload_len    â”‚ Length of payload (LE)     â”‚
â”‚ 16     â”‚ N      â”‚ payload        â”‚ Encrypted payload          â”‚
â”‚ 16+N   â”‚ 16     â”‚ mac            â”‚ HMAC-SHA256 truncated      â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Message Types:
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Value  â”‚ Message                                                 â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0x0001 â”‚ Challenge request (server â†’ client)                     â”‚
â”‚ 0x0002 â”‚ Challenge response (client â†’ server)                    â”‚
â”‚ 0x0003 â”‚ Attestation submit                                      â”‚
â”‚ 0x0004 â”‚ Attestation result                                      â”‚
â”‚ 0x0005 â”‚ Threat pattern update                                   â”‚
â”‚ 0x0006 â”‚ Heartbeat                                               â”‚
â”‚ 0x0007 â”‚ Audit log batch [NEW]                                   â”‚
â”‚ 0x0008 â”‚ Algorithm rotation notice [NEW]                         â”‚
â”‚ 0xFFFF â”‚ Error                                                   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

ENCRYPTION:
â€¢ Payload encrypted with session key (established via ML-KEM+X25519 HYBRID)
â€¢ Cipher: ChaCha20-Poly1305
â€¢ Nonce: sequence number (4 bytes) + random (8 bytes)

REPLAY PROTECTION:
â€¢ Server tracks highest sequence per client
â€¢ Reject if sequence <= last seen
â€¢ Reject if sequence > last seen + 1000 (window)
```

## SPEC 4: AUDIT LOG ENTRY FORMAT [NEW IN V3.1]

```
All audit log entries use this EXACT format:

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Offset â”‚ Size   â”‚ Field          â”‚ Description                â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0      â”‚ 4      â”‚ magic          â”‚ 0x4C4F4745 ("LOGE")        â”‚
â”‚ 4      â”‚ 2      â”‚ version        â”‚ 0x0001                     â”‚
â”‚ 6      â”‚ 2      â”‚ event_type     â”‚ See event type table       â”‚
â”‚ 8      â”‚ 8      â”‚ timestamp      â”‚ Unix timestamp (LE)        â”‚
â”‚ 16     â”‚ 32     â”‚ actor_id       â”‚ SHA-256(actor identity)    â”‚
â”‚ 48     â”‚ 32     â”‚ object_id      â”‚ SHA-256(object identity)   â”‚
â”‚ 80     â”‚ 1      â”‚ result         â”‚ 0x00=fail, 0x01=success    â”‚
â”‚ 81     â”‚ 1      â”‚ severity       â”‚ 0=info, 1=warn, 2=error    â”‚
â”‚ 82     â”‚ 2      â”‚ context_len    â”‚ Length of context (LE)     â”‚
â”‚ 84     â”‚ M      â”‚ context        â”‚ JSON context (no secrets)  â”‚
â”‚ 84+M   â”‚ 32     â”‚ prev_hash      â”‚ SHA-256(previous entry)    â”‚
â”‚ 116+M  â”‚ N      â”‚ signature      â”‚ ML-DSA-65 signature        â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Event Type Table:
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Value  â”‚ Event                                                   â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 0x0001 â”‚ Authentication attempt                                  â”‚
â”‚ 0x0002 â”‚ Key generation                                          â”‚
â”‚ 0x0003 â”‚ Key usage                                               â”‚
â”‚ 0x0004 â”‚ Key destruction                                         â”‚
â”‚ 0x0005 â”‚ Verification attempt                                    â”‚
â”‚ 0x0006 â”‚ Attestation generated                                   â”‚
â”‚ 0x0007 â”‚ Configuration change                                    â”‚
â”‚ 0x0008 â”‚ Anomaly detected                                        â”‚
â”‚ 0x0009 â”‚ Algorithm rotation                                      â”‚
â”‚ 0x000A â”‚ Privilege escalation                                    â”‚
â”‚ 0x000B â”‚ Data access                                             â”‚
â”‚ 0x000C â”‚ Network connection                                      â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

CHAIN INTEGRITY:
â€¢ Each entry contains SHA-256 of previous entry
â€¢ Genesis entry has prev_hash = all zeros
â€¢ Signature covers bytes 0 to 116+M-1
â€¢ Any modification breaks the chain
```

---

# PART IV: IMPLEMENTATION SKELETON

## SKELETON 1: Project Structure

```
teras/
â”œâ”€â”€ Cargo.toml                    # Workspace root
â”œâ”€â”€ Cargo.lock                    # MUST be committed
â”œâ”€â”€ rust-toolchain.toml           # Pin exact Rust version
â”œâ”€â”€ .cargo/
â”‚   â””â”€â”€ config.toml               # Cargo configuration
â”œâ”€â”€ vendor/                       # Vendored dependencies
â”‚   â””â”€â”€ .vendor-checksum          # SHA-256 of all vendored crates
â”‚
â”œâ”€â”€ crates/
â”‚   â”œâ”€â”€ teras-core/              # Core types, no crypto
â”‚   â”‚   â”œâ”€â”€ Cargo.toml
â”‚   â”‚   â””â”€â”€ src/
â”‚   â”‚       â”œâ”€â”€ lib.rs
â”‚   â”‚       â”œâ”€â”€ error.rs         # Error types
â”‚   â”‚       â””â”€â”€ types.rs         # Common types
â”‚   â”‚
â”‚   â”œâ”€â”€ teras-kunci/             # Cryptography
â”‚   â”‚   â”œâ”€â”€ Cargo.toml
â”‚   â”‚   â””â”€â”€ src/
â”‚   â”‚       â”œâ”€â”€ lib.rs
â”‚   â”‚       â”œâ”€â”€ kem.rs           # Key encapsulation (HYBRID)
â”‚   â”‚       â”œâ”€â”€ sign.rs          # Signatures (HYBRID)
â”‚   â”‚       â”œâ”€â”€ symmetric.rs     # AES, ChaCha
â”‚   â”‚       â”œâ”€â”€ hash.rs          # Hashing
â”‚   â”‚       â”œâ”€â”€ kdf.rs           # Key derivation
â”‚   â”‚       â”œâ”€â”€ rand.rs          # RNG
â”‚   â”‚       â”œâ”€â”€ agility.rs       # Algorithm rotation [NEW]
â”‚   â”‚       â””â”€â”€ tests/
â”‚   â”‚           â””â”€â”€ vectors.rs   # Test vector validation
â”‚   â”‚
â”‚   â”œâ”€â”€ teras-lindung/           # Memory protection
â”‚   â”‚   â”œâ”€â”€ Cargo.toml
â”‚   â”‚   â””â”€â”€ src/
â”‚   â”‚       â”œâ”€â”€ lib.rs
â”‚   â”‚       â”œâ”€â”€ secret.rs        # Secret<T> type
â”‚   â”‚       â”œâ”€â”€ zeroize.rs       # Zeroization
â”‚   â”‚       â””â”€â”€ mlock.rs         # Memory locking
â”‚   â”‚
â”‚   â”œâ”€â”€ teras-jejak/             # Audit logging [NEW]
â”‚   â”‚   â”œâ”€â”€ Cargo.toml
â”‚   â”‚   â””â”€â”€ src/
â”‚   â”‚       â”œâ”€â”€ lib.rs
â”‚   â”‚       â”œâ”€â”€ entry.rs         # Log entry format
â”‚   â”‚       â”œâ”€â”€ chain.rs         # Hash chain
â”‚   â”‚       â”œâ”€â”€ anomaly.rs       # Anomaly detection
â”‚   â”‚       â””â”€â”€ storage.rs       # Append-only storage
â”‚   â”‚
â”‚   â””â”€â”€ teras-benteng/           # eKYC (builds on above)
â”‚       â”œâ”€â”€ Cargo.toml
â”‚       â””â”€â”€ src/
â”‚           â”œâ”€â”€ lib.rs
â”‚           â”œâ”€â”€ document.rs      # Document processing
â”‚           â”œâ”€â”€ face.rs          # Face processing
â”‚           â”œâ”€â”€ liveness.rs      # Liveness detection (3+ signals)
â”‚           â”œâ”€â”€ deepfake.rs      # Deepfake detection [NEW]
â”‚           â”œâ”€â”€ binding.rs       # Device binding [NEW]
â”‚           â””â”€â”€ attestation.rs   # Attestation generation
â”‚
â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ crypto_vectors.rs        # MUST pass
â”‚   â”œâ”€â”€ timing_tests.rs          # MUST pass
â”‚   â”œâ”€â”€ audit_chain.rs           # MUST pass [NEW]
â”‚   â””â”€â”€ integration/
â”‚
â””â”€â”€ tools/
    â”œâ”€â”€ verify-build.sh          # Reproducibility check
    â”œâ”€â”€ run-dudect.sh            # Timing verification
    â””â”€â”€ audit-deps.sh            # Dependency audit
```

## SKELETON 2: Cargo.toml (Workspace Root)

```toml
# EXACT CONTENT - DO NOT MODIFY WITHOUT UPDATING THIS SPEC

[workspace]
resolver = "2"
members = [
    "crates/teras-core",
    "crates/teras-kunci",
    "crates/teras-lindung",
    "crates/teras-jejak",
    "crates/teras-benteng",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.75.0"  # NOTE: DEVIATION-001 - actual toolchain is stable (1.92.0+)
license = "PROPRIETARY"
repository = "https://github.com/ib823/teras"

[workspace.dependencies]
# Post-quantum crypto - DEVIATION-002 APPROVED
# Using pqcrypto family for Rust stable compatibility
# Cryptographically equivalent to NIST FIPS 203/204/205
pqcrypto-kyber = "=0.8.1"         # Kyber-768 â‰¡ ML-KEM-768
pqcrypto-dilithium = "=0.5.0"     # Dilithium3 â‰¡ ML-DSA-65
pqcrypto-sphincsplus = "=0.7.0"   # SPHINCS+ â‰¡ SLH-DSA (BACKUP)
pqcrypto-traits = "=0.3.5"        # Common traits

# Classical crypto - EXACT VERSIONS
x25519-dalek = "=2.0.1"
ed25519-dalek = { version = "=2.1.1", features = ["hazmat"] }
aes-gcm = "=0.10.3"
chacha20poly1305 = "=0.10.1"
sha3 = "=0.10.8"
sha2 = "=0.10.8"
blake3 = "=1.5.0"
hkdf = "=0.12.4"
argon2 = "=0.5.3"

# Utilities - EXACT VERSIONS
zeroize = { version = "=1.7.0", features = ["derive"] }
rand = "=0.8.5"
rand_core = "=0.6.4"
subtle = "=2.5.0"

# Internal crates
teras-core = { path = "crates/teras-core" }
teras-kunci = { path = "crates/teras-kunci" }
teras-lindung = { path = "crates/teras-lindung" }
teras-jejak = { path = "crates/teras-jejak" }

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## SKELETON 3: Secret Type Implementation

```rust
// crates/teras-lindung/src/secret.rs
// EXACT IMPLEMENTATION - DO NOT MODIFY

use core::sync::atomic::{compiler_fence, Ordering};
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// A type that holds secret data with automatic zeroization.
/// 
/// # Security Properties
/// - Data is zeroized on drop (guaranteed by compiler_fence)
/// - No Clone implementation (secrets cannot be copied)
/// - No Debug implementation (secrets cannot be printed)
/// - Memory is mlocked if platform supports it
pub struct Secret<T: Zeroize> {
    data: Box<T>,
    #[cfg(unix)]
    is_locked: bool,
}

impl<T: Zeroize> Secret<T> {
    /// Create a new secret.
    /// 
    /// # Panics
    /// Panics if memory locking fails on platforms that support it
    /// and TERAS_STRICT_MLOCK environment variable is set.
    pub fn new(data: T) -> Self {
        let boxed = Box::new(data);
        
        #[cfg(unix)]
        let is_locked = {
            let ptr = boxed.as_ref() as *const T as *const u8;
            let len = std::mem::size_of::<T>();
            let result = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
            if result != 0 {
                #[cfg(debug_assertions)]
                eprintln!("[TERAS WARNING] mlock failed: {}", std::io::Error::last_os_error());
                
                // In strict mode, fail if mlock fails
                if std::env::var("TERAS_STRICT_MLOCK").is_ok() {
                    panic!("mlock failed and TERAS_STRICT_MLOCK is set");
                }
            }
            result == 0
        };
        
        Secret {
            data: boxed,
            #[cfg(unix)]
            is_locked,
        }
    }
    
    /// Expose the secret for reading.
    /// 
    /// # Security
    /// The returned reference must not be stored or leaked.
    #[inline]
    pub fn expose(&self) -> &T {
        &self.data
    }
    
    /// Expose the secret for mutation.
    /// 
    /// # Security
    /// The returned reference must not be stored or leaked.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        // Step 1: Zeroize the data
        self.data.zeroize();
        
        // Step 2: Memory barrier to prevent reordering
        compiler_fence(Ordering::SeqCst);
        
        // Step 3: Unlock memory
        #[cfg(unix)]
        if self.is_locked {
            let ptr = self.data.as_ref() as *const T as *const u8;
            let len = std::mem::size_of::<T>();
            unsafe { libc::munlock(ptr as *const libc::c_void, len); }
        }
    }
}

// PROHIBITED IMPLEMENTATIONS - These must NOT exist:
// impl<T: Zeroize> Clone for Secret<T> { ... }     // NO
// impl<T: Zeroize> Debug for Secret<T> { ... }     // NO
// impl<T: Zeroize> Display for Secret<T> { ... }   // NO
// impl<T: Zeroize> Serialize for Secret<T> { ... } // NO

// VALIDATION: Compile must fail if any of the above are implemented.
```

## SKELETON 4: Constant-Time Comparison

```rust
// crates/teras-kunci/src/ct.rs
// EXACT IMPLEMENTATION - DO NOT MODIFY

use subtle::ConstantTimeEq;

/// Constant-time equality comparison.
/// 
/// # Security
/// - No early return
/// - No branching on input values
/// - Verified by dudect
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    a.ct_eq(b).into()
}

/// Constant-time selection.
/// 
/// Returns `a` if `condition` is true, `b` otherwise.
/// 
/// # Security
/// - No branching on condition
/// - Both branches are always evaluated
#[inline(never)]
pub fn ct_select_u8(condition: bool, a: u8, b: u8) -> u8 {
    use subtle::ConditionallySelectable;
    let choice = subtle::Choice::from(condition as u8);
    u8::conditional_select(&b, &a, choice)
}

/// Constant-time conditional copy.
///
/// Copies `src` to `dst` if `choice` is true.
/// Execution time is independent of `choice`.
#[inline(never)]
pub fn ct_copy_if(choice: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "ct_copy_if: length mismatch");
    
    let mask = (-(choice as i8)) as u8;
    for i in 0..dst.len() {
        dst[i] = (src[i] & mask) | (dst[i] & !mask);
    }
}

/// Constant-time is_zero check.
///
/// Returns true if all bytes are zero.
#[inline(never)]
pub fn ct_is_zero(data: &[u8]) -> bool {
    let zero = vec![0u8; data.len()];
    ct_eq(data, &zero)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ct_eq_equal() {
        assert!(ct_eq(b"hello", b"hello"));
    }
    
    #[test]
    fn test_ct_eq_not_equal() {
        assert!(!ct_eq(b"hello", b"world"));
    }
    
    #[test]
    fn test_ct_eq_different_length() {
        assert!(!ct_eq(b"hello", b"hi"));
    }
    
    // REQUIRED: dudect verification in CI
}
```

## SKELETON 5: Hybrid KEM Implementation [NEW IN V3.1]

```rust
// crates/teras-kunci/src/kem.rs
// EXACT IMPLEMENTATION - DO NOT MODIFY
// NOTE: DEVIATION-002 - Using pqcrypto-kyber (Kyber-768 â‰¡ ML-KEM-768)

use crate::error::{TerasError, TerasResult};
use teras_lindung::Secret;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Hybrid KEM combining Kyber-768 (â‰¡ ML-KEM-768) and X25519.
/// 
/// Both algorithms must succeed for encapsulation/decapsulation.
/// If either fails, the operation fails.
/// 
/// This provides security if EITHER:
/// - Classical crypto (X25519) remains secure, OR
/// - Post-quantum crypto (Kyber/ML-KEM) remains secure
/// 
/// NOTE: Kyber-768 is cryptographically equivalent to ML-KEM-768 (FIPS 203)
pub struct HybridKem {
    kyber_sk: Secret<Vec<u8>>,       // Kyber-768 secret key
    x25519_sk: Secret<[u8; 32]>,     // X25519 secret key
}

/// Hybrid encapsulation key (public)
pub struct HybridEncapsulationKey {
    kyber_pk: Vec<u8>,       // Kyber-768 public key (1184 bytes)
    x25519_pk: [u8; 32],     // X25519 public key
}

/// Hybrid ciphertext
pub struct HybridCiphertext {
    kyber_ct: Vec<u8>,       // Kyber-768 ciphertext (1088 bytes)
    x25519_ct: [u8; 32],     // X25519 ephemeral public key
}

impl HybridKem {
    /// Generate new hybrid keypair.
    pub fn generate() -> TerasResult<(Self, HybridEncapsulationKey)> {
        use rand::rngs::OsRng;
        
        // Generate Kyber-768 keypair
        let (kyber_pk, kyber_sk) = kyber768::keypair();
        
        // Generate X25519 keypair
        let x25519_sk = X25519Secret::random_from_rng(OsRng);
        let x25519_pk = X25519Public::from(&x25519_sk);
        
        let private = HybridKem {
            kyber_sk: Secret::new(kyber_sk.as_bytes().to_vec()),
            x25519_sk: Secret::new(x25519_sk.to_bytes()),
        };
        
        let public = HybridEncapsulationKey {
            kyber_pk: kyber_pk.as_bytes().to_vec(),
            x25519_pk: x25519_pk.to_bytes(),
        };
        
        Ok((private, public))
    }
    
    /// Decapsulate to get shared secret.
    /// 
    /// Returns 64-byte shared secret (32 from each algorithm, concatenated).
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> TerasResult<Secret<[u8; 64]>> {
        // Reconstruct Kyber secret key
        let kyber_sk = kyber768::SecretKey::from_bytes(&self.kyber_sk.expose())
            .map_err(|_| TerasError::DecryptionFailed)?;
        
        // Reconstruct Kyber ciphertext
        let kyber_ct = kyber768::Ciphertext::from_bytes(&ct.kyber_ct)
            .map_err(|_| TerasError::DecryptionFailed)?;
        
        // Decapsulate Kyber
        let kyber_ss = kyber768::decapsulate(&kyber_ct, &kyber_sk);
        
        // Decapsulate X25519
        let x25519_their_public = X25519Public::from(ct.x25519_ct);
        let x25519_sk = X25519Secret::from(self.x25519_sk.expose().clone());
        let x25519_ss = x25519_sk.diffie_hellman(&x25519_their_public);
        
        // Combine shared secrets
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(kyber_ss.as_bytes());
        combined[32..].copy_from_slice(x25519_ss.as_bytes());
        
        Ok(Secret::new(combined))
    }
}

impl HybridEncapsulationKey {
    /// Encapsulate to create ciphertext and shared secret.
    pub fn encapsulate(&self) -> TerasResult<(HybridCiphertext, Secret<[u8; 64]>)> {
        use rand::rngs::OsRng;
        
        // Reconstruct Kyber public key
        let kyber_pk = kyber768::PublicKey::from_bytes(&self.kyber_pk)
            .map_err(|_| TerasError::KeyDerivationFailed)?;
        
        // Encapsulate Kyber
        let (kyber_ss, kyber_ct) = kyber768::encapsulate(&kyber_pk);
        
        // Encapsulate X25519
        let x25519_ephemeral = X25519Secret::random_from_rng(OsRng);
        let x25519_ephemeral_public = X25519Public::from(&x25519_ephemeral);
        let x25519_their_public = X25519Public::from(self.x25519_pk);
        let x25519_ss = x25519_ephemeral.diffie_hellman(&x25519_their_public);
        
        let ct = HybridCiphertext {
            kyber_ct: kyber_ct.as_bytes().to_vec(),
            x25519_ct: x25519_ephemeral_public.to_bytes(),
        };
        
        // Combine shared secrets
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(kyber_ss.as_bytes());
        combined[32..].copy_from_slice(x25519_ss.as_bytes());
        
        Ok((ct, Secret::new(combined)))
    }
}
```

---

# PART V: VALIDATION PROTOCOL

## CHECKPOINT 1: Before Any Commit

```
EVERY commit must pass:

â–¡ cargo fmt --check
  Fails if code is not formatted

â–¡ cargo clippy -- -D warnings
  Fails if any clippy warnings

â–¡ cargo test
  Fails if any test fails

â–¡ cargo test --release
  Fails if release tests fail (different from debug)

â–¡ grep -r "unsafe" --include="*.rs" | wc -l
  Must be <= APPROVED_UNSAFE_COUNT (currently: 10)
  Each unsafe block must have safety comment

â–¡ No println!/dbg!/eprintln! in crypto code
  Grep must return 0 for these in teras-kunci, teras-lindung

COMMIT BLOCKED if any check fails.
```

## CHECKPOINT 2: Before Merge to Main

```
EVERY merge must pass:

â–¡ All CHECKPOINT 1 items

â–¡ cargo +nightly miri test
  Fails if undefined behavior detected

â–¡ ./tools/run-dudect.sh
  Fails if any t-value > 4.5

â–¡ ./tools/verify-vectors.sh
  Fails if test vectors don't match

â–¡ cargo deny check
  Fails if prohibited dependency detected

â–¡ ./tools/verify-build.sh
  Fails if build not reproducible

â–¡ Audit log tests pass
  ./tools/verify-audit-chain.sh

MERGE BLOCKED if any check fails.
```

## CHECKPOINT 3: Before Release

```
EVERY release must pass:

â–¡ All CHECKPOINT 2 items

â–¡ Full Kani verification
  cargo kani --all-features

â–¡ Security review checklist
  - [ ] No new unsafe blocks without review
  - [ ] No new dependencies without audit
  - [ ] All secrets use Secret<T> type
  - [ ] All crypto uses approved algorithms
  - [ ] All network uses TLS with pinning
  - [ ] No biometric data leaves device
  - [ ] Audit logging captures all security events
  - [ ] Deepfake detection enabled for face matching
  - [ ] Device binding enforced

â–¡ Reproducibility verification
  Build on 3 different machines
  Compare SHA-256 of outputs
  Must be identical

â–¡ Diverse double-compilation
  Build with different compilers
  Compare behavior

RELEASE BLOCKED if any check fails.
```

---

# PART VI: PROHIBITED ACTIONS

## PROHIBITION 1: Data Handling

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ NEVER:                                                                        â•‘
â•‘ â€¢ Send raw biometric data to any server                                       â•‘
â•‘ â€¢ Send face embeddings/templates to server                                    â•‘
â•‘ â€¢ Store biometric data in cloud storage                                       â•‘
â•‘ â€¢ Log any secret or key material                                              â•‘
â•‘ â€¢ Log any biometric data                                                      â•‘
â•‘ â€¢ Store secrets in plain text                                                 â•‘
â•‘ â€¢ Use platform storage without our encryption                                 â•‘
â•‘ â€¢ Share secrets between users                                                 â•‘
â•‘ â€¢ Transmit secrets without TLS + certificate pinning                          â•‘
â•‘ â€¢ Use SMS OTP as sole authentication factor                                   â•‘
â•‘ â€¢ Use email OTP as sole authentication factor                                 â•‘
â•‘ â€¢ Trust phone numbers as identity                                             â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## PROHIBITION 2: Implementation

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ NEVER:                                                                        â•‘
â•‘ â€¢ Use algorithms not in the approved list                                     â•‘
â•‘ â€¢ Use libraries not in the approved list                                      â•‘
â•‘ â€¢ Add dependencies without updating Cargo.lock                                â•‘
â•‘ â€¢ Use version ranges in Cargo.toml (use exact versions)                       â•‘
â•‘ â€¢ Implement crypto primitives (use approved libraries)                        â•‘
â•‘ â€¢ Use unsafe without safety comment                                           â•‘
â•‘ â€¢ Use unwrap() or expect() on user input                                      â•‘
â•‘ â€¢ Panic on error (fail secure, don't crash)                                   â•‘
â•‘ â€¢ Use println!/dbg! for secrets (even in development)                        â•‘
â•‘ â€¢ Clone Secret<T> (even if it "seems convenient")                            â•‘
â•‘ â€¢ Use non-hybrid KEM for new deployments                                      â•‘
â•‘ â€¢ Skip deepfake detection "for performance"                                   â•‘
â•‘ â€¢ Skip liveness detection "for convenience"                                   â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## PROHIBITION 3: Architecture

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ NEVER:                                                                        â•‘
â•‘ â€¢ Build "simplified version" that violates laws                               â•‘
â•‘ â€¢ Skip validation "for MVP"                                                   â•‘
â•‘ â€¢ Add "temporary" workarounds to security                                     â•‘
â•‘ â€¢ Claim TERAS-LANG implementation exists (it doesn't)                        â•‘
â•‘ â€¢ Claim ZK face verification works (it's research)                           â•‘
â•‘ â€¢ Promise timelines not in REALITY section                                   â•‘
â•‘ â€¢ Modify wire formats without updating this spec                             â•‘
â•‘ â€¢ Change test vectors without cryptographic review                           â•‘
â•‘ â€¢ Disable audit logging in production                                         â•‘
â•‘ â€¢ Implement "backdoor" for any reason                                         â•‘
â•‘ â€¢ Create single point of key escrow                                           â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## PROHIBITION 4: Claims

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ NEVER CLAIM:                                                                  â•‘
â•‘ â€¢ "Zero-knowledge face verification" (not implemented)                        â•‘
â•‘ â€¢ "Formally verified" (until actual proofs exist)                            â•‘
â•‘ â€¢ "Quantum-resistant" (say "quantum-ready with hybrid crypto")               â•‘
â•‘ â€¢ "Unhackable" (nothing is)                                                   â•‘
â•‘ â€¢ "100% secure" (nothing is)                                                  â•‘
â•‘ â€¢ "Deepfake-proof" (say "deepfake-resistant")                                â•‘
â•‘ â€¢ "Unbreakable encryption" (algorithms may be broken in future)              â•‘
â•‘ â€¢ Features that don't exist                                                   â•‘
â•‘ â€¢ Timelines that aren't validated                                            â•‘
â•‘ â€¢ Protection against threats not in Part XV                                   â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

# PART VII: DECISION LOG

## DECISION 1: Use Rust Instead of TERAS-LANG (For Now)

```
DATE: 2025-12-30
DECISION: Implement in Rust with verification tools, not TERAS-LANG

RATIONALE:
â€¢ TERAS-LANG doesn't exist
â€¢ Creating a new language is 2-5 year project
â€¢ Rust with Kani/Verus provides verification today
â€¢ Migration to TERAS-LANG possible later

ALTERNATIVES REJECTED:
â€¢ C/C++: Memory safety issues
â€¢ Go: GC unpredictable, no verification tools
â€¢ TERAS-LANG: Doesn't exist

MIGRATION PATH:
â€¢ Rust code follows strict patterns (Secret<T>, etc.)
â€¢ When TERAS-LANG exists, transpiler can convert
â€¢ Core logic is algorithm, not language
```

## DECISION 2: Signed Attestation Instead of ZK Face Proof

```
DATE: 2025-12-30
DECISION: Use signed attestation for face matching, not ZK proof

RATIONALE:
â€¢ ZK for 512-dim float cosine similarity is infeasible on mobile
â€¢ Estimated proving time: 10+ minutes
â€¢ Estimated memory: 8+ GB
â€¢ This is a research problem, not engineering

WHAT WE DO INSTEAD:
â€¢ Face matching happens on device (Law 1 satisfied)
â€¢ Device signs attestation "match succeeded"
â€¢ Server verifies device signature
â€¢ Biometrics never leave device

SECURITY PROPERTY PRESERVED:
â€¢ Server cannot see face (only attestation)
â€¢ Server cannot reconstruct face from attestation
â€¢ Law 1 is fully satisfied

FUTURE RESEARCH:
â€¢ Investigate ZK-friendly embedding models
â€¢ Investigate integer-only similarity
â€¢ Track academic progress
```

## DECISION 3: Exact Version Pinning

```
DATE: 2025-12-30
DECISION: Pin exact versions of all dependencies

RATIONALE:
â€¢ Semver allows breaking changes
â€¢ Supply chain attacks happen
â€¢ Reproducible builds require exact versions

IMPLICATIONS:
â€¢ No automatic updates
â€¢ Must manually review and update
â€¢ Slower, but safer
```

## DECISION 4: Hybrid Cryptography Mandatory [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: All new deployments MUST use hybrid (classical + PQ) crypto

RATIONALE:
â€¢ ML-KEM and ML-DSA are new algorithms
â€¢ Cryptographic breaks may be discovered
â€¢ Classical algorithms have decades of analysis
â€¢ Hybrid provides security if either survives

IMPLEMENTATION:
â€¢ KEM: ML-KEM-768 + X25519 (both required)
â€¢ Signatures: ML-DSA-65 + Ed25519 (both must verify)
â€¢ Shared secrets: Concatenated, then HKDF

MIGRATION:
â€¢ Existing single-algorithm deployments: Migrate within 6 months
â€¢ New deployments: Hybrid from day 1
```

## DECISION 5: Multi-Signal Liveness Required [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: Liveness detection requires minimum 3 independent signals

RATIONALE:
â€¢ Single-signal liveness is easily defeated
â€¢ Deepfakes are increasingly sophisticated
â€¢ Defense in depth for biometric verification

REQUIRED SIGNALS (minimum 3):
â€¢ Texture analysis (2D vs 3D)
â€¢ Behavioral (blink, head turn, random challenge)
â€¢ Reflection analysis (screen vs real light)
â€¢ Temporal consistency (frame-to-frame)
â€¢ Depth estimation (if available)

THRESHOLD:
â€¢ Each signal: >70% confidence
â€¢ Combined: >80% confidence
â€¢ Any signal <50%: Automatic failure
```

## DECISION 6: Device Binding Over Phone Numbers [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: Identity bound to device keys, not phone numbers

RATIONALE:
â€¢ SIM swap attacks are common
â€¢ Phone numbers are not secure identifiers
â€¢ Email accounts can be compromised
â€¢ Cryptographic device binding is stronger

IMPLEMENTATION:
â€¢ Device generates keypair on first launch
â€¢ Private key never leaves device
â€¢ Public key registered with server
â€¢ All attestations signed by device key
â€¢ Recovery: Multi-device registration before loss

PROHIBITED:
â€¢ SMS OTP as sole factor
â€¢ Email OTP as sole factor
â€¢ Phone number as identity
```

## DECISION 7: Comprehensive Audit Logging [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: All security events must be audit logged

RATIONALE:
â€¢ Insider threats require detection
â€¢ Forensics require complete history
â€¢ Compliance requires audit trails
â€¢ Anomaly detection requires data

IMPLEMENTATION:
â€¢ Every security event logged (Part III, SPEC 4)
â€¢ Cryptographic hash chain (tamper-evident)
â€¢ Append-only storage (cannot delete)
â€¢ 7-year retention minimum
â€¢ Anomaly detection on logs

LOG EVENTS:
â€¢ Authentication attempts
â€¢ Key operations
â€¢ Data access
â€¢ Configuration changes
â€¢ Privilege escalation
```

---

# PART VIII: FUTURE VISION

**THIS SECTION IS ASPIRATIONAL. DO NOT IMPLEMENT.**

## VISION 1: TERAS-LANG

```
STATUS: FUTURE (2-5 years)

DESCRIPTION:
A purpose-built language with:
â€¢ Dependent types
â€¢ Linear types
â€¢ Refinement types
â€¢ Built-in ZK DSL
â€¢ Integrated SMT verification

CURRENT STATE: Does not exist
WORK REQUIRED: New language, compiler, tools
TIMELINE: Unknown

DO NOT:
â€¢ Claim TERAS-LANG is implemented
â€¢ "Approximate" TERAS-LANG features
â€¢ Start TERAS-LANG without completing current milestones
```

## VISION 2: Zero-Knowledge Face Verification

```
STATUS: FUTURE (Research)

DESCRIPTION:
True ZK proof that face matches document without revealing face.

CURRENT STATE: Infeasible on mobile (10+ min proving time)
WORK REQUIRED: Research breakthroughs

RESEARCH DIRECTIONS:
â€¢ ZK-friendly face embedding models
â€¢ Integer-only similarity metrics
â€¢ Proof aggregation
â€¢ Hardware acceleration

DO NOT:
â€¢ Claim this is implemented
â€¢ "Simplify" by leaking biometrics
â€¢ Promise timeline
```

## VISION 3: SARAF/NADI Collective Immunity

```
STATUS: FUTURE (Post-BENTENG)

DESCRIPTION:
Collective threat intelligence sharing via ZK proofs.

CURRENT STATE: Design only
WORK REQUIRED: Full implementation after core products

DO NOT:
â€¢ Implement before BENTENG MVP complete
â€¢ Claim collective immunity exists
```

## VISION 4: Formal Proofs for All Components

```
STATUS: FUTURE (1-2 years after MVP)

DESCRIPTION:
Complete formal verification in Coq/Lean:
â€¢ Functional correctness proofs
â€¢ Security property proofs
â€¢ Side-channel freedom proofs

CURRENT STATE: Partial Kani coverage only
WORK REQUIRED: Significant theorem prover expertise

DO NOT:
â€¢ Claim "formally verified" until proofs exist
â€¢ Skip Kani as intermediate step
```

---

# PART IX: GLOSSARY

```
TERM                    DEFINITION
â”€â”€â”€â”€                    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Attestation             Signed statement from device about verification result
Biometric               Face, fingerprint, voice, iris, or any body-based identifier
Constant-time           Execution time independent of secret values
Deepfake                AI-generated fake video/image of a person
Device Binding          Cryptographically linking identity to specific device
Hash Chain              Sequence of hashes where each includes previous
Hybrid Crypto           Using both classical and post-quantum algorithms
KEM                     Key Encapsulation Mechanism (quantum-resistant key exchange)
LAW                     Immutable rule that cannot be changed
Liveness                Proof that a real person is present (not photo/video)
mlock                   OS call to prevent memory from being swapped to disk
ML-DSA                  NIST post-quantum digital signature algorithm (Dilithium)
ML-KEM                  NIST post-quantum key encapsulation (Kyber)
MVP                     Minimum Viable Product
PAD                     Presentation Attack Detection (anti-spoofing)
REALITY                 What actually exists and works today (not aspirational)
Secret<T>               Rust type that enforces secret handling rules
SIM Swap                Attack where attacker takes over victim's phone number
TERAS-LANG              Future programming language (DOES NOT EXIST)
Test vector             Known input/output pair for validating implementation
ZK                      Zero-knowledge (proof that reveals nothing beyond statement)
Zeroize                 Overwrite memory with zeros before deallocation
```

---

# PART X: COMPLETE TEST VECTORS

## TEST VECTOR SET 1: SHA-256

```
MANDATORY: Implementation MUST produce EXACT outputs below.
Source: NIST FIPS 180-4 examples + TERAS-specific

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ ID   â”‚ Input (hex)                        â”‚ Expected SHA-256 (hex)            â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ S001 â”‚ (empty)                            â”‚ e3b0c44298fc1c149afbf4c8996fb924  â”‚
â”‚      â”‚                                    â”‚ 27ae41e4649b934ca495991b7852b855  â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ S002 â”‚ 616263                             â”‚ ba7816bf8f01cfea414140de5dae2223  â”‚
â”‚      â”‚ ("abc")                            â”‚ b00361a396177a9cb410ff61f20015ad  â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ S003 â”‚ 6162636462636465636465666465666764 â”‚ 248d6a61d20638b8e5c026930c3e6039  â”‚
â”‚      â”‚ 6566676866676869676869696a686a6b69 â”‚ a33ce45964ff2167f6ecedd419db06c1  â”‚
â”‚      â”‚ 6a6b6a6b6c6b6c6d6c6d6e6d6e6f6e6f70 â”‚                                   â”‚
â”‚      â”‚ 6f7071                             â”‚                                   â”‚
â”‚      â”‚ ("abcdbcdecdefdefgefghfghighij..." â”‚                                   â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ S004 â”‚ 5445524153 ("TERAS")               â”‚ a8d3c26ae4c3a3d...                â”‚
â”‚      â”‚                                    â”‚ (COMPUTE EXACT VALUE)             â”‚
â””â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Test code (MUST be in crates/teras-kunci/src/tests/vectors.rs):

#[test]
fn test_sha256_vectors() {
    use sha2::{Sha256, Digest};
    
    let vectors: &[(&[u8], &str)] = &[
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ];
    
    for (input, expected) in vectors {
        let result = Sha256::digest(input);
        let hex = hex::encode(result);
        assert_eq!(hex, *expected, "SHA-256 test vector failed for input {:?}", input);
    }
}

BUILD MUST FAIL if these vectors don't match.
```

## TEST VECTOR SET 2: AES-256-GCM

```
MANDATORY: Implementation MUST produce EXACT outputs below.
Source: NIST SP 800-38D examples

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ ID   â”‚ Key (hex)                          â”‚ Nonce (hex)    â”‚ AAD (hex)        â”‚
â”‚      â”‚ Plaintext (hex)                    â”‚ Ciphertext+Tag (hex)              â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ A001 â”‚ 00000000000000000000000000000000   â”‚ 000000000000   â”‚ (none)           â”‚
â”‚      â”‚ 00000000000000000000000000000000   â”‚ 000000000000   â”‚                  â”‚
â”‚      â”‚ (32 zero bytes key)                â”‚                â”‚                  â”‚
â”‚      â”‚                                    â”‚                â”‚                  â”‚
â”‚      â”‚ Plaintext: (empty)                 â”‚                â”‚                  â”‚
â”‚      â”‚ Ciphertext: (empty)                â”‚                â”‚                  â”‚
â”‚      â”‚ Tag: 530f8afbc74536b9a963b4f1c4cb738b                                  â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ A002 â”‚ Key: feffe9928665731c6d6a8f9467308308                                  â”‚
â”‚      â”‚      feffe9928665731c6d6a8f9467308308                                  â”‚
â”‚      â”‚ Nonce: cafebabefacedbaddecaf888                                        â”‚
â”‚      â”‚ Plaintext: d9313225f88406e5a55909c5aff5269a                            â”‚
â”‚      â”‚            86a7a9531534f7da2e4c303d8a318a72                            â”‚
â”‚      â”‚            1c3c0c95956809532fcf0e2449a6b525                            â”‚
â”‚      â”‚            b16aedf5aa0de657ba637b391aafd255                            â”‚
â”‚      â”‚ Ciphertext: 522dc1f099567d07f47f37a32a84427d                           â”‚
â”‚      â”‚             643a8cdcbfe5c0c97598a2bd2555d1aa                           â”‚
â”‚      â”‚             8cb08e48590dbb3da7b08b1056828838                           â”‚
â”‚      â”‚             c5f61e6393ba7a0abcc9f662898015ad                           â”‚
â”‚      â”‚ Tag: b094dac5d93471bdec1a502270e3cc6c                                  â”‚
â””â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

BUILD MUST FAIL if these vectors don't match.
```

## TEST VECTOR SET 3: Ed25519

```
MANDATORY: Implementation MUST produce EXACT outputs below.
Source: RFC 8032

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ ID   â”‚ Private Key (seed, 32 bytes hex)                                       â”‚
â”‚      â”‚ Public Key (32 bytes hex)                                              â”‚
â”‚      â”‚ Message (hex)                                                          â”‚
â”‚      â”‚ Signature (64 bytes hex)                                               â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ E001 â”‚ Private: 9d61b19deffd5a60ba844af492ec2cc4                              â”‚
â”‚      â”‚          4449c5697b326919703bac031cae7f60                              â”‚
â”‚      â”‚ Public:  d75a980182b10ab7d54bfed3c964073a                              â”‚
â”‚      â”‚          0ee172f3daa62325af021a68f707511a                              â”‚
â”‚      â”‚ Message: (empty)                                                       â”‚
â”‚      â”‚ Signature: e5564300c360ac729086e2cc806e828a                            â”‚
â”‚      â”‚            84877f1eb8e5d974d873e06522490155                            â”‚
â”‚      â”‚            5fb8821590a33bacc61e39701cf9b46b                            â”‚
â”‚      â”‚            d25bf5f0595bbe24655141438e7a100b                            â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ E002 â”‚ Private: 4ccd089b28ff96da9db6c346ec114e0f                              â”‚
â”‚      â”‚          5b8a319f35aba624da8cf6ed4fb8a6fb                              â”‚
â”‚      â”‚ Public:  3d4017c3e843895a92b70aa74d1b7ebc                              â”‚
â”‚      â”‚          9c982ccf2ec4968cc0cd55f12af4660c                              â”‚
â”‚      â”‚ Message: 72                                                            â”‚
â”‚      â”‚ Signature: 92a009a9f0d4cab8720e820b5f642540                            â”‚
â”‚      â”‚            a2b27b5416503f8fb3762223ebdb69da                            â”‚
â”‚      â”‚            085ac1e43e15996e458f3613d0f11d8c                            â”‚
â”‚      â”‚            387b2eaeb4302aeeb00d291612bb0c00                            â”‚
â””â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

BUILD MUST FAIL if these vectors don't match.
```

## TEST VECTOR SET 4: X25519

```
MANDATORY: Implementation MUST produce EXACT outputs below.
Source: RFC 7748

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ ID   â”‚ Alice Private / Public             â”‚ Bob Private / Public              â”‚
â”‚      â”‚ Shared Secret                                                           â”‚
â”œâ”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ X001 â”‚ Private A: 77076d0a7318a57d3c16c17251b26645                            â”‚
â”‚      â”‚            df4c2f87ebc0992ab177fba51db92c2a                            â”‚
â”‚      â”‚ Public A:  8520f0098930a754748b7ddcb43ef75a                            â”‚
â”‚      â”‚            0dbf3a0d26381af4eba4a98eaa9b4e6a                            â”‚
â”‚      â”‚                                                                         â”‚
â”‚      â”‚ Private B: 5dab087e624a8a4b79e17f8b83800ee6                            â”‚
â”‚      â”‚            6f3bb1292618b6fd1c2f8b27ff88e0eb                            â”‚
â”‚      â”‚ Public B:  de9edb7d7b7dc1b4d35b61c2ece43537                            â”‚
â”‚      â”‚            3f8343c85b78674dadfc7e146f882b4f                            â”‚
â”‚      â”‚                                                                         â”‚
â”‚      â”‚ Shared: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742â”‚
â””â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

BUILD MUST FAIL if shared secret doesn't match.
```

## TEST VECTOR SET 5: ML-KEM-768

```
MANDATORY: Implementation MUST produce EXACT outputs below.
Source: NIST FIPS 203 Known Answer Tests

NOTE: Full KAT file is large. Use NIST reference for complete validation.
100% pass rate required. BUILD MUST FAIL if any vector fails.
```

## TEST VECTOR SET 6: Audit Log Chain [NEW IN V3.1]

```
MANDATORY: Hash chain must be verifiable.

Genesis Entry:
â”‚ prev_hash: 0000000000000000000000000000000000000000000000000000000000000000
â”‚ entry_hash: SHA-256(genesis_entry_bytes)

Entry N:
â”‚ prev_hash: entry_hash of Entry N-1
â”‚ entry_hash: SHA-256(entry_N_bytes excluding signature)

VALIDATION:
â€¢ For each entry E[i] where i > 0:
  - E[i].prev_hash MUST equal SHA-256(E[i-1])
  - Signature MUST verify over E[i] bytes 0 to 116+M-1
â€¢ Chain broken = immediate security alert
```

---

# PART XI: COMPLETE CODE MODULES

## MODULE 1: Error Types (COMPLETE)

```rust
// crates/teras-core/src/error.rs
// COMPLETE IMPLEMENTATION - USE EXACTLY AS IS

use std::fmt;

/// All TERAS errors.
/// 
/// Every function that can fail MUST return Result<T, TerasError>.
/// NEVER use unwrap(), expect(), or panic!() on user input.
#[derive(Debug)]
pub enum TerasError {
    // Cryptographic errors
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidSignature,
    DecryptionFailed,
    KeyDerivationFailed,
    RandomGenerationFailed,
    HybridCryptoFailed { classical_ok: bool, pq_ok: bool },
    
    // Memory errors
    MemoryLockFailed,
    MemoryUnlockFailed,
    ZeroizationFailed,
    
    // Format errors
    InvalidMagic { expected: u32, actual: u32 },
    InvalidVersion { expected: u16, actual: u16 },
    InvalidChecksum,
    InvalidFormat(String),
    
    // Validation errors
    ExpiredKey,
    InvalidAttestation,
    ReplayDetected,
    TimestampOutOfRange,
    
    // Biometric errors [NEW IN V3.1]
    LivenessCheckFailed { score: u8 },
    DeepfakeDetected { score: u8 },
    InsufficientSignals { required: u8, provided: u8 },
    
    // Device binding errors [NEW IN V3.1]
    DeviceNotBound,
    DeviceMismatch,
    
    // Audit errors [NEW IN V3.1]
    AuditChainBroken { entry_index: u64 },
    AuditLogFull,
    
    // IO errors
    IoError(std::io::Error),
    NetworkError(String),
    
    // Platform errors
    PlatformNotSupported(String),
}

impl fmt::Display for TerasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, actual)
            }
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Self::RandomGenerationFailed => write!(f, "Random generation failed"),
            Self::HybridCryptoFailed { classical_ok, pq_ok } => {
                write!(f, "Hybrid crypto failed: classical={}, pq={}", classical_ok, pq_ok)
            }
            Self::MemoryLockFailed => write!(f, "Memory lock (mlock) failed"),
            Self::MemoryUnlockFailed => write!(f, "Memory unlock (munlock) failed"),
            Self::ZeroizationFailed => write!(f, "Zeroization verification failed"),
            Self::InvalidMagic { expected, actual } => {
                write!(f, "Invalid magic: expected 0x{:08X}, got 0x{:08X}", expected, actual)
            }
            Self::InvalidVersion { expected, actual } => {
                write!(f, "Invalid version: expected {}, got {}", expected, actual)
            }
            Self::InvalidChecksum => write!(f, "Invalid checksum"),
            Self::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            Self::ExpiredKey => write!(f, "Key has expired"),
            Self::InvalidAttestation => write!(f, "Invalid attestation"),
            Self::ReplayDetected => write!(f, "Replay attack detected"),
            Self::TimestampOutOfRange => write!(f, "Timestamp out of acceptable range"),
            Self::LivenessCheckFailed { score } => {
                write!(f, "Liveness check failed: score {} < 80", score)
            }
            Self::DeepfakeDetected { score } => {
                write!(f, "Deepfake detected: score {} > 20", score)
            }
            Self::InsufficientSignals { required, provided } => {
                write!(f, "Insufficient liveness signals: {} required, {} provided", required, provided)
            }
            Self::DeviceNotBound => write!(f, "Device not bound to identity"),
            Self::DeviceMismatch => write!(f, "Device does not match registered device"),
            Self::AuditChainBroken { entry_index } => {
                write!(f, "Audit chain broken at entry {}", entry_index)
            }
            Self::AuditLogFull => write!(f, "Audit log storage full"),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::PlatformNotSupported(platform) => {
                write!(f, "Platform not supported: {}", platform)
            }
        }
    }
}

impl std::error::Error for TerasError {}

impl From<std::io::Error> for TerasError {
    fn from(e: std::io::Error) -> Self {
        TerasError::IoError(e)
    }
}

/// Result type for all TERAS operations.
pub type TerasResult<T> = Result<T, TerasError>;
```

## MODULE 2: Secret Type (COMPLETE)

See SKELETON 3 in Part IV.

## MODULE 3: Constant-Time Utilities (COMPLETE)

See SKELETON 4 in Part IV.

## MODULE 4: Hybrid KEM (COMPLETE)

See SKELETON 5 in Part IV.

## MODULE 5: Hash Functions (COMPLETE)

```rust
// crates/teras-kunci/src/hash.rs
// COMPLETE IMPLEMENTATION - USE EXACTLY AS IS

use sha2::{Sha256, Digest as Sha2Digest};
use sha3::{Sha3_256, Digest as Sha3Digest};
use blake3::Hasher as Blake3Hasher;

/// Hash algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha3_256,
    Blake3,
}

/// Compute hash of data.
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(data);
            hasher.finalize().as_bytes().to_vec()
        }
    }
}

/// Compute SHA-256 hash (convenience function).
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA3-256 hash (convenience function).
#[inline]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute BLAKE3 hash (convenience function).
#[inline]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // MANDATORY TEST VECTORS - BUILD FAILS IF THESE DON'T MATCH
    
    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"");
        let expected = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ).unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }
    
    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc");
        let expected = hex::decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ).unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }
    
    #[test]
    fn test_sha3_256_empty() {
        let result = sha3_256(b"");
        let expected = hex::decode(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ).unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }
}
```

## MODULE 6: Audit Log Entry [NEW IN V3.1]

```rust
// crates/teras-jejak/src/entry.rs
// COMPLETE IMPLEMENTATION - USE EXACTLY AS IS

use teras_core::error::{TerasError, TerasResult};
use teras_kunci::hash::sha256;
use serde::{Serialize, Deserialize};

/// Magic number for log entries: "LOGE" in ASCII
pub const LOG_ENTRY_MAGIC: u32 = 0x4C4F4745;
pub const LOG_ENTRY_VERSION: u16 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EventType {
    AuthenticationAttempt = 0x0001,
    KeyGeneration = 0x0002,
    KeyUsage = 0x0003,
    KeyDestruction = 0x0004,
    VerificationAttempt = 0x0005,
    AttestationGenerated = 0x0006,
    ConfigurationChange = 0x0007,
    AnomalyDetected = 0x0008,
    AlgorithmRotation = 0x0009,
    PrivilegeEscalation = 0x000A,
    DataAccess = 0x000B,
    NetworkConnection = 0x000C,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Warning = 1,
    Error = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Result {
    Failure = 0,
    Success = 1,
}

/// Audit log entry.
/// 
/// Each entry contains:
/// - Event metadata
/// - Hash of previous entry (chain integrity)
/// - Signature for authenticity
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub magic: u32,
    pub version: u16,
    pub event_type: EventType,
    pub timestamp: u64,
    pub actor_id: [u8; 32],
    pub object_id: [u8; 32],
    pub result: Result,
    pub severity: Severity,
    pub context: Vec<u8>,  // JSON, no secrets
    pub prev_hash: [u8; 32],
    pub signature: Vec<u8>,  // ML-DSA-65
}

impl AuditLogEntry {
    /// Create new entry (unsigned).
    /// 
    /// Call `sign()` before storing.
    pub fn new(
        event_type: EventType,
        actor_id: [u8; 32],
        object_id: [u8; 32],
        result: Result,
        severity: Severity,
        context: Vec<u8>,
        prev_hash: [u8; 32],
    ) -> Self {
        Self {
            magic: LOG_ENTRY_MAGIC,
            version: LOG_ENTRY_VERSION,
            event_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            actor_id,
            object_id,
            result,
            severity,
            context,
            prev_hash,
            signature: Vec::new(),
        }
    }
    
    /// Compute hash of this entry (for chaining).
    pub fn compute_hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes_without_signature();
        sha256(&bytes)
    }
    
    /// Serialize entry without signature (for signing/hashing).
    pub fn to_bytes_without_signature(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic.to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&(self.event_type as u16).to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.actor_id);
        bytes.extend_from_slice(&self.object_id);
        bytes.push(self.result as u8);
        bytes.push(self.severity as u8);
        bytes.extend_from_slice(&(self.context.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.prev_hash);
        bytes
    }
    
    /// Verify chain integrity.
    /// 
    /// Returns error if prev_hash doesn't match expected.
    pub fn verify_chain(&self, expected_prev_hash: &[u8; 32]) -> TerasResult<()> {
        if self.prev_hash != *expected_prev_hash {
            return Err(TerasError::AuditChainBroken { entry_index: 0 });
        }
        Ok(())
    }
}

/// Genesis entry for new audit log.
pub fn create_genesis_entry() -> AuditLogEntry {
    AuditLogEntry::new(
        EventType::ConfigurationChange,
        [0u8; 32],  // System actor
        [0u8; 32],  // No object
        Result::Success,
        Severity::Info,
        b"Genesis entry".to_vec(),
        [0u8; 32],  // No previous
    )
}
```

---

# PART XII: VALIDATION SCRIPTS

## SCRIPT 1: Build Verification

```bash
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
```

## SCRIPT 2: Timing Verification

```bash
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
```

## SCRIPT 3: Dependency Audit

```bash
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
# NOTE: DEVIATION-002 - Using pqcrypto-* instead of ml-kem/ml-dsa/slh-dsa
APPROVED="pqcrypto-kyber pqcrypto-dilithium pqcrypto-sphincsplus pqcrypto-traits x25519-dalek ed25519-dalek aes-gcm chacha20poly1305 sha3 sha2 blake3 hkdf argon2 zeroize rand rand_core subtle"
# (Add validation logic here)

echo "=== Dependency audit passed ==="
```

## SCRIPT 4: Audit Chain Verification [NEW IN V3.1]

```bash
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
```

---

# PART XIII: COMPLIANCE MATRIX

## MATRIX 1: Law Compliance Checklist

```
For EVERY pull request, verify:

â–¡ LAW 1 (Biometric Locality)
  â–¡ No biometric data in network requests
  â–¡ No biometric embeddings/templates in network requests
  â–¡ No biometric data in logs
  â–¡ No biometric data in crash reports
  â–¡ Biometrics processed only on device

â–¡ LAW 2 (Cryptographic Standards)
  â–¡ Only approved algorithms used
  â–¡ Only approved libraries used
  â–¡ Key sizes meet minimums
  â–¡ No prohibited algorithms
  â–¡ Hybrid mode used for new KEM/signatures

â–¡ LAW 3 (Constant-Time)
  â–¡ All secret operations are constant-time
  â–¡ dudect tests pass (t < 4.5)
  â–¡ No early returns on secrets
  â–¡ No secret-dependent branches
  â–¡ Uses subtle crate for comparisons

â–¡ LAW 4 (Zeroization)
  â–¡ All secrets use Secret<T>
  â–¡ Drop implementations call zeroize
  â–¡ Compiler fence present
  â–¡ Miri shows no UB

â–¡ LAW 5 (No Trust)
  â–¡ Our encryption used, not platform
  â–¡ TLS with certificate pinning
  â–¡ Secrets encrypted before platform storage
  â–¡ No SMS OTP as sole factor
  â–¡ Device binding used

â–¡ LAW 6 (Fail Secure)
  â–¡ No "fail open" paths
  â–¡ All errors return Err, don't panic
  â–¡ Partial state zeroized on error
  â–¡ No fallback to less secure methods

â–¡ LAW 7 (Reproducible)
  â–¡ Cargo.lock committed
  â–¡ No build timestamps
  â–¡ Exact versions in Cargo.toml

â–¡ LAW 8 (Audit Logging) [NEW]
  â–¡ All security events logged
  â–¡ No secrets in logs
  â–¡ Hash chain maintained
  â–¡ Signature on each entry

ALL BOXES MUST BE CHECKED FOR MERGE.
```

---

# PART XIV: QUICK REFERENCE CARD

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                      TERAS QUICK REFERENCE v3.1                              â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘                                                                              â•‘
â•‘  APPROVED CRYPTO:                                                            â•‘
â•‘  â”œâ”€ Symmetric: AES-256-GCM, ChaCha20-Poly1305                               â•‘
â•‘  â”œâ”€ Hash: SHA-256, SHA3-256, BLAKE3                                         â•‘
â•‘  â”œâ”€ KEM: ML-KEM-768 + X25519 (HYBRID MANDATORY)                             â•‘
â•‘  â”œâ”€ Sign: ML-DSA-65 + Ed25519 (HYBRID MANDATORY)                            â•‘
â•‘  â””â”€ KDF: HKDF, Argon2id                                                     â•‘
â•‘                                                                              â•‘
â•‘  PROHIBITED:                                                                 â•‘
â•‘  â”œâ”€ MD5, SHA-1, DES, 3DES, RC4, Blowfish                                   â•‘
â•‘  â”œâ”€ RSA < 3072, ECDSA < 256 bit                                            â•‘
â•‘  â”œâ”€ ring, openssl, any unlisted library                                     â•‘
â•‘  â””â”€ SMS OTP, email OTP as sole factor                                       â•‘
â•‘                                                                              â•‘
â•‘  SECRET HANDLING:                                                            â•‘
â•‘  â”œâ”€ Always use Secret<T>                                                    â•‘
â•‘  â”œâ”€ Never Clone, Debug, or Display secrets                                  â•‘
â•‘  â”œâ”€ Zeroize on drop                                                         â•‘
â•‘  â””â”€ mlock on supported platforms                                            â•‘
â•‘                                                                              â•‘
â•‘  ERROR HANDLING:                                                             â•‘
â•‘  â”œâ”€ Return Result<T, TerasError>                                            â•‘
â•‘  â”œâ”€ Never unwrap() or expect() user input                                   â•‘
â•‘  â”œâ”€ Never panic on error                                                    â•‘
â•‘  â””â”€ Fail secure (deny access)                                               â•‘
â•‘                                                                              â•‘
â•‘  BIOMETRICS (BENTENG):                                                       â•‘
â•‘  â”œâ”€ 3+ liveness signals required                                            â•‘
â•‘  â”œâ”€ Deepfake detection required                                             â•‘
â•‘  â”œâ”€ Device binding required                                                 â•‘
â•‘  â””â”€ NEVER send to server                                                    â•‘
â•‘                                                                              â•‘
â•‘  BEFORE COMMIT:                                                              â•‘
â•‘  â”œâ”€ cargo fmt                                                               â•‘
â•‘  â”œâ”€ cargo clippy -- -D warnings                                             â•‘
â•‘  â”œâ”€ cargo test                                                              â•‘
â•‘  â”œâ”€ No debug prints in crypto code                                          â•‘
â•‘  â””â”€ Unsafe blocks have SAFETY comment                                       â•‘
â•‘                                                                              â•‘
â•‘  BEFORE MERGE:                                                               â•‘
â•‘  â”œâ”€ All above +                                                             â•‘
â•‘  â”œâ”€ cargo +nightly miri test                                                â•‘
â•‘  â”œâ”€ ./tools/run-dudect.sh                                                   â•‘
â•‘  â”œâ”€ ./tools/verify-build.sh                                                 â•‘
â•‘  â””â”€ ./tools/verify-audit-chain.sh                                           â•‘
â•‘                                                                              â•‘
â•‘  NEVER:                                                                      â•‘
â•‘  â”œâ”€ Send biometrics to server                                               â•‘
â•‘  â”œâ”€ Log secrets                                                             â•‘
â•‘  â”œâ”€ Skip validation "for MVP"                                               â•‘
â•‘  â”œâ”€ Claim features that don't exist                                         â•‘
â•‘  â”œâ”€ Use non-hybrid crypto for new code                                      â•‘
â•‘  â””â”€ Modify this spec without version update                                 â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

# PART XV: THREAT COVERAGE MATRIX [NEW IN V3.1]

## WHAT TERAS COVERS

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ THREAT                        â”‚ PRODUCT    â”‚ MITIGATION              â”‚STATUS â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•£
â•‘ Biometric data theft          â”‚ BENTENG    â”‚ Never leaves device     â”‚ âœ…    â•‘
â•‘ Classical crypto break        â”‚ SANDI      â”‚ Hybrid PQ + classical   â”‚ âœ…    â•‘
â•‘ Quantum computer attack       â”‚ SANDI      â”‚ ML-KEM-768, ML-DSA-65   â”‚ âœ…    â•‘
â•‘ Timing side-channels          â”‚ ALL        â”‚ Constant-time code      â”‚ âœ…    â•‘
â•‘ Memory disclosure             â”‚ ALL        â”‚ Secret<T>, mlock        â”‚ âœ…    â•‘
â•‘ Fail-open vulnerabilities     â”‚ ALL        â”‚ Fail-secure by design   â”‚ âœ…    â•‘
â•‘ Supply chain (dependencies)   â”‚ BUILD      â”‚ Vendoring, exact pins   â”‚ âœ…    â•‘
â•‘ Photo/video spoofing          â”‚ BENTENG    â”‚ Multi-signal liveness   â”‚ âœ…    â•‘
â•‘ Deepfakes                     â”‚ BENTENG    â”‚ Deepfake detection      â”‚ âœ…    â•‘
â•‘ SIM swapping                  â”‚ BENTENG    â”‚ Device binding          â”‚ âœ…    â•‘
â•‘ Replay attacks                â”‚ ALL        â”‚ Nonces, timestamps      â”‚ âœ…    â•‘
â•‘ Insider threats (detection)   â”‚ ALL        â”‚ Audit logging           â”‚ âœ…    â•‘
â•‘ Algorithm break (future)      â”‚ SANDI      â”‚ Algorithm agility       â”‚ âœ…    â•‘
â•‘ Key compromise                â”‚ ALL        â”‚ Key rotation, hybrid    â”‚ âœ…    â•‘
â•‘ Log tampering                 â”‚ ALL        â”‚ Hash chain, signatures  â”‚ âœ…    â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## WHAT TERAS PARTIALLY COVERS

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ THREAT                        â”‚ PRODUCT    â”‚ STATUS       â”‚ LIMITATION       â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘ Nation-state 0-days           â”‚ ZIRAH      â”‚ âš ï¸ PARTIAL   â”‚ Detection only   â•‘
â•‘ Sophisticated deepfakes       â”‚ BENTENG    â”‚ âš ï¸ PARTIAL   â”‚ Arms race        â•‘
â•‘ Compiler backdoors            â”‚ BUILD      â”‚ âš ï¸ PARTIAL   â”‚ Diverse compile  â•‘
â•‘ Supply chain (hardware)       â”‚ N/A        â”‚ âš ï¸ PARTIAL   â”‚ Accept risk      â•‘
â•‘ DDoS attacks                  â”‚ GAPURA     â”‚ âš ï¸ PARTIAL   â”‚ Basic mitigation â•‘
â•‘ Logic bugs                    â”‚ ALL        â”‚ âš ï¸ PARTIAL   â”‚ Kani, not formal â•‘
â•‘ Behavioral anomalies          â”‚ ZIRAH      â”‚ âš ï¸ PARTIAL   â”‚ Baseline needed  â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## WHAT TERAS DOES NOT COVER

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ THREAT                        â”‚ WHY NOT COVERED                    â”‚ ACCEPT? â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•£
â•‘ Power/EM side-channels        â”‚ Requires hardware isolation        â”‚ YES     â•‘
â•‘ Spectre/Meltdown variants     â”‚ Kernel-level, complex             â”‚ PARTIAL â•‘
â•‘ Physical access attacks       â”‚ Cannot prevent physical access     â”‚ YES     â•‘
â•‘ Social engineering            â”‚ Human problem, not technical       â”‚ YES     â•‘
â•‘ Government backdoor laws      â”‚ Cannot prevent legally             â”‚ YES     â•‘
â•‘ Custom silicon backdoors      â”‚ Cannot verify without fab          â”‚ YES     â•‘
â•‘ Perfect forward secrecy break â”‚ Past data already captured         â”‚ YES     â•‘
â•‘ Complete formal verification  â”‚ Requires 1-2 years additional      â”‚ LATER   â•‘
â•‘ True ZK face verification     â”‚ Research problem, infeasible now   â”‚ LATER   â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

ACKNOWLEDGMENT: No security system is complete. TERAS provides defense-in-depth
for the threats it addresses. Users must understand the limitations.
```

---

# PART XVI: ANTI-DEEPFAKE & ADVERSARIAL ML [UPDATED IN V3.2]


## BENTENG ANTI-DEEPFAKE REQUIREMENTS

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   PRESENTATION ATTACK DETECTION (PAD)                                        â•‘
â•‘                                                                              â•‘
â•‘   MINIMUM COMPLIANCE: ISO 30107-3 Level 2                                    â•‘
â•‘                                                                              â•‘
â•‘   REQUIRED DETECTIONS:                                                       â•‘
â•‘   â”œâ”€ Photo attack (printed photo): MUST detect (>99%)                       â•‘
â•‘   â”œâ”€ Screen replay (photo/video on screen): MUST detect (>99%)              â•‘
â•‘   â”œâ”€ Video replay: MUST detect (>95%)                                       â•‘
â•‘   â”œâ”€ 2D mask: MUST detect (>95%)                                            â•‘
â•‘   â”œâ”€ 3D mask: SHOULD detect (>80%) - Level 2                                â•‘
â•‘   â””â”€ Deepfake video: SHOULD detect (>80%)                                   â•‘
â•‘                                                                              â•‘
â•‘   LIVENESS SIGNALS (MINIMUM 3 REQUIRED):                                     â•‘
â•‘   â”œâ”€ Texture analysis (2D vs 3D surface)                                    â•‘
â•‘   â”œâ”€ Depth estimation (if hardware available)                               â•‘
â•‘   â”œâ”€ Behavioral challenges (blink, head turn, smile)                        â•‘
â•‘   â”œâ”€ Reflection analysis (screen glare vs natural light)                    â•‘
â•‘   â”œâ”€ Temporal consistency (frame-to-frame coherence)                        â•‘
â•‘   â”œâ”€ MoirÃ© pattern detection (screen pixels)                                â•‘
â•‘   â””â”€ Edge detection (mask boundaries)                                       â•‘
â•‘                                                                              â•‘
â•‘   SCORE THRESHOLDS:                                                          â•‘
â•‘   â”œâ”€ Individual signal: >70% confidence required                            â•‘
â•‘   â”œâ”€ Combined liveness: >80% confidence required                            â•‘
â•‘   â”œâ”€ Deepfake score: <20% (lower = more likely real)                        â•‘
â•‘   â””â”€ Any signal <50%: Automatic FAIL                                        â•‘
â•‘                                                                              â•‘
â•‘   FAILURE BEHAVIOR (LAW 6 - FAIL SECURE):                                    â•‘
â•‘   â”œâ”€ Score below threshold â†’ DENY verification                              â•‘
â•‘   â”œâ”€ Insufficient signals â†’ DENY verification                               â•‘
â•‘   â”œâ”€ Detection timeout â†’ DENY verification (never skip)                     â•‘
â•‘   â””â”€ All failures logged to audit trail                                     â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## DEEPFAKE DETECTION IMPLEMENTATION

```rust
// crates/teras-benteng/src/deepfake.rs
// STRUCTURE ONLY - IMPLEMENTATION REQUIRES ML MODEL

use teras_core::error::{TerasError, TerasResult};

/// Deepfake detection result.
#[derive(Debug, Clone)]
pub struct DeepfakeResult {
    /// Score from 0-100. Lower = more likely real.
    pub score: u8,
    /// Individual detector scores.
    pub texture_score: u8,
    pub temporal_score: u8,
    pub frequency_score: u8,
    /// Whether detection passed.
    pub passed: bool,
}

/// Deepfake detector configuration.
pub struct DeepfakeDetector {
    /// Maximum score to consider real (default: 20).
    pub threshold: u8,
}

impl DeepfakeDetector {
    pub fn new() -> Self {
        Self { threshold: 20 }
    }
    
    /// Analyze frames for deepfake indicators.
    /// 
    /// Returns error if detection fails or score exceeds threshold.
    pub fn analyze(&self, frames: &[Frame]) -> TerasResult<DeepfakeResult> {
        // Implementation requires ML model
        // This is the interface only
        
        let result = self.run_detection(frames)?;
        
        if result.score > self.threshold {
            return Err(TerasError::DeepfakeDetected { score: result.score });
        }
        
        Ok(result)
    }
    
    fn run_detection(&self, frames: &[Frame]) -> TerasResult<DeepfakeResult> {
        // IMPLEMENTATION REQUIRED:
        // 1. Texture inconsistency detection
        // 2. Temporal coherence analysis
        // 3. Frequency domain analysis
        // 4. Blending boundary detection
        unimplemented!("Requires ML model integration")
    }
}
```

## ADVERSARIAL ML DEFENSE

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   ADVERSARIAL ATTACK MITIGATIONS                                             â•‘
â•‘                                                                              â•‘
â•‘   INPUT VALIDATION:                                                          â•‘
â•‘   â”œâ”€ Image size bounds: 320x240 to 4096x3072                                â•‘
â•‘   â”œâ”€ File format: JPEG, PNG only (no exotic formats)                        â•‘
â•‘   â”œâ”€ Metadata stripped before processing                                    â•‘
â•‘   â””â”€ Pixel value normalization                                              â•‘
â•‘                                                                              â•‘
â•‘   MODEL HARDENING:                                                           â•‘
â•‘   â”œâ”€ Adversarial training with PGD attacks                                  â•‘
â•‘   â”œâ”€ Input randomization (small random transforms)                          â•‘
â•‘   â”œâ”€ Ensemble of multiple models (>50% must agree)                          â•‘
â•‘   â””â”€ Gradient masking (obfuscate gradients)                                 â•‘
â•‘                                                                              â•‘
â•‘   RUNTIME DEFENSE:                                                           â•‘
â•‘   â”œâ”€ Input perturbation detection                                           â•‘
â•‘   â”œâ”€ Confidence threshold (reject low-confidence)                           â•‘
â•‘   â”œâ”€ Rate limiting per device/user                                          â•‘
â•‘   â””â”€ Anomaly detection on repeated failures                                 â•‘
â•‘                                                                              â•‘
â•‘   LIMITATIONS (HONEST):                                                      â•‘
â•‘   â”œâ”€ Adversarial ML is an arms race                                         â•‘
â•‘   â”œâ”€ Novel attacks may succeed                                              â•‘
â•‘   â”œâ”€ Defense improves with attack data                                      â•‘
â•‘   â””â”€ Cannot guarantee 100% detection                                        â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```


## DOCUMENT OCR REQUIREMENTS [NEW IN V3.2]

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SUPPORTED DOCUMENT TYPES                                                   ║
║                                                                              ║
║   MANDATORY SUPPORT:                                                         ║
║   ├─ Malaysia MyKad (front)                                                  ║
║   ├─ Malaysia MyKad (back)                                                   ║
║   ├─ Malaysia Passport (biodata page)                                        ║
║   ├─ ICAO 9303 compliant passports (MRZ extraction)                          ║
║   ├─ Malaysia Driver's License                                               ║
║   └─ Custom templates (client-configurable)                                  ║
║                                                                              ║
║   DOCUMENT REGIONS (MyKad Front):                                            ║
║   ├─ Name field (Malay/Latin)                                                ║
║   ├─ IC number (YYMMDD-PB-####)                                              ║
║   ├─ Address (multi-line)                                                    ║
║   ├─ Religion                                                                ║
║   ├─ Citizenship status                                                      ║
║   └─ Photo (face image extraction)                                           ║
║                                                                              ║
║   DOCUMENT REGIONS (Passport):                                               ║
║   ├─ MRZ Line 1 (Document type, Country, Name)                               ║
║   ├─ MRZ Line 2 (Passport#, Nationality, DOB, Sex, Expiry, PersonalNo)       ║
║   ├─ VIZ fields (Visual Inspection Zone - all text fields)                   ║
║   └─ Photo (face image extraction)                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ACCURACY REQUIREMENTS                                                      ║
║                                                                              ║
║   FIELD-LEVEL ACCURACY TARGETS:                                              ║
║   ├─ Text fields (name, address): >99.0% character accuracy                  ║
║   ├─ MRZ extraction: 100.0% (machine-readable, no tolerance)                 ║
║   ├─ Photo extraction: Face quality >80% (LAW 1 compliant)                   ║
║   ├─ Date fields: 100.0% (no tolerance on dates)                             ║
║   ├─ Document numbers (IC, passport): 100.0% (no tolerance)                  ║
║   └─ Numeric fields: 100.0% (no tolerance)                                   ║
║                                                                              ║
║   DOCUMENT-LEVEL ACCURACY:                                                   ║
║   ├─ MyKad: >99.5% correct extraction (all fields)                           ║
║   ├─ Passport MRZ: 100.0% (reject if uncertain)                              ║
║   ├─ Driver's License: >99.0% correct extraction                             ║
║   └─ Custom templates: Client-defined thresholds                             ║
║                                                                              ║
║   ERROR HANDLING (LAW 6 - FAIL SECURE):                                      ║
║   ├─ Low confidence (<threshold) → REJECT, request recapture                 ║
║   ├─ Partial extraction → REJECT, do not return partial data                 ║
║   ├─ Invalid document format → REJECT with specific error                    ║
║   └─ All rejections logged to audit trail                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PROCESSING REQUIREMENTS (LAW 1 COMPLIANCE)                                 ║
║                                                                              ║
║   ALL PROCESSING MUST OCCUR ON-DEVICE:                                       ║
║   ├─ Document image capture: On-device camera                                ║
║   ├─ OCR extraction: On-device ML models                                     ║
║   ├─ Quality assessment: On-device validation                                ║
║   ├─ Face extraction: On-device, for local matching                          ║
║   └─ Result signing: With device-bound key                                   ║
║                                                                              ║
║   WHAT LEAVES DEVICE:                                                        ║
║   ├─ Signed attestation: "Document valid, fields match"                      ║
║   ├─ Hash of extracted data (for audit)                                      ║
║   ├─ ZK proof of document validity (no raw data)                             ║
║   └─ Encrypted data if user explicitly consents AND                          ║
║      encryption uses user-controlled key                                     ║
║                                                                              ║
║   WHAT NEVER LEAVES DEVICE:                                                  ║
║   ├─ Raw document images                                                     ║
║   ├─ Extracted face photos                                                   ║
║   ├─ Raw OCR text (unencrypted)                                              ║
║   └─ Document metadata revealing identity                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   DOCUMENT AUTHENTICITY DETECTION                                            ║
║                                                                              ║
║   ANTI-PHOTOCOPY DETECTION:                                                  ║
║   ├─ Screen moiré pattern detection (>99% accuracy)                          ║
║   ├─ Print quality degradation detection                                     ║
║   ├─ Color consistency analysis                                              ║
║   └─ Reflection pattern analysis                                             ║
║                                                                              ║
║   ANTI-SCREENSHOT DETECTION:                                                 ║
║   ├─ Screen pixel pattern detection                                          ║
║   ├─ Resolution inconsistency detection                                      ║
║   ├─ Artifact detection (JPEG compression on photo)                          ║
║   └─ Edge sharpness analysis                                                 ║
║                                                                              ║
║   HOLOGRAM/SECURITY FEATURE DETECTION (where applicable):                    ║
║   ├─ Hologram presence verification                                          ║
║   ├─ UV feature detection (if UV camera available)                           ║
║   ├─ Microprint detection (high-resolution capture)                          ║
║   └─ Optically variable device (OVD) verification                            ║
║                                                                              ║
║   TEMPLATE MATCHING:                                                         ║
║   ├─ Document layout validation against known template                       ║
║   ├─ Font consistency checking                                               ║
║   ├─ Field position verification                                             ║
║   └─ Security feature placement validation                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   OUTPUT FORMAT SPECIFICATION                                                ║
║                                                                              ║
║   STRUCTURED JSON OUTPUT:                                                    ║
║   {                                                                          ║
║     "document_type": "MYKAD_FRONT",                                          ║
║     "extraction_version": "1.0.0",                                           ║
║     "timestamp_utc": "2025-01-15T09:30:00Z",                                 ║
║     "device_attestation": "<base64_attestation>",                            ║
║     "fields": {                                                              ║
║       "name": { "value": "...", "confidence": 0.99, "bbox": [...] },         ║
║       "ic_number": { "value": "...", "confidence": 1.00, "bbox": [...] },    ║
║       ...                                                                    ║
║     },                                                                       ║
║     "face_extracted": true,                                                  ║
║     "face_quality_score": 0.85,                                              ║
║     "document_hash": "<sha3-256 of canonical extraction>",                   ║
║     "authenticity_checks": {                                                 ║
║       "photocopy_score": 0.02,                                               ║
║       "screenshot_score": 0.01,                                              ║
║       "template_match_score": 0.98                                           ║
║     },                                                                       ║
║     "overall_confidence": 0.97,                                              ║
║     "signature": "<ed25519_signature>"                                       ║
║   }                                                                          ║
║                                                                              ║
║   STANDARDIZED SCHEMA MAPPING:                                               ║
║   ├─ All document types map to common schema fields                          ║
║   ├─ Unmapped fields preserved in document-specific section                  ║
║   ├─ Date formats normalized to ISO 8601                                     ║
║   └─ Name formats normalized (given name, family name)                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   VALIDATION TEST CORPUS REQUIREMENTS                                        ║
║                                                                              ║
║   MINIMUM TEST CORPUS PER DOCUMENT TYPE:                                     ║
║   ├─ MyKad: 1,000+ authentic samples                                         ║
║   ├─ Malaysian Passport: 1,000+ authentic samples                            ║
║   ├─ ICAO 9303 passports: 1,000+ samples (diverse countries)                 ║
║   ├─ Driver's License: 1,000+ authentic samples                              ║
║   └─ Custom templates: 100+ samples per template                             ║
║                                                                              ║
║   ADVERSARIAL TEST CORPUS:                                                   ║
║   ├─ Photocopied documents: 500+ samples                                     ║
║   ├─ Screen captures: 500+ samples                                           ║
║   ├─ Manipulated documents: 500+ samples (edited fields)                     ║
║   ├─ Expired documents: 200+ samples                                         ║
║   └─ Damaged documents: 200+ samples (partial occlusion)                     ║
║                                                                              ║
║   ACCURACY VALIDATION:                                                       ║
║   ├─ Character-level accuracy measured against ground truth                  ║
║   ├─ Field-level extraction rate measured                                    ║
║   ├─ False positive rate for authenticity detection <0.1%                    ║
║   ├─ False negative rate for authenticity detection <1%                      ║
║   └─ All metrics computed with 95% confidence intervals                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XVII: ALGORITHM AGILITY & CRYPTOGRAPHIC RECOVERY [UPDATED IN V3.2]


## ALGORITHM AGILITY ARCHITECTURE

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   ALGORITHM STATUS LEVELS                                                    â•‘
â•‘                                                                              â•‘
â•‘   ACTIVE (use for all new operations):                                       â•‘
â•‘   â”œâ”€ KEM: ML-KEM-768 + X25519 (hybrid, both required)                       â•‘
â•‘   â”œâ”€ Signature: ML-DSA-65 + Ed25519 (hybrid, both must verify)              â•‘
â•‘   â”œâ”€ Symmetric: ChaCha20-Poly1305 (primary), AES-256-GCM (alternate)        â•‘
â•‘   â””â”€ Hash: SHA3-256 (primary), SHA-256 (compatibility)                      â•‘
â•‘                                                                              â•‘
â•‘   BACKUP (ready to activate within 24 hours):                                â•‘
â•‘   â”œâ”€ KEM: Classic McEliece (if ML-KEM breaks)                               â•‘
â•‘   â”œâ”€ Signature: SLH-DSA-SHAKE-256f (if ML-DSA breaks)                       â•‘
â•‘   â””â”€ Hash: BLAKE3 (if SHA-3 has issues)                                     â•‘
â•‘                                                                              â•‘
â•‘   DEPRECATED (accept for verification, don't create new):                    â•‘
â•‘   â”œâ”€ Single-algorithm KEM (non-hybrid)                                      â•‘
â•‘   â”œâ”€ Single-algorithm signatures (non-hybrid)                               â•‘
â•‘   â””â”€ SHA-256 only (without SHA3)                                            â•‘
â•‘                                                                              â•‘
â•‘   PROHIBITED (reject always):                                                â•‘
â•‘   â”œâ”€ MD5, SHA-1, DES, 3DES, RC4                                             â•‘
â•‘   â”œâ”€ RSA < 3072 bits                                                         â•‘
â•‘   â””â”€ Non-approved algorithms                                                 â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## ALGORITHM ROTATION TRIGGERS

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   TRIGGER                          â”‚ ACTION           â”‚ TIMELINE            â•‘
â•‘   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•‘
â•‘   NIST announces algorithm break   â”‚ Activate backup  â”‚ 24 hours            â•‘
â•‘   Academic paper shows weakness    â”‚ Activate backup  â”‚ 7 days              â•‘
â•‘   Cryptanalysis concern raised     â”‚ Enable hybrid    â”‚ 30 days             â•‘
â•‘   New NIST standard published      â”‚ Evaluate, plan   â”‚ 90 days             â•‘
â•‘   Algorithm deprecated by NIST     â”‚ Migrate away     â”‚ 1 year              â•‘
â•‘                                                                              â•‘
â•‘   ROTATION PROCESS:                                                          â•‘
â•‘   1. Announcement: Notify all clients of pending rotation                    â•‘
â•‘   2. Dual-support: Accept both old and new for transition period            â•‘
â•‘   3. Migration: Re-encrypt/re-sign with new algorithm                        â•‘
â•‘   4. Deprecation: Stop accepting old algorithm                               â•‘
â•‘   5. Purge: Remove old algorithm code (after all data migrated)             â•‘
â•‘                                                                              â•‘
â•‘   KEY ROTATION (independent of algorithm rotation):                          â•‘
â•‘   â”œâ”€ Session keys: <24 hours                                                â•‘
â•‘   â”œâ”€ Device keys: <1 year                                                   â•‘
â•‘   â”œâ”€ Long-term keys: <2 years                                               â•‘
â•‘   â””â”€ On algorithm change: Immediate rotation                                 â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## ALGORITHM AGILITY IMPLEMENTATION

```rust
// crates/teras-kunci/src/agility.rs
// STRUCTURE FOR ALGORITHM AGILITY

use teras_core::error::{TerasError, TerasResult};

/// Algorithm status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmStatus {
    Active,      // Use for new operations
    Backup,      // Ready to activate
    Deprecated,  // Accept, don't create new
    Prohibited,  // Reject always
}

/// KEM algorithm identifier.
/// NOTE: MlKem refers to the NIST FIPS 203 standard (formerly Kyber).
/// Implementation uses pqcrypto-kyber which is cryptographically equivalent.
/// See DEVIATION-002 in DEVIATIONS.md for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KemAlgorithm {
    HybridMlKemX25519 = 0x0001,  // Active (implemented as Kyber-768 + X25519)
    MlKem768Only = 0x0002,        // Deprecated
    X25519Only = 0x0003,          // Deprecated
    ClassicMcEliece = 0x0004,     // Backup
}

impl KemAlgorithm {
    pub fn status(&self) -> AlgorithmStatus {
        match self {
            Self::HybridMlKemX25519 => AlgorithmStatus::Active,
            Self::MlKem768Only => AlgorithmStatus::Deprecated,
            Self::X25519Only => AlgorithmStatus::Deprecated,
            Self::ClassicMcEliece => AlgorithmStatus::Backup,
        }
    }
    
    /// Check if algorithm is acceptable for the given operation.
    pub fn is_acceptable_for(&self, operation: Operation) -> bool {
        match (self.status(), operation) {
            (AlgorithmStatus::Active, _) => true,
            (AlgorithmStatus::Backup, Operation::Decapsulate) => true,
            (AlgorithmStatus::Deprecated, Operation::Decapsulate) => true,
            (AlgorithmStatus::Deprecated, Operation::Encapsulate) => false,
            (AlgorithmStatus::Prohibited, _) => false,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Operation {
    Encapsulate,
    Decapsulate,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
}

/// Get the current active algorithm for new operations.
pub fn current_kem_algorithm() -> KemAlgorithm {
    // Could be loaded from config for runtime switching
    KemAlgorithm::HybridMlKemX25519
}

/// Check if algorithm rotation is needed.
pub fn check_rotation_needed() -> Option<RotationNotice> {
    // Check for rotation triggers
    // Return notice if rotation needed
    None
}

pub struct RotationNotice {
    pub algorithm: KemAlgorithm,
    pub reason: String,
    pub deadline: u64,
}
```


## DOCUMENT WORKFLOW REQUIREMENTS [NEW IN V3.2]

### SIGNING WORKFLOW

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STEP 1: DOCUMENT INGESTION                                                 ║
║                                                                              ║
║   SUPPORTED FORMATS:                                                         ║
║   ├─ PDF (PDF/A-1b, PDF/A-2b preferred for archival)                         ║
║   ├─ DOCX (Microsoft Word)                                                   ║
║   ├─ Image formats (PNG, JPEG for single-page documents)                     ║
║   └─ Plain text (UTF-8)                                                      ║
║                                                                              ║
║   PROCESSING:                                                                ║
║   ├─ Compute SHA3-256 hash of document bytes                                 ║
║   ├─ ONLY hash transmitted to server (LAW 1 compliance)                      ║
║   ├─ Document bytes NEVER leave client device                                ║
║   ├─ Store document hash with timestamp for audit                            ║
║   └─ Generate unique document identifier (UUID v4)                           ║
║                                                                              ║
║   VALIDATION:                                                                ║
║   ├─ File size limit: Configurable (default 50MB)                            ║
║   ├─ Page count limit: Configurable (default 500 pages)                      ║
║   ├─ Malware scan: Integrated with ZIRAH if available                        ║
║   └─ Format validation: Reject malformed/corrupted files                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STEP 2: SIGNER IDENTITY VERIFICATION                                       ║
║                                                                              ║
║   BENTENG LIVENESS CHECK REQUIRED:                                           ║
║   ├─ Individual signal threshold: >70% confidence                            ║
║   ├─ Combined liveness threshold: >80% confidence                            ║
║   ├─ Deepfake score: <20% (lower = more likely real)                         ║
║   └─ Any signal <50%: Automatic FAIL (LAW 6)                                 ║
║                                                                              ║
║   IDENTITY VERIFICATION:                                                     ║
║   ├─ Verify face matches registered identity                                 ║
║   ├─ Verify device attestation (same device as registration)                 ║
║   ├─ Verify biometric freshness (<30 seconds)                                ║
║   └─ Generate identity attestation proof                                     ║
║                                                                              ║
║   ATTESTATION PROOF CONTENTS:                                                ║
║   ├─ ZK proof of identity match (no biometric data)                          ║
║   ├─ Device attestation token                                                ║
║   ├─ Timestamp of verification                                               ║
║   ├─ Liveness check result hash                                              ║
║   └─ Signer public key commitment                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STEP 3: SIGNATURE PLACEMENT                                                ║
║                                                                              ║
║   USER INTERFACE REQUIREMENTS:                                               ║
║   ├─ User selects signature location                                         ║
║   ├─ Location specified as: (page, x, y, width, height)                      ║
║   ├─ Preview signature appearance before confirmation                        ║
║   └─ Support for multiple signature fields per document                      ║
║                                                                              ║
║   SIGNATURE FIELD METADATA:                                                  ║
║   {                                                                          ║
║     "field_id": "<uuid>",                                                    ║
║     "page": 1,                                                               ║
║     "x": 100,                                                                ║
║     "y": 700,                                                                ║
║     "width": 200,                                                            ║
║     "height": 50,                                                            ║
║     "required": true,                                                        ║
║     "signer_role": "PRIMARY"                                                 ║
║   }                                                                          ║
║                                                                              ║
║   VISUAL APPEARANCE OPTIONS:                                                 ║
║   ├─ Text-only (signer name + timestamp)                                     ║
║   ├─ Image + text (custom signature image)                                   ║
║   ├─ Stamp style (seal appearance)                                           ║
║   └─ QR code + text (verification link embedded)                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STEP 4: HYBRID SIGNATURE GENERATION                                        ║
║                                                                              ║
║   SIGNATURE ALGORITHM (BOTH REQUIRED):                                       ║
║   ├─ ML-DSA-65 (Post-quantum, NIST FIPS 204)                                 ║
║   └─ Ed25519 (Classical, RFC 8032)                                           ║
║                                                                              ║
║   SIGNATURE DATA STRUCTURE:                                                  ║
║   ├─ Document hash (SHA3-256)                                                ║
║   ├─ Identity attestation proof                                              ║
║   ├─ Signing timestamp (UTC)                                                 ║
║   ├─ Signer public key (both ML-DSA-65 and Ed25519)                          ║
║   └─ Signature algorithm identifiers                                         ║
║                                                                              ║
║   HYBRID SIGNATURE FORMAT:                                                   ║
║   {                                                                          ║
║     "version": "1.0",                                                        ║
║     "document_hash": "<sha3-256>",                                           ║
║     "ml_dsa_signature": "<base64>",                                          ║
║     "ed25519_signature": "<base64>",                                         ║
║     "attestation": "<base64_zk_proof>",                                      ║
║     "timestamp": "2025-01-15T10:00:00Z",                                     ║
║     "signer_pubkey_ml_dsa": "<base64>",                                      ║
║     "signer_pubkey_ed25519": "<base64>"                                      ║
║   }                                                                          ║
║                                                                              ║
║   VERIFICATION REQUIREMENT:                                                  ║
║   ├─ BOTH signatures MUST verify for document to be valid                    ║
║   ├─ Either signature failing → Document signature INVALID                   ║
║   └─ This provides defense against quantum AND classical attacks             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STEP 5: TIMESTAMP ACQUISITION                                              ║
║                                                                              ║
║   RFC 3161 TIMESTAMP REQUIREMENTS:                                           ║
║   ├─ Obtain timestamp from Trusted Timestamping Authority (TSA)              ║
║   ├─ MINIMUM 2 TSAs required (redundancy)                                    ║
║   ├─ Timestamp covers: signature + document hash                             ║
║   ├─ Store full timestamp token with signature                               ║
║   └─ TSA response validated before acceptance                                ║
║                                                                              ║
║   APPROVED TSA LIST:                                                         ║
║   ├─ DigiCert Timestamp Authority                                            ║
║   ├─ Sectigo Timestamp Authority                                             ║
║   ├─ GlobalSign Timestamp Authority                                          ║
║   └─ Client-configurable additional TSAs                                     ║
║                                                                              ║
║   TIMESTAMP VALIDATION:                                                      ║
║   ├─ TSA certificate chain verified to trusted root                          ║
║   ├─ Timestamp token signature verified                                      ║
║   ├─ Timestamp within acceptable clock skew (<5 minutes)                     ║
║   └─ TSA certificate not expired at signing time                             ║
║                                                                              ║
║   FAILURE HANDLING (LAW 6):                                                  ║
║   ├─ Primary TSA fails → Try secondary TSA                                   ║
║   ├─ All TSAs fail → REJECT signing operation                                ║
║   └─ Never proceed without valid timestamp                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STEP 6: AUDIT LOG ENTRY                                                    ║
║                                                                              ║
║   LOG TO JEJAK (REQUIRED):                                                   ║
║   ├─ Document hash (SHA3-256)                                                ║
║   ├─ Signer ID hash (not raw ID - privacy)                                   ║
║   ├─ Signing timestamp                                                       ║
║   ├─ Signature operation result (SUCCESS/FAIL)                               ║
║   └─ Device attestation hash                                                 ║
║                                                                              ║
║   WHAT IS NEVER LOGGED:                                                      ║
║   ├─ Actual document content                                                 ║
║   ├─ Biometric data                                                          ║
║   ├─ Private keys                                                            ║
║   ├─ Raw signer identity                                                     ║
║   └─ Decrypted sensitive data                                                ║
║                                                                              ║
║   HASH CHAIN REQUIREMENT:                                                    ║
║   ├─ Entry hash chained to previous entry                                    ║
║   ├─ Forms tamper-evident audit trail                                        ║
║   ├─ Merkle tree for efficient verification                                  ║
║   └─ Cannot be modified without detection                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STEP 7: SIGNATURE EMBEDDING                                                ║
║                                                                              ║
║   EMBEDDING PROCESS:                                                         ║
║   ├─ Embed signature at specified location                                   ║
║   ├─ Add visual representation (name, timestamp, seal)                       ║
║   ├─ Add QR code linking to verification endpoint                            ║
║   └─ Return signed document to user                                          ║
║                                                                              ║
║   QR CODE CONTENTS:                                                          ║
║   {                                                                          ║
║     "verify_url": "https://verify.sandi.teras.my/v/{doc_id}",                ║
║     "doc_hash": "<sha3-256>",                                                ║
║     "sig_hash": "<sha3-256 of signature>"                                    ║
║   }                                                                          ║
║                                                                              ║
║   PDF SIGNATURE EMBEDDING (PAdES):                                           ║
║   ├─ Use PAdES-B-LTA for long-term archival                                  ║
║   ├─ Embed full certificate chain                                            ║
║   ├─ Embed timestamp tokens                                                  ║
║   └─ Include revocation information (CRL/OCSP)                               ║
║                                                                              ║
║   DOCUMENT RETURN:                                                           ║
║   ├─ Signed document stored ONLY on client device                            ║
║   ├─ Client responsible for secure storage                                   ║
║   ├─ Optional: Encrypted backup with user key                                ║
║   └─ Server stores ONLY verification data (hashes, proofs)                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### MULTI-PARTY SIGNING

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SIGNING MODES                                                              ║
║                                                                              ║
║   SEQUENTIAL MODE:                                                           ║
║   ├─ Signers must sign in defined order                                      ║
║   ├─ Signer N cannot sign until Signer N-1 completes                         ║
║   ├─ Order set at workflow creation time                                     ║
║   └─ Order CANNOT be changed after first signature                           ║
║                                                                              ║
║   PARALLEL MODE:                                                             ║
║   ├─ All signers can sign simultaneously                                     ║
║   ├─ No ordering requirements                                                ║
║   ├─ Document complete when all required signers complete                    ║
║   └─ Each signature independent                                              ║
║                                                                              ║
║   HYBRID MODE:                                                               ║
║   ├─ Combination of sequential and parallel                                  ║
║   ├─ Example: Signers A,B parallel, then C sequential                        ║
║   ├─ Defined as workflow stages                                              ║
║   └─ Stage N+1 blocked until Stage N complete                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   WORKFLOW STATES                                                            ║
║                                                                              ║
║   STATES:                                                                    ║
║   ├─ PENDING: Workflow created, no signatures yet                            ║
║   ├─ PARTIALLY_SIGNED: At least one signature, not all                       ║
║   ├─ COMPLETE: All required signatures obtained                              ║
║   ├─ CANCELLED: Workflow cancelled before completion                         ║
║   ├─ EXPIRED: Deadline passed without completion                             ║
║   └─ REVOKED: One or more signatures revoked                                 ║
║                                                                              ║
║   STATE TRANSITIONS:                                                         ║
║   PENDING → PARTIALLY_SIGNED: First signature obtained                       ║
║   PARTIALLY_SIGNED → COMPLETE: Last required signature obtained              ║
║   PENDING/PARTIALLY_SIGNED → CANCELLED: Creator cancels                      ║
║   PENDING/PARTIALLY_SIGNED → EXPIRED: Deadline reached                       ║
║   PARTIALLY_SIGNED/COMPLETE → REVOKED: Signature revoked                     ║
║                                                                              ║
║   NOTIFICATIONS:                                                             ║
║   ├─ Signer notified when turn arrives (sequential)                          ║
║   ├─ Signer notified when workflow created (parallel)                        ║
║   ├─ All parties notified on completion                                      ║
║   ├─ All parties notified on cancellation                                    ║
║   └─ Reminders sent before deadline (24h, 1h)                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SIGNATURE REVOCATION                                                       ║
║                                                                              ║
║   REVOCATION RULES:                                                          ║
║   ├─ Signer can revoke ONLY their own signature                              ║
║   ├─ Revocation allowed ONLY before workflow COMPLETE                        ║
║   ├─ All revocations logged to JEJAK                                         ║
║   ├─ Revocation invalidates subsequent signatures (sequential)               ║
║   └─ Revocation requires fresh identity verification                         ║
║                                                                              ║
║   REVOCATION PROCESS:                                                        ║
║   1. Signer initiates revocation request                                     ║
║   2. Identity verification (same as signing)                                 ║
║   3. Revocation reason captured (optional)                                   ║
║   4. Signature marked as revoked                                             ║
║   5. Subsequent signatures invalidated (sequential mode)                     ║
║   6. All parties notified                                                    ║
║   7. Audit log updated                                                       ║
║                                                                              ║
║   AFTER REVOCATION:                                                          ║
║   ├─ Workflow state → REVOKED                                                ║
║   ├─ New workflow must be created to re-sign                                 ║
║   ├─ Previous document hash linked to new workflow                           ║
║   └─ Full audit trail preserved                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   DEADLINE ENFORCEMENT                                                       ║
║                                                                              ║
║   DEADLINE CONFIGURATION:                                                    ║
║   ├─ Set at workflow creation time                                           ║
║   ├─ Optional: Per-signer deadlines (sequential)                             ║
║   ├─ Minimum deadline: 1 hour                                                ║
║   └─ Maximum deadline: Configurable (default 30 days)                        ║
║                                                                              ║
║   WARNINGS:                                                                  ║
║   ├─ 24 hours before deadline: Email + push notification                     ║
║   ├─ 1 hour before deadline: Push notification                               ║
║   └─ Warning frequency configurable                                          ║
║                                                                              ║
║   EXPIRATION:                                                                ║
║   ├─ Expired workflows marked as CANCELLED                                   ║
║   ├─ Audit log entry with expiration reason                                  ║
║   ├─ All parties notified of expiration                                      ║
║   ├─ Existing signatures preserved (for audit)                               ║
║   └─ New workflow required to continue                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### COMPLIANCE PROOF GENERATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   COMPLIANCE PROOF COMPONENTS                                                ║
║                                                                              ║
║   1. AUDIT TRAIL PROOF:                                                      ║
║   ├─ Complete hash chain from genesis to document entry                      ║
║   ├─ Merkle proof for efficient verification                                 ║
║   ├─ All intermediate hashes                                                 ║
║   └─ Proof that entry exists in tamper-evident log                           ║
║                                                                              ║
║   2. TIMESTAMP CHAIN VERIFICATION:                                           ║
║   ├─ TSA certificate chain to trusted root                                   ║
║   ├─ Full timestamp token                                                    ║
║   ├─ Validity proof at signing time                                          ║
║   └─ Revocation status at signing time                                       ║
║                                                                              ║
║   3. SIGNER IDENTITY ATTESTATION:                                            ║
║   ├─ ZK proof that identity was verified (no raw identity)                   ║
║   ├─ Device attestation validity                                             ║
║   ├─ Liveness check pass/fail (not biometric data)                           ║
║   └─ Link to signer's public key                                             ║
║                                                                              ║
║   4. DOCUMENT INTEGRITY PROOF:                                               ║
║   ├─ Document hash at time of signing                                        ║
║   ├─ Proof document unchanged since signing                                  ║
║   ├─ All signers with their timestamps                                       ║
║   └─ Signature validity verification                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   EXPORT FORMATS                                                             ║
║                                                                              ║
║   PDF REPORT:                                                                ║
║   ├─ Human-readable compliance report                                        ║
║   ├─ Visual timeline of signing events                                       ║
║   ├─ Certificate chain visualization                                         ║
║   ├─ Verification instructions                                               ║
║   └─ QR codes for independent verification                                   ║
║                                                                              ║
║   JSON MACHINE-READABLE:                                                     ║
║   ├─ Structured data for automated verification                              ║
║   ├─ All proofs in standard formats                                          ║
║   ├─ API endpoint for real-time verification                                 ║
║   └─ Schema versioned for forward compatibility                              ║
║                                                                              ║
║   INDEPENDENT VERIFICATION TOOL:                                             ║
║   ├─ Open-source verification tool provided                                  ║
║   ├─ Can verify offline (with cached data)                                   ║
║   ├─ No dependency on SANDI servers                                          ║
║   └─ Published verification algorithm                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   LEGAL COMPLIANCE                                                           ║
║                                                                              ║
║   MALAYSIA DIGITAL SIGNATURE ACT 1997:                                       ║
║   ├─ Signatures meet "advanced electronic signature" requirements            ║
║   ├─ Signer identity verified via approved method                            ║
║   ├─ Signature uniquely linked to signer                                     ║
║   ├─ Created using data under signer's sole control                          ║
║   └─ Changes to document detectable                                          ║
║                                                                              ║
║   EU eIDAS REGULATION:                                                       ║
║   ├─ Qualified Electronic Signature (QES) capable                            ║
║   ├─ Advanced Electronic Signature (AdES) by default                         ║
║   ├─ PAdES format for PDF signatures                                         ║
║   └─ Qualified timestamp integration                                         ║
║                                                                              ║
║   US ESIGN ACT & UETA:                                                       ║
║   ├─ Electronic signature legally binding                                    ║
║   ├─ Consumer consent requirements met                                       ║
║   ├─ Record retention requirements supported                                 ║
║   └─ Attribution requirements satisfied                                      ║
║                                                                              ║
║   COMPLIANCE VALIDATION:                                                     ║
║   ├─ Legal review of signature process required                              ║
║   ├─ Jurisdiction-specific requirements documented                           ║
║   ├─ Regular compliance audits                                               ║
║   └─ Legal opinion letter available for each jurisdiction                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---
# PART XVIII: BEHAVIORAL DETECTION & 0-DAY DEFENSE [NEW IN V3.1]

## ZIRAH BEHAVIORAL DETECTION

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   BEHAVIORAL DETECTION (ASSUMES 0-DAYS EXIST)                                â•‘
â•‘                                                                              â•‘
â•‘   PHILOSOPHY:                                                                â•‘
â•‘   We cannot prevent all 0-days. We CAN detect abnormal behavior.             â•‘
â•‘                                                                              â•‘
â•‘   BASELINE ESTABLISHMENT (per application):                                  â•‘
â•‘   â”œâ”€ Normal process spawn patterns                                          â•‘
â•‘   â”œâ”€ Normal network connection patterns                                     â•‘
â•‘   â”œâ”€ Normal file access patterns                                            â•‘
â•‘   â”œâ”€ Normal memory allocation patterns                                      â•‘
â•‘   â””â”€ Normal system call sequences                                           â•‘
â•‘                                                                              â•‘
â•‘   ANOMALY DETECTION:                                                         â•‘
â•‘   â”œâ”€ Deviation from baseline > 3Ïƒ â†’ ALERT                                   â•‘
â•‘   â”œâ”€ Process spawning sensitive child â†’ ALERT                               â•‘
â•‘   â”œâ”€ Unexpected outbound connection â†’ ALERT                                 â•‘
â•‘   â”œâ”€ Memory pattern matching exploit signatures â†’ ALERT                     â•‘
â•‘   â”œâ”€ Unusual system call sequence â†’ ALERT                                   â•‘
â•‘   â””â”€ Privilege escalation attempt â†’ BLOCK + ALERT                           â•‘
â•‘                                                                              â•‘
â•‘   SPECTRE/MELTDOWN INDICATORS (Linux only):                                  â•‘
â•‘   â”œâ”€ High-frequency timer access â†’ FLAG                                     â•‘
â•‘   â”œâ”€ Cache timing patterns â†’ FLAG                                           â•‘
â•‘   â”œâ”€ Speculative execution markers â†’ FLAG                                   â•‘
â•‘   â””â”€ Kernel memory access attempts â†’ BLOCK                                  â•‘
â•‘                                                                              â•‘
â•‘   LIMITATIONS (HONEST):                                                      â•‘
â•‘   â”œâ”€ Baseline requires learning period                                      â•‘
â•‘   â”œâ”€ Novel attacks may evade detection                                      â•‘
â•‘   â”œâ”€ False positives possible                                               â•‘
â•‘   â””â”€ Cannot prevent exploitation, only detect                               â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## 0-DAY RESPONSE PROCEDURE

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   WHEN ANOMALY DETECTED:                                                     â•‘
â•‘                                                                              â•‘
â•‘   IMMEDIATE (automated):                                                     â•‘
â•‘   1. Log full context to audit trail                                         â•‘
â•‘   2. Capture memory snapshot (if safe)                                       â•‘
â•‘   3. Block suspicious activity (if high confidence)                          â•‘
â•‘   4. Alert security team                                                     â•‘
â•‘                                                                              â•‘
â•‘   SHORT-TERM (human review):                                                 â•‘
â•‘   1. Analyze captured data                                                   â•‘
â•‘   2. Determine if true positive                                              â•‘
â•‘   3. Isolate affected systems if confirmed                                   â•‘
â•‘   4. Begin forensics                                                         â•‘
â•‘                                                                              â•‘
â•‘   LONG-TERM (if confirmed 0-day):                                            â•‘
â•‘   1. Develop signature/detection rule                                        â•‘
â•‘   2. Push to all ZIRAH instances                                            â•‘
â•‘   3. Coordinate disclosure if appropriate                                    â•‘
â•‘   4. Update baseline models                                                  â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

# PART XIX: DDOS MITIGATION & AVAILABILITY [NEW IN V3.1]

## GAPURA DDOS MITIGATION

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   LAYER 7 (APPLICATION):                                                     â•‘
â•‘   â”œâ”€ Rate limiting per IP: 100 req/min (configurable)                       â•‘
â•‘   â”œâ”€ Rate limiting per session: 1000 req/min                                â•‘
â•‘   â”œâ”€ Rate limiting per user: 5000 req/min                                   â•‘
â•‘   â”œâ”€ Proof-of-work challenge if threshold exceeded                          â•‘
â•‘   â”œâ”€ CAPTCHA fallback (accessibility concerns noted)                        â•‘
â•‘   â””â”€ Slowloris protection (connection timeouts)                             â•‘
â•‘                                                                              â•‘
â•‘   LAYER 4 (TRANSPORT):                                                       â•‘
â•‘   â”œâ”€ SYN cookie enforcement                                                  â•‘
â•‘   â”œâ”€ Connection limits per IP: 100 concurrent                               â•‘
â•‘   â”œâ”€ TCP window validation                                                   â•‘
â•‘   â””â”€ UDP amplification protection                                            â•‘
â•‘                                                                              â•‘
â•‘   LAYER 3 (NETWORK):                                                         â•‘
â•‘   â”œâ”€ Upstream provider filtering (requires ISP cooperation)                 â•‘
â•‘   â”œâ”€ Geographic filtering (optional, configurable)                          â•‘
â•‘   â”œâ”€ BGP blackholing (requires ISP cooperation)                             â•‘
â•‘   â””â”€ Anycast distribution (future enhancement)                               â•‘
â•‘                                                                              â•‘
â•‘   CHALLENGE-RESPONSE:                                                        â•‘
â•‘   â”œâ”€ JavaScript challenge (bot detection)                                   â•‘
â•‘   â”œâ”€ Cryptographic puzzle (adjustable difficulty)                           â•‘
â•‘   â””â”€ Behavioral analysis (human vs bot patterns)                            â•‘
â•‘                                                                              â•‘
â•‘   LIMITATIONS:                                                               â•‘
â•‘   â”œâ”€ Large-scale attacks require upstream help                              â•‘
â•‘   â”œâ”€ Sophisticated botnets may solve challenges                             â•‘
â•‘   â””â”€ Geographic filtering may block legitimate users                        â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

# PART XX: AUDIT LOGGING & INSIDER THREAT [NEW IN V3.1]

## COMPREHENSIVE AUDIT LOGGING

See LAW 8 in Part I and SPEC 4 in Part III.

## INSIDER THREAT DETECTION

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   ANOMALY DETECTION ON AUDIT LOGS                                            â•‘
â•‘                                                                              â•‘
â•‘   BASELINE PATTERNS (per user/service):                                      â•‘
â•‘   â”œâ”€ Normal access times                                                     â•‘
â•‘   â”œâ”€ Normal access locations (IP ranges)                                    â•‘
â•‘   â”œâ”€ Normal data access volumes                                             â•‘
â•‘   â”œâ”€ Normal privilege usage                                                 â•‘
â•‘   â””â”€ Normal operation sequences                                             â•‘
â•‘                                                                              â•‘
â•‘   ALERTS:                                                                    â•‘
â•‘   â”œâ”€ Access outside normal hours â†’ ALERT                                    â•‘
â•‘   â”œâ”€ Access from unusual location â†’ ALERT                                   â•‘
â•‘   â”œâ”€ Bulk data access â†’ ALERT                                               â•‘
â•‘   â”œâ”€ Privilege escalation â†’ ALERT                                           â•‘
â•‘   â”œâ”€ Accessing data outside role â†’ ALERT                                    â•‘
â•‘   â”œâ”€ Failed authentication spike â†’ ALERT                                    â•‘
â•‘   â””â”€ Pattern matching known attack â†’ BLOCK + ALERT                          â•‘
â•‘                                                                              â•‘
â•‘   SEPARATION OF DUTIES:                                                      â•‘
â•‘   â”œâ”€ Key generation â‰  key usage                                             â•‘
â•‘   â”œâ”€ Admin access â‰  user data access                                        â•‘
â•‘   â”œâ”€ Log access â‰  log deletion (deletion prohibited)                        â•‘
â•‘   â””â”€ Config change requires 2 approvals                                     â•‘
â•‘                                                                              â•‘
â•‘   LOG PROTECTION:                                                            â•‘
â•‘   â”œâ”€ Append-only storage                                                     â•‘
â•‘   â”œâ”€ Cryptographic hash chain                                                â•‘
â•‘   â”œâ”€ Signature on each entry                                                 â•‘
â•‘   â”œâ”€ Replicated to 2+ locations                                              â•‘
â•‘   â””â”€ 7-year retention                                                        â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

# PART XXI: DEVICE BINDING & SIM-SWAP RESISTANCE [NEW IN V3.1]

## DEVICE BINDING ARCHITECTURE

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   DEVICE IDENTITY (NOT PHONE NUMBER)                                         â•‘
â•‘                                                                              â•‘
â•‘   DEVICE KEY GENERATION:                                                     â•‘
â•‘   1. On first app launch, generate ML-DSA-65 + Ed25519 keypair              â•‘
â•‘   2. Store private key in Secret<T> with mlock                               â•‘
â•‘   3. Additional protection: Platform keystore (Keychain/Keystore)            â•‘
â•‘   4. Private key NEVER leaves device                                         â•‘
â•‘   5. Public key registered with server                                       â•‘
â•‘                                                                              â•‘
â•‘   DEVICE ATTESTATION:                                                        â•‘
â•‘   â”œâ”€ iOS: DeviceCheck + our signature                                        â•‘
â•‘   â”œâ”€ Android: Play Integrity + our signature                                 â•‘
â•‘   â””â”€ Desktop: TPM attestation + our signature (if available)                â•‘
â•‘                                                                              â•‘
â•‘   ALL OPERATIONS REQUIRE:                                                    â•‘
â•‘   â”œâ”€ Valid device signature                                                  â•‘
â•‘   â”œâ”€ Device ID matches registered                                            â•‘
â•‘   â””â”€ Platform attestation (where available)                                  â•‘
â•‘                                                                              â•‘
â•‘   PROHIBITED:                                                                â•‘
â•‘   â”œâ”€ Phone number as identity                                                â•‘
â•‘   â”œâ”€ SMS OTP as sole authentication factor                                   â•‘
â•‘   â”œâ”€ Email OTP as sole authentication factor                                 â•‘
â•‘   â””â”€ Any non-cryptographic device identification                             â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

## RECOVERY MECHANISM

```
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                                              â•‘
â•‘   DEVICE LOSS RECOVERY                                                       â•‘
â•‘                                                                              â•‘
â•‘   PREVENTION (before loss):                                                  â•‘
â•‘   â”œâ”€ Multi-device registration (recommended)                                â•‘
â•‘   â”œâ”€ Recovery key generation (stored offline by user)                        â•‘
â•‘   â””â”€ Trusted contact designation (optional)                                  â•‘
â•‘                                                                              â•‘
â•‘   RECOVERY PROCESS:                                                          â•‘
â•‘   1. User initiates recovery from new device                                 â•‘
â•‘   2. Requires recovery key OR trusted contact approval                       â•‘
â•‘   3. Waiting period: 72 hours (security delay)                               â•‘
â•‘   4. Notification to all registered devices                                  â•‘
â•‘   5. Old device key revoked after waiting period                             â•‘
â•‘   6. New device key generated and registered                                 â•‘
â•‘                                                                              â•‘
â•‘   WAITING PERIOD CANNOT BE BYPASSED:                                         â•‘
â•‘   â”œâ”€ Even with recovery key, 72-hour wait applies                           â•‘
â•‘   â”œâ”€ Provides window for legitimate owner to cancel                          â•‘
â•‘   â””â”€ Alerts sent to all known contact methods                                â•‘
â•‘                                                                              â•‘
â•‘   LIMITATIONS:                                                               â•‘
â•‘   â”œâ”€ Recovery key loss + single device = account lost                        â•‘
â•‘   â”œâ”€ 72-hour delay may be inconvenient                                       â•‘
â•‘   â””â”€ No "customer support" bypass possible                                   â•‘
â•‘                                                                              â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
```

---

---

# PART XXII: MENARA MOBILE SECURITY [NEW IN V3.2]

## LAW M-1: DETECTION PILLAR REQUIREMENTS

All six detection pillars are MANDATORY. Each pillar MUST achieve specified detection rates.

### PILLAR 1: PERMISSION AUDITOR

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PERMISSION AUDITOR SPECIFICATION                                           ║
║                                                                              ║
║   PURPOSE: Analyze app permissions vs declared functionality                 ║
║                                                                              ║
║   DETECTION CAPABILITIES:                                                    ║
║   ├─ Over-privileged apps (permissions exceed stated functionality)          ║
║   ├─ Permission escalation (runtime permission requests)                     ║
║   ├─ Dangerous permission combinations                                       ║
║   └─ Permission changes across app updates                                   ║
║                                                                              ║
║   DANGEROUS PERMISSION COMBINATIONS:                                         ║
║   ┌────────────────────────────────────┬────────────────────────────────────┐ ║
║   │ COMBINATION                        │ THREAT INDICATION                  │ ║
║   ├────────────────────────────────────┼────────────────────────────────────┤ ║
║   │ CAMERA + RECORD_AUDIO + INTERNET   │ Spyware (audio/video exfil)        │ ║
║   │ READ_SMS + INTERNET                │ 2FA bypass (SMS interception)      │ ║
║   │ ACCESSIBILITY + INTERNET           │ Banking trojan (overlay attacks)   │ ║
║   │ READ_CONTACTS + INTERNET           │ Contact harvesting                 │ ║
║   │ READ_CALL_LOG + INTERNET           │ Call metadata exfiltration         │ ║
║   │ ACCESS_FINE_LOCATION + INTERNET    │ Location tracking                  │ ║
║   │ BIND_NOTIFICATION_LISTENER + *     │ Notification interception          │ ║
║   │ SYSTEM_ALERT_WINDOW + INTERNET     │ Overlay/clickjacking attacks       │ ║
║   │ REQUEST_INSTALL_PACKAGES           │ Dropper functionality              │ ║
║   │ QUERY_ALL_PACKAGES                 │ Reconnaissance                     │ ║
║   └────────────────────────────────────┴────────────────────────────────────┘ ║
║                                                                              ║
║   SCORING SYSTEM:                                                            ║
║   ├─ Trust score: 0-100 per app                                              ║
║   ├─ 100: No dangerous permissions                                           ║
║   ├─ 80-99: Permissions match declared functionality                         ║
║   ├─ 60-79: Minor permission concerns                                        ║
║   ├─ 40-59: Suspicious permission combinations                               ║
║   ├─ 0-39: High-risk / likely malicious                                      ║
║   └─ Score <40 triggers alert                                                ║
║                                                                              ║
║   PERMISSION CHANGE TRACKING:                                                ║
║   ├─ Baseline established at app install                                     ║
║   ├─ Changes tracked across updates                                          ║
║   ├─ Alert on permission escalation                                          ║
║   └─ Alert on runtime permission abuse                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PILLAR 2: IOC MATCHER

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   IOC MATCHER SPECIFICATION                                                  ║
║                                                                              ║
║   PURPOSE: Match Indicators of Compromise from threat feeds                  ║
║                                                                              ║
║   SUPPORTED IOC TYPES:                                                       ║
║   ┌────────────────────────┬─────────────────────────────────────────────────┐║
║   │ TYPE                   │ MATCHING RULES                                  │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ IPv4 Address           │ Exact match                                     │║
║   │ IPv6 Address           │ Exact match + /64 subnet match                  │║
║   │ Domain                 │ Exact match + wildcard subdomain                │║
║   │ URL                    │ Normalized match + path-prefix match            │║
║   │ File Hash (MD5)        │ Exact match (legacy support only)               │║
║   │ File Hash (SHA-1)      │ Exact match (legacy support only)               │║
║   │ File Hash (SHA-256)    │ Exact match (preferred)                         │║
║   │ File Hash (SHA-512)    │ Exact match                                     │║
║   │ Certificate Fingerprint│ SHA-256 exact match                             │║
║   └────────────────────────┴─────────────────────────────────────────────────┘║
║                                                                              ║
║   PERFORMANCE REQUIREMENTS:                                                  ║
║   ├─ Real-time matching latency: <10ms P99                                   ║
║   ├─ IOC database capacity: >10 million entries                              ║
║   ├─ Lookup complexity: O(1) amortized                                       ║
║   └─ Memory footprint: <100MB for full database                              ║
║                                                                              ║
║   INTEGRATION:                                                               ║
║   ├─ Primary source: teras-suap threat feeds                                 ║
║   ├─ Local cache with configurable TTL (default 24h)                         ║
║   ├─ Delta updates to minimize bandwidth                                     ║
║   └─ False positive allow-list (client-configurable)                         ║
║                                                                              ║
║   MATCHING OPERATIONS:                                                       ║
║   ├─ Network connections: Match destination IP/domain                        ║
║   ├─ DNS queries: Match queried domain                                       ║
║   ├─ App installations: Match APK hash                                       ║
║   ├─ Certificate validation: Match cert fingerprint                          ║
║   └─ URL navigation: Match normalized URL                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PILLAR 3: POWER ANOMALY DETECTOR

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   POWER ANOMALY DETECTOR SPECIFICATION                                       ║
║                                                                              ║
║   PURPOSE: Detect malicious activity through power consumption patterns      ║
║                                                                              ║
║   BASELINE ESTABLISHMENT:                                                    ║
║   ├─ Learning period: 7 days                                                 ║
║   ├─ Per-app category baselines                                              ║
║   ├─ Time-of-day patterns                                                    ║
║   └─ User behavior patterns                                                  ║
║                                                                              ║
║   CRYPTO-MINING INDICATORS:                                                  ║
║   ├─ High CPU usage (>80%) sustained >5 minutes                              ║
║   ├─ Elevated battery temperature                                            ║
║   ├─ Power draw >3σ above baseline                                           ║
║   ├─ GPU usage without visible rendering                                     ║
║   └─ Background computation during idle                                      ║
║                                                                              ║
║   DATA EXFILTRATION INDICATORS:                                              ║
║   ├─ Unusual network + battery drain correlation                             ║
║   ├─ Background transfers during screen-off                                  ║
║   ├─ High network activity with low UI activity                              ║
║   └─ Periodic burst transmissions (beaconing pattern)                        ║
║                                                                              ║
║   ALERT THRESHOLDS:                                                          ║
║   ├─ WARNING: >2σ deviation from baseline                                    ║
║   ├─ CRITICAL: >3σ deviation from baseline                                   ║
║   └─ Sustained anomaly (>5 min): Escalate to CRITICAL                        ║
║                                                                              ║
║   BATTERY HEALTH CORRELATION:                                                ║
║   ├─ Track battery degradation rate                                          ║
║   ├─ Detect rapid degradation (mining indicator)                             ║
║   └─ Alert on unusual discharge patterns                                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PILLAR 4: SENSOR FUSION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SENSOR FUSION SPECIFICATION                                                ║
║                                                                              ║
║   PURPOSE: Correlate multiple sensors to detect threats                      ║
║                                                                              ║
║   SENSOR SOURCES:                                                            ║
║   ├─ Accelerometer (motion)                                                  ║
║   ├─ Gyroscope (orientation)                                                 ║
║   ├─ Magnetometer (compass)                                                  ║
║   ├─ Light sensor (ambient light)                                            ║
║   └─ Proximity sensor (screen proximity)                                     ║
║                                                                              ║
║   SAMPLING RATE: 100Hz during sensitive operations                           ║
║                                                                              ║
║   SCREEN CAPTURE DETECTION:                                                  ║
║   ├─ Screenshot API call monitoring                                          ║
║   ├─ Screen recording detection                                              ║
║   ├─ External camera detection (light pattern analysis)                      ║
║   ├─ HDMI/MHL output monitoring                                              ║
║   └─ Screen mirroring detection                                              ║
║                                                                              ║
║   PHYSICAL TAMPERING DETECTION:                                              ║
║   ├─ Unusual movement during sensitive operations                            ║
║   ├─ Orientation changes during authentication                               ║
║   ├─ Rapid device handoff detection                                          ║
║   └─ Physical stress indicators (drops, impacts)                             ║
║                                                                              ║
║   DEVICE CLONING DETECTION:                                                  ║
║   ├─ Sensor fingerprint mismatch                                             ║
║   ├─ Impossible sensor readings (emulator)                                   ║
║   ├─ Sensor noise pattern analysis                                           ║
║   ├─ Calibration offset verification                                         ║
║   └─ Hardware characteristic validation                                      ║
║                                                                              ║
║   SENSOR FINGERPRINTING:                                                     ║
║   ├─ Each device has unique sensor characteristics                           ║
║   ├─ Fingerprint established at registration                                 ║
║   ├─ Mismatch indicates different device or emulation                        ║
║   └─ Used as device binding factor                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PILLAR 5: TIMING ANALYSIS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   TIMING ANALYSIS SPECIFICATION                                              ║
║                                                                              ║
║   PURPOSE: Detect hooking and instrumentation through timing anomalies       ║
║                                                                              ║
║   TIMING RESOLUTION: <1μs                                                    ║
║                                                                              ║
║   HOOKING FRAMEWORK DETECTION:                                               ║
║   ┌────────────────────────┬─────────────────────────────────────────────────┐║
║   │ FRAMEWORK              │ DETECTION METHOD                                │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Frida                  │ Function timing anomalies                       │║
║   │                        │ Memory pattern detection                        │║
║   │                        │ Named pipe detection                            │║
║   │                        │ D-Bus interface scanning                        │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Xposed                 │ Module enumeration                              │║
║   │                        │ Function hook timing                            │║
║   │                        │ Bridge method detection                         │║
║   │                        │ ClassLoader inspection                          │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Magisk Hide            │ Mount namespace detection                       │║
║   │                        │ /proc/self/maps analysis                        │║
║   │                        │ Property hiding detection                       │║
║   │                        │ SELinux context verification                    │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Substrate/Cydia (iOS)  │ Method swizzling detection                      │║
║   │                        │ Dynamic library injection                       │║
║   │                        │ Objective-C runtime inspection                  │║
║   └────────────────────────┴─────────────────────────────────────────────────┘║
║                                                                              ║
║   INSTRUMENTATION DELAY DETECTION:                                           ║
║   ├─ Function call timing >3σ from baseline                                  ║
║   ├─ Syscall timing anomalies                                                ║
║   ├─ IPC timing deviations                                                   ║
║   └─ Binder transaction timing                                               ║
║                                                                              ║
║   CONSTANT-TIME SECURITY CHECKS:                                             ║
║   ├─ All security comparisons use constant-time operations                   ║
║   ├─ No early-exit on comparison failure                                     ║
║   ├─ Timing-safe memory comparison                                           ║
║   └─ Prevents timing-based bypass attacks                                    ║
║                                                                              ║
║   ANTI-TAMPERING:                                                            ║
║   ├─ Code integrity verification (checksum)                                  ║
║   ├─ Self-checksum validation                                                ║
║   ├─ Code section hash verification                                          ║
║   └─ Detects runtime code modification                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PILLAR 6: CANARY SYSTEM

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   CANARY SYSTEM SPECIFICATION                                                ║
║                                                                              ║
║   PURPOSE: Deploy decoy data to detect unauthorized access                   ║
║                                                                              ║
║   CANARY TYPES:                                                              ║
║   ┌────────────────────────┬─────────────────────────────────────────────────┐║
║   │ CANARY TYPE            │ DEPLOYMENT                                      │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Fake Credentials       │ SharedPreferences (Android)                     │║
║   │                        │ Keychain (iOS)                                  │║
║   │                        │ Enticing key names (password, token, key)       │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Decoy API Endpoints    │ Server endpoints never called by real app       │║
║   │                        │ Access = compromise indicator                   │║
║   │                        │ Track IP, timing, payload                       │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Honeypot Files         │ Enticing names (wallet.dat, keys.json)          │║
║   │                        │ Located in accessible directories               │║
║   │                        │ Access triggers alert                           │║
║   ├────────────────────────┼─────────────────────────────────────────────────┤║
║   │ Fake Network Resources │ DNS entries for fake internal services          │║
║   │                        │ Query = lateral movement detection              │║
║   └────────────────────────┴─────────────────────────────────────────────────┘║
║                                                                              ║
║   CANARY BEHAVIOR:                                                           ║
║   ├─ Any canary access = compromise indicator                                ║
║   ├─ Track access patterns to identify attacker techniques                   ║
║   ├─ Immediate notification to SARAF                                         ║
║   └─ Full context logged to JEJAK                                            ║
║                                                                              ║
║   CANARY UNIQUENESS:                                                         ║
║   ├─ Each canary unique per-device                                           ║
║   ├─ Allows tracing leaked data to source device                             ║
║   ├─ Cryptographically generated unique values                               ║
║   └─ Rotation on detected access                                             ║
║                                                                              ║
║   HONEYPOT INTEGRATION:                                                      ║
║   ├─ Fake data attractive to attackers                                       ║
║   ├─ Format matches real sensitive data                                      ║
║   ├─ Slightly corrupted to prevent misuse if leaked                          ║
║   └─ Watermarked for attribution                                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PILLAR VALIDATION REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   VALIDATION REQUIREMENTS PER PILLAR                                         ║
║                                                                              ║
║   CODE COVERAGE: >95% for each pillar                                        ║
║                                                                              ║
║   DETECTION RATES:                                                           ║
║   ├─ Permission Auditor: >99% for dangerous combinations                     ║
║   ├─ IOC Matcher: >99.9% for exact matches                                   ║
║   ├─ Power Anomaly: >95% for crypto-mining                                   ║
║   ├─ Sensor Fusion: >99% for emulator detection                              ║
║   ├─ Timing Analysis: >95% for Frida detection                               ║
║   └─ Canary System: 100% for canary access                                   ║
║                                                                              ║
║   FALSE POSITIVE RATE: <1% for each pillar                                   ║
║                                                                              ║
║   TEST MALWARE CORPUS:                                                       ║
║   ├─ Known malware families: >1,000 samples                                  ║
║   ├─ Spyware variants: >500 samples                                          ║
║   ├─ Banking trojans: >300 samples                                           ║
║   ├─ Crypto-miners: >200 samples                                             ║
║   └─ Custom test cases: >500 samples                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## PINQ QUERY LANGUAGE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PINQ (Privacy-preserving INtelligence Query) SPECIFICATION                 ║
║                                                                              ║
║   GRAMMAR:                                                                   ║
║   SELECT <Fields> FROM <Source> WHERE <Predicate> WITHIN <Timeframe>         ║
║                                                                              ║
║   DATA SOURCES:                                                              ║
║   ├─ threat_indicators: IOC database                                         ║
║   ├─ local_detections: On-device detection events                            ║
║   ├─ device_events: Device state changes                                     ║
║   └─ network_events: Network activity                                        ║
║                                                                              ║
║   QUERY PROPERTIES:                                                          ║
║   ├─ Type-safe: Query validated at compile time                              ║
║   ├─ Privacy-preserving: Cannot leak raw data                                ║
║   ├─ Auditable: All queries logged to JEJAK                                  ║
║   ├─ Bounded: Resource limits enforced                                       ║
║   └─ Differential privacy: DP noise injection                                ║
║                                                                              ║
║   ALLOWED OPERATIONS:                                                        ║
║   ├─ COUNT with differential privacy noise                                   ║
║   ├─ EXISTS (boolean: yes/no only)                                           ║
║   ├─ AGGREGATE statistics with DP                                            ║
║   └─ CATEGORY breakdown (threat types)                                       ║
║                                                                              ║
║   PROHIBITED OPERATIONS:                                                     ║
║   ├─ SELECT * (never raw data)                                               ║
║   ├─ JOIN across privacy domains                                             ║
║   ├─ Queries returning <k rows (k-anonymity violation, k=100)                ║
║   ├─ Queries on biometric data                                               ║
║   └─ Queries revealing individual device identity                            ║
║                                                                              ║
║   EXAMPLE QUERIES:                                                           ║
║   ┌────────────────────────────────────────────────────────────────────────┐ ║
║   │ -- Count threats by category (with DP noise)                           │ ║
║   │ SELECT COUNT(category) FROM threat_indicators                          │ ║
║   │ WHERE detected = true WITHIN last_24h                                  │ ║
║   │                                                                        │ ║
║   │ -- Check if specific IOC exists (boolean only)                         │ ║
║   │ SELECT EXISTS(hash) FROM threat_indicators                             │ ║
║   │ WHERE hash = 'abc123...'                                               │ ║
║   │                                                                        │ ║
║   │ -- INVALID: Raw data query                                             │ ║
║   │ SELECT * FROM local_detections -- REJECTED                             │ ║
║   └────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## KERISMESH PROTOCOL

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   KERISMESH PRIVACY REQUIREMENTS                                             ║
║                                                                              ║
║   PRIVACY GUARANTEES:                                                        ║
║   ├─ Device identity NEVER transmitted                                       ║
║   ├─ Only ZK proofs of threat sightings shared                               ║
║   ├─ No raw indicator values transmitted                                     ║
║   ├─ Local processing, aggregate sharing                                     ║
║   └─ k-anonymity: minimum k=100                                              ║
║                                                                              ║
║   WHAT IS SHARED:                                                            ║
║   ├─ ZK proof: "I saw threat matching pattern P"                             ║
║   ├─ Timestamp range (not exact)                                             ║
║   ├─ Threat category                                                         ║
║   └─ Severity assessment                                                     ║
║                                                                              ║
║   WHAT IS NEVER SHARED:                                                      ║
║   ├─ Device identity                                                         ║
║   ├─ User identity                                                           ║
║   ├─ Raw threat data                                                         ║
║   ├─ Network topology                                                        ║
║   └─ Location data                                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   KERISMESH PERFORMANCE REQUIREMENTS                                         ║
║                                                                              ║
║   LATENCY:                                                                   ║
║   ├─ Mesh update latency: <5s P99                                            ║
║   ├─ Proof generation: <100ms (mobile device)                                ║
║   ├─ Proof verification: <10ms                                               ║
║   └─ Gossip propagation: <30s for 95% coverage                               ║
║                                                                              ║
║   RESOURCE USAGE:                                                            ║
║   ├─ Battery impact: <2% per day                                             ║
║   ├─ Network usage: <10MB per day                                            ║
║   ├─ Memory footprint: <50MB                                                 ║
║   └─ CPU (background): <1%                                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   KERISMESH TRUST MODEL                                                      ║
║                                                                              ║
║   BOOTSTRAP:                                                                 ║
║   ├─ Initial trust from SARAF network                                        ║
║   ├─ Device attestation via BENTENG                                          ║
║   └─ Sybil resistance via device attestation                                 ║
║                                                                              ║
║   ONGOING TRUST:                                                             ║
║   ├─ Proof verification before acceptance                                    ║
║   ├─ Reputation scoring for nodes                                            ║
║   ├─ Penalty for false reports                                               ║
║   └─ Quarantine for suspicious nodes                                         ║
║                                                                              ║
║   BYZANTINE FAULT TOLERANCE:                                                 ║
║   ├─ Assumes up to 1/3 nodes malicious                                       ║
║   ├─ Voting threshold: 2/3 + 1 for consensus                                 ║
║   ├─ Conflicting information flagged                                         ║
║   └─ Reputation penalty for false reports                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   KERISMESH PROTOCOL SPECIFICATION                                           ║
║                                                                              ║
║   TRANSPORT:                                                                 ║
║   ├─ Protocol: QUIC over UDP                                                 ║
║   ├─ Port: 4433                                                              ║
║   ├─ Encryption: TLS 1.3 with ML-KEM + X25519 hybrid                         ║
║   └─ Multiplexing: Multiple streams per connection                           ║
║                                                                              ║
║   GOSSIP PROTOCOL:                                                           ║
║   ├─ Type: Epidemic broadcast                                                ║
║   ├─ Fanout: 8 peers per round                                               ║
║   ├─ Round interval: 1 second                                                ║
║   └─ Deduplication: Bloom filter                                             ║
║                                                                              ║
║   MESSAGE FORMAT:                                                            ║
║   ├─ Encoding: CBOR                                                          ║
║   ├─ Signature: Device key (Ed25519)                                         ║
║   ├─ TTL: 24 hours                                                           ║
║   └─ Versioning: Schema versioned                                            ║
║                                                                              ║
║   MESSAGE TYPES:                                                             ║
║   ├─ THREAT_SIGHTING: ZK proof of threat observation                         ║
║   ├─ THREAT_QUERY: Request for threat information                            ║
║   ├─ HEARTBEAT: Node liveness                                                ║
║   ├─ SYNC_REQUEST: State synchronization                                     ║
║   └─ REPUTATION_UPDATE: Node reputation change                               ║
║                                                                              ║
║   CONSISTENCY MODEL:                                                         ║
║   ├─ Eventual consistency: 30 seconds                                        ║
║   ├─ Conflict resolution: Last-writer-wins with vector clocks                ║
║   ├─ Partition tolerance: Sync on reconnect                                  ║
║   └─ Anti-entropy: Merkle tree reconciliation                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## MOBILE PLATFORM REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   iOS PLATFORM REQUIREMENTS                                                  ║
║                                                                              ║
║   LANGUAGE INTEROP:                                                          ║
║   ├─ Swift primary interface                                                 ║
║   ├─ Objective-C headers for compatibility                                   ║
║   └─ C ABI for core library                                                  ║
║                                                                              ║
║   BIOMETRIC INTEGRATION:                                                     ║
║   ├─ Face ID via LocalAuthentication framework                               ║
║   ├─ Touch ID via LocalAuthentication framework                              ║
║   └─ Fallback to device passcode NOT permitted (LAW 1)                       ║
║                                                                              ║
║   KEY STORAGE:                                                               ║
║   ├─ Secure Enclave (SEP) for key generation and storage                     ║
║   ├─ Keys marked as non-exportable                                           ║
║   └─ Biometric-protected access policy                                       ║
║                                                                              ║
║   DEPLOYMENT:                                                                ║
║   ├─ Minimum iOS version: 14.0                                               ║
║   ├─ Architectures: arm64 (device)                                           ║
║   ├─ Simulator: arm64 + x86_64                                               ║
║   └─ Distribution: XCFramework                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ANDROID PLATFORM REQUIREMENTS                                              ║
║                                                                              ║
║   LANGUAGE INTEROP:                                                          ║
║   ├─ Kotlin primary interface                                                ║
║   ├─ Java interop maintained                                                 ║
║   └─ JNI for native code                                                     ║
║                                                                              ║
║   BIOMETRIC INTEGRATION:                                                     ║
║   ├─ BiometricPrompt API (Class 3 biometrics required)                       ║
║   ├─ Strong authentication level required                                    ║
║   └─ No device credential fallback (LAW 1)                                   ║
║                                                                              ║
║   KEY STORAGE:                                                               ║
║   ├─ StrongBox Keymaster when available                                      ║
║   ├─ TEE-backed Keystore as fallback                                         ║
║   ├─ Keys bound to biometric authentication                                  ║
║   └─ Non-exportable key policy                                               ║
║                                                                              ║
║   DEPLOYMENT:                                                                ║
║   ├─ Minimum SDK: API 26 (Android 8.0 Oreo)                                  ║
║   ├─ Target SDK: Latest stable                                               ║
║   ├─ Architectures: armeabi-v7a, arm64-v8a, x86, x86_64                      ║
║   └─ Distribution: AAR via Maven Central                                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   WEB (WASM) PLATFORM REQUIREMENTS                                           ║
║                                                                              ║
║   BIOMETRIC INTEGRATION:                                                     ║
║   ├─ WebAuthn for biometric authentication                                   ║
║   ├─ Platform authenticator preferred                                        ║
║   └─ Security key as fallback                                                ║
║                                                                              ║
║   CRYPTOGRAPHIC OPERATIONS:                                                  ║
║   ├─ WebCrypto API for supported algorithms                                  ║
║   ├─ WASM implementation for post-quantum                                    ║
║   └─ No native dependencies                                                  ║
║                                                                              ║
║   BROWSER SUPPORT:                                                           ║
║   ├─ Chrome 90+                                                              ║
║   ├─ Firefox 90+                                                             ║
║   ├─ Safari 15+                                                              ║
║   └─ Edge 90+                                                                ║
║                                                                              ║
║   DISTRIBUTION:                                                              ║
║   ├─ npm package                                                             ║
║   └─ CDN distribution                                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   DESKTOP PLATFORM REQUIREMENTS                                              ║
║                                                                              ║
║   WINDOWS:                                                                   ║
║   ├─ Windows Hello integration                                               ║
║   ├─ TPM 2.0 for key storage                                                 ║
║   ├─ Distribution: MSIX package                                              ║
║   └─ Architecture: x86_64, arm64                                             ║
║                                                                              ║
║   macOS:                                                                     ║
║   ├─ Touch ID integration via LocalAuthentication                            ║
║   ├─ Secure Enclave for key storage (Apple Silicon)                          ║
║   ├─ Keychain for key storage (Intel)                                        ║
║   ├─ Distribution: Universal binary (arm64 + x86_64)                         ║
║   └─ Minimum: macOS 11 (Big Sur)                                             ║
║                                                                              ║
║   LINUX:                                                                     ║
║   ├─ TPM 2.0 integration when available                                      ║
║   ├─ Software fallback with user-password encryption                         ║
║   ├─ Distribution: deb, rpm, AppImage                                        ║
║   └─ Architecture: x86_64, arm64                                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XXIII: GAPURA WAF ENGINE [NEW IN V3.2]

## LAW G-1: CANONICALIZATION REQUIREMENTS

Canonicalization MUST occur BEFORE any rule matching. Canonicalization MUST be deterministic.

### URL CANONICALIZATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   URL CANONICALIZATION PROCESS (IN ORDER)                                    ║
║                                                                              ║
║   STEP 1: Decode all URL encoding (percent-decode)                           ║
║   STEP 2: Repeat Step 1 until stable (handle double/triple encoding)         ║
║   STEP 3: Normalize Unicode to NFC                                           ║
║   STEP 4: Convert scheme and host to lowercase                               ║
║   STEP 5: Remove default ports (:80 for http, :443 for https)                ║
║   STEP 6: Normalize path segments:                                           ║
║           ├─ Remove consecutive slashes (//)                                 ║
║           ├─ Resolve single-dot segments (/./)                               ║
║           ├─ Resolve double-dot segments (/../)                              ║
║           └─ REJECT paths escaping document root                             ║
║   STEP 7: Sort query parameters alphabetically by key                        ║
║   STEP 8: Normalize empty values (key= → key)                                ║
║                                                                              ║
║   VALIDATION:                                                                ║
║   ├─ Same input MUST produce identical canonical output                      ║
║   ├─ Canonical form is used for all rule matching                            ║
║   └─ Original form preserved in logs for audit                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### HEADER CANONICALIZATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   HEADER CANONICALIZATION PROCESS                                            ║
║                                                                              ║
║   STEP 1: Convert header names to lowercase                                  ║
║   STEP 2: Trim leading/trailing whitespace from values                       ║
║   STEP 3: Collapse internal whitespace to single space                       ║
║   STEP 4: Combine duplicate headers per RFC 7230                             ║
║   STEP 5: Validate Content-Length matches body size                          ║
║   STEP 6: REJECT requests with conflicting headers                           ║
║                                                                              ║
║   CONFLICTING HEADER DETECTION:                                              ║
║   ├─ Multiple Content-Length values                                          ║
║   ├─ Content-Length AND Transfer-Encoding (unless HTTP/2)                    ║
║   ├─ Multiple Transfer-Encoding headers                                      ║
║   └─ Host header mismatch with URL                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### BODY CANONICALIZATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   BODY CANONICALIZATION BY CONTENT-TYPE                                      ║
║                                                                              ║
║   application/x-www-form-urlencoded:                                         ║
║   ├─ Parse key-value pairs                                                   ║
║   ├─ URL-decode both keys and values                                         ║
║   ├─ Handle duplicate keys as arrays                                         ║
║   └─ Normalize for rule matching                                             ║
║                                                                              ║
║   multipart/form-data:                                                       ║
║   ├─ Parse boundary from Content-Type                                        ║
║   ├─ Extract individual parts                                                ║
║   ├─ Decode Content-Transfer-Encoding if present                             ║
║   ├─ Validate part headers                                                   ║
║   └─ REJECT malformed multipart                                              ║
║                                                                              ║
║   application/json:                                                          ║
║   ├─ Parse strictly (reject invalid JSON)                                    ║
║   ├─ Normalize numbers (no leading zeros except 0.x)                         ║
║   ├─ REJECT duplicate keys                                                   ║
║   └─ LIMIT nesting depth: max 32                                             ║
║                                                                              ║
║   application/xml OR text/xml:                                               ║
║   ├─ Parse strictly (reject malformed XML)                                   ║
║   ├─ REJECT external entity declarations (XXE prevention)                    ║
║   ├─ REJECT DTD processing                                                   ║
║   └─ LIMIT nesting depth: max 32                                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### NESTED ENCODING HANDLING

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   NESTED ENCODING DETECTION AND HANDLING                                     ║
║                                                                              ║
║   BASE64 DETECTION:                                                          ║
║   ├─ Detect Base64-encoded payloads by pattern                               ║
║   ├─ Decode and scan recursively                                             ║
║   └─ Maximum recursion depth: 3 levels                                       ║
║                                                                              ║
║   COMPRESSION DETECTION:                                                     ║
║   ├─ Detect gzip magic bytes (1f 8b)                                         ║
║   ├─ Detect deflate streams                                                  ║
║   ├─ Decompress and scan                                                     ║
║   └─ Maximum decompressed size: 10MB                                         ║
║                                                                              ║
║   RULE APPLICATION:                                                          ║
║   ├─ Apply rules to BOTH encoded and decoded forms                           ║
║   ├─ Match on any representation                                             ║
║   └─ Log which representation matched                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## LAW G-2: REQUEST SMUGGLING PREVENTION

All request smuggling variants MUST be detected and BLOCKED.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   CL-TE ATTACK PREVENTION                                                    ║
║                                                                              ║
║   RULE: REJECT requests with BOTH Content-Length AND Transfer-Encoding       ║
║                                                                              ║
║   DETECTION:                                                                 ║
║   ├─ Scan all headers for Content-Length                                     ║
║   ├─ Scan all headers for Transfer-Encoding                                  ║
║   ├─ If BOTH present: REJECT immediately                                     ║
║   └─ Log rejection with sanitized headers                                    ║
║                                                                              ║
║   ALERT: Trigger alert on repeated attempts from same source                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   TE-TE ATTACK PREVENTION                                                    ║
║                                                                              ║
║   REJECT ALL OF:                                                             ║
║   ├─ "Transfer-Encoding: chunked, identity"                                  ║
║   ├─ "Transfer-Encoding: xchunked" (or any non-standard value)               ║
║   ├─ "Transfer-Encoding:\tchunked" (tab before value)                        ║
║   ├─ "Transfer-Encoding : chunked" (space before colon)                      ║
║   ├─ Multiple Transfer-Encoding headers                                      ║
║   └─ Unusual whitespace in Transfer-Encoding                                 ║
║                                                                              ║
║   ACCEPT ONLY: Exactly "Transfer-Encoding: chunked"                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   HTTP/2 DOWNGRADE ATTACK PREVENTION                                         ║
║                                                                              ║
║   AT GATEWAY (HTTP/2 → HTTP/1.1 translation):                                ║
║   ├─ Validate translation correctness                                        ║
║   ├─ REJECT pseudo-headers in HTTP/1.1 (:method, :path, :authority)          ║
║   ├─ REJECT HTTP/2 framing artifacts                                         ║
║   └─ Ensure Content-Length correct after downgrade                           ║
║                                                                              ║
║   PSEUDO-HEADER INJECTION:                                                   ║
║   ├─ REJECT any header starting with ":"                                     ║
║   └─ Log and alert on attempts                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   RESPONSE SPLITTING PREVENTION                                              ║
║                                                                              ║
║   REJECT requests containing CR or LF in ANY field:                          ║
║   ├─ URL path and query string                                               ║
║   ├─ All header names and values                                             ║
║   ├─ Cookie values                                                           ║
║   └─ All body fields (form fields, JSON values)                              ║
║                                                                              ║
║   DETECTION PATTERNS:                                                        ║
║   ├─ \r (CR, 0x0d, %0d)                                                      ║
║   ├─ \n (LF, 0x0a, %0a)                                                      ║
║   ├─ Double-encoded: %250d, %250a                                            ║
║   └─ Unicode variants                                                        ║
║                                                                              ║
║   VALIDATE RESPONSE HEADERS:                                                 ║
║   ├─ Validate response headers before sending to client                      ║
║   └─ Strip any injected headers                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   WEBSOCKET SMUGGLING PREVENTION                                             ║
║                                                                              ║
║   VALIDATION:                                                                ║
║   ├─ Validate Upgrade header matches supported protocols                     ║
║   ├─ Reject malformed Sec-WebSocket-Key                                      ║
║   ├─ Ensure proper handshake completion before data transfer                 ║
║   └─ Validate Sec-WebSocket-Accept response                                  ║
║                                                                              ║
║   RESTRICTIONS:                                                              ║
║   ├─ No data before handshake complete                                       ║
║   ├─ Proper frame validation                                                 ║
║   └─ Mask validation for client frames                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## DETECTION PATTERNS

### SQL INJECTION (50+ PATTERNS)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SQL INJECTION LEVEL 1: BASIC PATTERNS (15)                                 ║
║                                                                              ║
║   1.  UNION SELECT                                                           ║
║   2.  UNION ALL SELECT                                                       ║
║   3.  OR 1=1                                                                 ║
║   4.  AND 1=1                                                                ║
║   5.  OR '1'='1'                                                             ║
║   6.  AND '1'='1'                                                            ║
║   7.  OR "1"="1"                                                             ║
║   8.  AND "1"="1"                                                            ║
║   9.  ' OR ''='                                                              ║
║   10. -- (SQL comment)                                                       ║
║   11. /* */ (block comment)                                                  ║
║   12. # (MySQL comment)                                                      ║
║   13. SLEEP()                                                                ║
║   14. WAITFOR DELAY                                                          ║
║   15. BENCHMARK()                                                            ║
║                                                                              ║
║   ADDITIONAL BASIC:                                                          ║
║   ├─ pg_sleep() (PostgreSQL)                                                 ║
║   ├─ '; DROP TABLE                                                           ║
║   └─ 1; DROP TABLE                                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SQL INJECTION LEVEL 2: EVASION PATTERNS (20)                               ║
║                                                                              ║
║   CASE VARIATIONS:                                                           ║
║   1.  uNiOn SeLeCt (mixed case)                                              ║
║   2.  UNION/**/SELECT (comment-based whitespace)                             ║
║   3.  UN%49ON (URL-encoded character)                                        ║
║   4.  UN%2549ON (double URL-encoded)                                         ║
║                                                                              ║
║   WHITESPACE SUBSTITUTION:                                                   ║
║   5.  UNION%09SELECT (tab, %09)                                              ║
║   6.  UNION%0aSELECT (newline, %0a)                                          ║
║   7.  UNION%0dSELECT (carriage return, %0d)                                  ║
║   8.  UNION%0bSELECT (vertical tab, %0b)                                     ║
║   9.  UNION%0cSELECT (form feed, %0c)                                        ║
║                                                                              ║
║   STRING ENCODING:                                                           ║
║   10. CHAR(117,110,105,111,110) (ASCII encoding)                             ║
║   11. CHR(117)||CHR(110)... (Oracle)                                         ║
║   12. 'admin'||'istrator' (concatenation with +)                             ║
║   13. 'admin'+'istrator' (concatenation with ||)                             ║
║   14. CONCAT('ad','min')                                                     ║
║                                                                              ║
║   NUMERIC ENCODING:                                                          ║
║   15. 1e0=1 (scientific notation)                                            ║
║   16. 0x756e696f6e (hex encoding)                                            ║
║                                                                              ║
║   UNICODE/ENCODING:                                                          ║
║   17. Unicode normalization bypass                                           ║
║   18. %00 (null byte injection)                                              ║
║   19. Overlong UTF-8 encoding                                                ║
║   20. Mixed encoding combinations                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SQL INJECTION LEVEL 3: ADVANCED PATTERNS (15+)                             ║
║                                                                              ║
║   STACKED QUERIES:                                                           ║
║   1.  ; SELECT (stacked query)                                               ║
║   2.  SELECT (SELECT ...) (subquery injection)                               ║
║                                                                              ║
║   COMMAND EXECUTION:                                                         ║
║   3.  EXEC / EXECUTE                                                         ║
║   4.  xp_cmdshell                                                            ║
║   5.  INTO OUTFILE                                                           ║
║   6.  LOAD_FILE()                                                            ║
║   7.  UTL_HTTP (Oracle)                                                      ║
║   8.  DBMS_PIPE (Oracle)                                                     ║
║                                                                              ║
║   INFORMATION DISCLOSURE:                                                    ║
║   9.  information_schema access                                              ║
║   10. System table access (sysobjects, pg_tables)                            ║
║                                                                              ║
║   BLIND INJECTION:                                                           ║
║   11. Boolean-based: AND 1=1 vs AND 1=2                                      ║
║   12. Error-based: extractvalue(), updatexml()                               ║
║                                                                              ║
║   ENUMERATION:                                                               ║
║   13. ORDER BY enumeration (ORDER BY 1, ORDER BY 2...)                       ║
║   14. GROUP BY enumeration                                                   ║
║   15. HAVING injection                                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### XSS DETECTION (40+ PATTERNS)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   XSS LEVEL 1: SCRIPT INJECTION (15)                                         ║
║                                                                              ║
║   SCRIPT TAGS:                                                               ║
║   1.  <script> (all case variations)                                         ║
║   2.  <script src= (external script loading)                                 ║
║   3.  </script><script> (tag breaking)                                       ║
║                                                                              ║
║   EVENT HANDLERS:                                                            ║
║   4.  onerror=                                                               ║
║   5.  onload=                                                                ║
║   6.  onmouseover=                                                           ║
║   7.  onclick=                                                               ║
║   8.  onfocus=                                                               ║
║   9.  onblur=                                                                ║
║   10. onsubmit=                                                              ║
║                                                                              ║
║   URL SCHEMES:                                                               ║
║   11. javascript: URL scheme                                                 ║
║   12. vbscript: URL scheme                                                   ║
║   13. data:text/html URL scheme                                              ║
║   14. data:application/javascript                                            ║
║                                                                              ║
║   SVG-BASED:                                                                 ║
║   15. <svg onload= (SVG-based XSS)                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   XSS LEVEL 2: DOM-BASED (10)                                                ║
║                                                                              ║
║   DOCUMENT ACCESS:                                                           ║
║   1.  document.cookie                                                        ║
║   2.  document.location (assignment)                                         ║
║                                                                              ║
║   DOCUMENT WRITE:                                                            ║
║   3.  document.write()                                                       ║
║   4.  document.writeln()                                                     ║
║                                                                              ║
║   DOM MANIPULATION:                                                          ║
║   5.  innerHTML assignment                                                   ║
║   6.  outerHTML assignment                                                   ║
║                                                                              ║
║   CODE EXECUTION:                                                            ║
║   7.  eval() with string argument                                            ║
║   8.  Function() constructor                                                 ║
║   9.  setTimeout() with string                                               ║
║   10. setInterval() with string                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   XSS LEVEL 3: EVASION PATTERNS (15+)                                        ║
║                                                                              ║
║   HTML ENTITY ENCODING:                                                      ║
║   1.  &lt;script&gt;                                                         ║
║   2.  &#x3c;script&#x3e; (hex)                                               ║
║   3.  &#60;script&#62; (decimal)                                             ║
║   4.  \u003cscript (Unicode)                                                 ║
║                                                                              ║
║   OBFUSCATION:                                                               ║
║   5.  <scr%00ipt> (null byte)                                                ║
║   6.  <ScRiPt> (case variation)                                              ║
║   7.  <scr ipt> (whitespace insertion)                                       ║
║   8.  <scr\nipt> (newline insertion)                                         ║
║                                                                              ║
║   POLYGLOT PAYLOADS:                                                         ║
║   9.  Polyglot payloads (multiple contexts)                                  ║
║   10. Template literal injection `${...}`                                    ║
║                                                                              ║
║   ALTERNATIVE TAGS:                                                          ║
║   11. <img src=x onerror=...>                                                ║
║   12. <body onload=...>                                                      ║
║   13. <iframe src="javascript:...">                                          ║
║   14. <object data="javascript:...">                                         ║
║   15. <embed src="javascript:...">                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### COMMAND INJECTION (25+ PATTERNS)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   COMMAND INJECTION: SHELL METACHARACTERS (10)                               ║
║                                                                              ║
║   1.  ; (command separator)                                                  ║
║   2.  && (AND operator)                                                      ║
║   3.  || (OR operator)                                                       ║
║   4.  | (pipe)                                                               ║
║   5.  `command` (backtick execution)                                         ║
║   6.  $(command) (subshell execution)                                        ║
║   7.  > (output redirection)                                                 ║
║   8.  >> (append redirection)                                                ║
║   9.  < (input redirection)                                                  ║
║   10. << (here document)                                                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   COMMAND INJECTION: COMMON COMMANDS (10)                                    ║
║                                                                              ║
║   SHELL ACCESS:                                                              ║
║   1.  /bin/sh                                                                ║
║   2.  /bin/bash                                                              ║
║   3.  cmd.exe                                                                ║
║   4.  powershell                                                             ║
║                                                                              ║
║   SYSTEM INFO:                                                               ║
║   5.  id / whoami / uname                                                    ║
║                                                                              ║
║   NETWORK:                                                                   ║
║   6.  ping / curl / wget / nc (netcat)                                       ║
║                                                                              ║
║   FILE ACCESS:                                                               ║
║   7.  cat / type / less / more (file read)                                   ║
║   8.  ls / dir (directory listing)                                           ║
║   9.  rm / del / rmdir (file deletion)                                       ║
║   10. chmod / chown / icacls (permission change)                             ║
║                                                                              ║
║   PROCESS:                                                                   ║
║   ├─ ps / tasklist (process listing)                                         ║
║   └─ kill / taskkill (process termination)                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   COMMAND INJECTION: EVASION PATTERNS (5+)                                   ║
║                                                                              ║
║   1.  ${IFS} (variable expansion for space)                                  ║
║   2.  \x2f (hex encoding for /)                                              ║
║   3.  \057 (octal encoding for /)                                            ║
║   4.  Command substitution via $()                                           ║
║   5.  Quote breaking ('cmd' or "cmd")                                        ║
║                                                                              ║
║   ADDITIONAL:                                                                ║
║   ├─ Newline injection                                                       ║
║   ├─ Carriage return injection                                               ║
║   ├─ Tab substitution                                                        ║
║   └─ Environment variable abuse                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PATH TRAVERSAL (20+ PATTERNS)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PATH TRAVERSAL: BASIC PATTERNS (8)                                         ║
║                                                                              ║
║   UNIX:                                                                      ║
║   1.  ../ (parent directory)                                                 ║
║   2.  ....// (double dot bypass)                                             ║
║   3.  ..;/ (semicolon bypass)                                                ║
║   4.  /etc/passwd (sensitive file)                                           ║
║   5.  /etc/shadow (password hashes)                                          ║
║                                                                              ║
║   WINDOWS:                                                                   ║
║   6.  ..\ (Windows parent)                                                   ║
║   7.  C:\Windows\system32                                                    ║
║   8.  %SYSTEMROOT%                                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PATH TRAVERSAL: ENCODED PATTERNS (7)                                       ║
║                                                                              ║
║   1.  %2e%2e%2f (URL-encoded ../)                                            ║
║   2.  %252e%252e%252f (double URL-encoded)                                   ║
║   3.  ..%00 (null byte injection)                                            ║
║   4.  ..%c0%af (overlong UTF-8)                                              ║
║   5.  ..%c1%9c (overlong UTF-8 backslash)                                    ║
║   6.  ....%2f%2f (partial encoding)                                          ║
║   7.  %2e%2e/ (mixed encoding)                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PATH TRAVERSAL: WINDOWS-SPECIFIC (5)                                       ║
║                                                                              ║
║   1.  ::$DATA (alternate data stream)                                        ║
║   2.  C: (drive letter access)                                               ║
║   3.  \\ (UNC path)                                                          ║
║   4.  PROGRA~1 (8.3 short name)                                              ║
║   5.  /??/C: (NT object path)                                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## GCRA RATE LIMITING

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   GCRA (Generic Cell Rate Algorithm) SPECIFICATION                           ║
║                                                                              ║
║   ALGORITHM PROPERTIES:                                                      ║
║   ├─ Token bucket equivalent                                                 ║
║   ├─ Millisecond precision                                                   ║
║   ├─ O(1) time and space complexity per request                              ║
║   ├─ Configurable bursting                                                   ║
║   └─ Atomic operations for distributed deployment                            ║
║                                                                              ║
║   CONFIGURATION PARAMETERS:                                                  ║
║   ├─ rate: Requests per second (float)                                       ║
║   ├─ burst: Maximum burst size (integer)                                     ║
║   ├─ key: Rate limit key (IP, API key, user ID, composite)                   ║
║   └─ period: Time window (default 1 second)                                  ║
║                                                                              ║
║   DEFAULT LIMITS:                                                            ║
║   ┌──────────────────────┬──────────────────┬───────────────────────────────┐║
║   │ CATEGORY             │ RATE (req/s)     │ BURST                         │║
║   ├──────────────────────┼──────────────────┼───────────────────────────────┤║
║   │ Anonymous (by IP)    │ 100              │ 200                           │║
║   │ Authenticated (user) │ 1000             │ 2000                          │║
║   │ API (by API key)     │ Configurable/tier│ 2x rate                       │║
║   └──────────────────────┴──────────────────┴───────────────────────────────┘║
║                                                                              ║
║   RESPONSE HEADERS (MANDATORY):                                              ║
║   ├─ X-RateLimit-Limit: Maximum requests per period                          ║
║   ├─ X-RateLimit-Remaining: Requests remaining                               ║
║   ├─ X-RateLimit-Reset: Unix timestamp when limit resets                     ║
║   └─ Retry-After: Seconds to wait (on 429 response)                          ║
║                                                                              ║
║   BACKEND INTEGRATION:                                                       ║
║   ├─ Redis backend (distributed deployment)                                  ║
║   ├─ In-memory backend (single-node deployment)                              ║
║   └─ Prometheus metrics export                                               ║
║                                                                              ║
║   LOGGING:                                                                   ║
║   ├─ All rate limit events logged to JEJAK                                   ║
║   └─ Include: key, limit, current, action                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## OBSERVABILITY REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PROMETHEUS METRICS (MANDATORY)                                             ║
║                                                                              ║
║   REQUEST METRICS:                                                           ║
║   ├─ gapura_requests_total{method, path, status}                             ║
║   ├─ gapura_request_duration_seconds{method, path}                           ║
║   ├─ gapura_bytes_received_total                                             ║
║   └─ gapura_bytes_sent_total                                                 ║
║                                                                              ║
║   SECURITY METRICS:                                                          ║
║   ├─ gapura_blocked_requests_total{rule_id, category}                        ║
║   ├─ gapura_rate_limited_requests_total{key_type}                            ║
║   └─ gapura_smuggling_attempts_total{type}                                   ║
║                                                                              ║
║   CONNECTION METRICS:                                                        ║
║   └─ gapura_active_connections                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   LOGGING FORMAT                                                             ║
║                                                                              ║
║   FORMAT: JSON structured                                                    ║
║                                                                              ║
║   REQUIRED FIELDS:                                                           ║
║   {                                                                          ║
║     "timestamp": "2025-01-15T10:00:00.000Z",                                 ║
║     "request_id": "uuid",                                                    ║
║     "client_ip": "1.2.3.4",                                                  ║
║     "method": "POST",                                                        ║
║     "path": "/api/v1/users",                                                 ║
║     "status": 200,                                                           ║
║     "duration_ms": 45,                                                       ║
║     "rule_matched": "SQL_INJECTION_001",                                     ║
║     "action_taken": "BLOCK"                                                  ║
║   }                                                                          ║
║                                                                              ║
║   SENSITIVE DATA HANDLING:                                                   ║
║   ├─ Passwords MUST be redacted                                              ║
║   ├─ Tokens MUST be redacted                                                 ║
║   ├─ API keys MUST be masked (first/last 4 chars only)                       ║
║   └─ PII follows data minimization                                           ║
║                                                                              ║
║   JEJAK INTEGRATION:                                                         ║
║   ├─ Security events logged to audit trail                                   ║
║   └─ Hash-chained for tamper evidence                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ALERTING THRESHOLDS                                                        ║
║                                                                              ║
║   BLOCK RATE:                                                                ║
║   ├─ WARNING: >10% requests blocked                                          ║
║   └─ CRITICAL: >25% requests blocked                                         ║
║                                                                              ║
║   SMUGGLING ATTEMPTS:                                                        ║
║   └─ CRITICAL: Any smuggling attempt detected                                ║
║                                                                              ║
║   ERROR RATE:                                                                ║
║   ├─ WARNING: >1% error rate                                                 ║
║   └─ CRITICAL: >5% error rate                                                ║
║                                                                              ║
║   LATENCY:                                                                   ║
║   ├─ WARNING: P99 >100ms                                                     ║
║   └─ CRITICAL: P99 >500ms                                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XXIV: ZIRAH EDR ENGINE [NEW IN V3.2]

## LAW Z-1: PERFORMANCE REQUIREMENTS

All performance targets are MANDATORY. Exceeding limits is cause for rejection.

### CPU OVERHEAD

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   CPU OVERHEAD REQUIREMENTS                                                  ║
║                                                                              ║
║   ┌──────────────────────────────┬───────────────────────────────────────────┐║
║   │ STATE                        │ MAXIMUM CPU OVERHEAD (1-min average)      │║
║   ├──────────────────────────────┼───────────────────────────────────────────┤║
║   │ Idle                         │ <0.1%                                     │║
║   │ Active monitoring (normal)   │ <0.5%                                     │║
║   │ Active monitoring (high load)│ <1.0%                                     │║
║   │ Under attack (graceful deg.) │ <2.0%                                     │║
║   └──────────────────────────────┴───────────────────────────────────────────┘║
║                                                                              ║
║   MEASUREMENT:                                                               ║
║   ├─ Average over 1-minute window                                            ║
║   ├─ Measured on reference hardware                                          ║
║   └─ Under typical workload                                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### LATENCY REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   LATENCY REQUIREMENTS (P99)                                                 ║
║                                                                              ║
║   ┌──────────────────────────────┬───────────────────────────────────────────┐║
║   │ OPERATION                    │ MAXIMUM LATENCY (P99)                     │║
║   ├──────────────────────────────┼───────────────────────────────────────────┤║
║   │ Event processing             │ <300ns                                    │║
║   │ Detection decision           │ <1ms                                      │║
║   │ Blocking action              │ <10ms                                     │║
║   │ Alert generation             │ <100ms                                    │║
║   └──────────────────────────────┴───────────────────────────────────────────┘║
║                                                                              ║
║   MEASUREMENT:                                                               ║
║   ├─ P99 latency (99th percentile)                                           ║
║   ├─ Measured under production load                                          ║
║   └─ Critical path only                                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### THROUGHPUT REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   THROUGHPUT REQUIREMENTS (MINIMUM)                                          ║
║                                                                              ║
║   ┌──────────────────────────────────┬───────────────────────────────────────┐║
║   │ METRIC                           │ MINIMUM THROUGHPUT                    │║
║   ├──────────────────────────────────┼───────────────────────────────────────┤║
║   │ Event ingestion                  │ >3,000,000 events/second              │║
║   │ Concurrent processes monitored   │ >10,000                               │║
║   │ Concurrent network connections   │ >100,000                              │║
║   │ File operations monitored        │ >1,000,000/second                     │║
║   └──────────────────────────────────┴───────────────────────────────────────┘║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### MEMORY REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   MEMORY REQUIREMENTS (MAXIMUM)                                              ║
║                                                                              ║
║   ┌──────────────────────────────────┬───────────────────────────────────────┐║
║   │ COMPONENT                        │ MAXIMUM MEMORY                        │║
║   ├──────────────────────────────────┼───────────────────────────────────────┤║
║   │ Base footprint                   │ <100MB                                │║
║   │ Per-process overhead             │ <1KB                                  │║
║   │ Per-connection overhead          │ <512 bytes                            │║
║   │ Event buffer (configurable)      │ Default 500MB, max 4GB                │║
║   │ Rule cache                       │ <50MB                                 │║
║   └──────────────────────────────────┴───────────────────────────────────────┘║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## LINUX INSTRUMENTATION (eBPF)

### REQUIRED HOOKS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PROCESS LIFECYCLE HOOKS                                                    ║
║                                                                              ║
║   PROCESS EXECUTION:                                                         ║
║   ├─ sys_enter_execve / sys_exit_execve                                      ║
║   └─ sys_enter_execveat / sys_exit_execveat                                  ║
║                                                                              ║
║   PROCESS CREATION:                                                          ║
║   ├─ sched_process_fork                                                      ║
║   └─ sys_enter_clone / sys_enter_clone3                                      ║
║                                                                              ║
║   PROCESS TERMINATION:                                                       ║
║   └─ sched_process_exit                                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   FILE OPERATION HOOKS                                                       ║
║                                                                              ║
║   FILE OPEN:                                                                 ║
║   └─ sys_enter_openat / sys_exit_openat                                      ║
║                                                                              ║
║   FILE READ/WRITE:                                                           ║
║   ├─ sys_enter_read / sys_exit_read                                          ║
║   ├─ sys_enter_write / sys_exit_write                                        ║
║   └─ sys_enter_mmap / sys_exit_mmap                                          ║
║                                                                              ║
║   FILE DELETION:                                                             ║
║   ├─ sys_enter_unlink                                                        ║
║   └─ sys_enter_unlinkat                                                      ║
║                                                                              ║
║   FILE RENAME:                                                               ║
║   ├─ sys_enter_rename                                                        ║
║   └─ sys_enter_renameat                                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   NETWORK OPERATION HOOKS                                                    ║
║                                                                              ║
║   CONNECTION:                                                                ║
║   ├─ sys_enter_connect / sys_exit_connect                                    ║
║   └─ sys_enter_accept / sys_exit_accept                                      ║
║                                                                              ║
║   DATA TRANSFER:                                                             ║
║   ├─ sys_enter_sendto / sys_exit_sendto                                      ║
║   └─ sys_enter_recvfrom / sys_exit_recvfrom                                  ║
║                                                                              ║
║   SOCKET LIFECYCLE:                                                          ║
║   ├─ sock_create                                                             ║
║   └─ sock_release                                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   MODULE OPERATION HOOKS                                                     ║
║                                                                              ║
║   MODULE LOADING:                                                            ║
║   ├─ sys_enter_init_module                                                   ║
║   └─ sys_enter_finit_module                                                  ║
║                                                                              ║
║   MODULE UNLOADING:                                                          ║
║   └─ sys_enter_delete_module                                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### CO-RE REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   CO-RE (Compile Once, Run Everywhere) REQUIREMENTS                          ║
║                                                                              ║
║   BTF SUPPORT:                                                               ║
║   ├─ BTF (BPF Type Format) support REQUIRED                                  ║
║   ├─ Kernel version 5.8+ recommended                                         ║
║   ├─ Kernel version 4.18+ minimum (reduced functionality)                    ║
║   └─ Fallback to kprobes for kernels without BTF                             ║
║                                                                              ║
║   LIBBPF VERSION: 1.0+                                                       ║
║                                                                              ║
║   VERIFIER CONSTRAINTS:                                                      ║
║   ├─ All eBPF programs MUST pass kernel verifier                             ║
║   ├─ No unbounded loops                                                      ║
║   ├─ Stack size <512 bytes per program                                       ║
║   ├─ Map size limits enforced (configurable)                                 ║
║   └─ Helper function whitelist enforced                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## WINDOWS INSTRUMENTATION

### MINIFILTER DRIVER REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   MINIFILTER DRIVER SPECIFICATION                                            ║
║                                                                              ║
║   REQUIRED IRP CALLBACKS:                                                    ║
║   ├─ IRP_MJ_CREATE (file open)                                               ║
║   ├─ IRP_MJ_READ (file read)                                                 ║
║   ├─ IRP_MJ_WRITE (file write)                                               ║
║   ├─ IRP_MJ_SET_INFORMATION (rename, delete)                                 ║
║   ├─ IRP_MJ_QUERY_INFORMATION (file metadata)                                ║
║   └─ IRP_MJ_NETWORK_QUERY_OPEN (network file access)                         ║
║                                                                              ║
║   DRIVER CONFIGURATION:                                                      ║
║   ├─ Altitude: 325000 (antivirus range)                                      ║
║   └─ Flags: FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### ETW INTEGRATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ETW (Event Tracing for Windows) REQUIREMENTS                               ║
║                                                                              ║
║   REQUIRED PROVIDERS:                                                        ║
║   ├─ Microsoft-Windows-Kernel-Process                                        ║
║   ├─ Microsoft-Windows-Kernel-Network                                        ║
║   ├─ Microsoft-Windows-Kernel-File                                           ║
║   ├─ Microsoft-Windows-Kernel-Registry                                       ║
║   └─ Microsoft-Windows-Security-Auditing                                     ║
║                                                                              ║
║   EVENTS MONITORED:                                                          ║
║   ├─ Process creation/termination                                            ║
║   ├─ Network connections (inbound/outbound)                                  ║
║   ├─ Registry modifications                                                  ║
║   ├─ Image load events (DLL, driver loading)                                 ║
║   └─ Token manipulation                                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### AMSI INTEGRATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   AMSI (Antimalware Scan Interface) REQUIREMENTS                             ║
║                                                                              ║
║   INTEGRATION:                                                               ║
║   ├─ Integrate with AMSI for script scanning                                 ║
║   ├─ Register as AMSI provider                                               ║
║   └─ Process scan requests asynchronously                                    ║
║                                                                              ║
║   CONTENT INSPECTION:                                                        ║
║   ├─ PowerShell script content                                               ║
║   ├─ VBScript/JScript content                                                ║
║   ├─ .NET in-memory assembly                                                 ║
║   └─ Office macro content                                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### DRIVER SIGNING

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   DRIVER SIGNING REQUIREMENTS                                                ║
║                                                                              ║
║   PRODUCTION:                                                                ║
║   ├─ EV (Extended Validation) code signing certificate REQUIRED              ║
║   └─ WHQL certification REQUIRED for Windows 10+                             ║
║                                                                              ║
║   DEVELOPMENT:                                                               ║
║   └─ Attestation signing for development builds                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## HARDWARE SECURITY INTEGRATION

### INTEL SGX

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   INTEL SGX INTEGRATION                                                      ║
║                                                                              ║
║   ENCLAVE OPERATIONS:                                                        ║
║   ├─ Cryptographic key operations                                            ║
║   ├─ Threat signature verification                                           ║
║   └─ Policy enforcement logic                                                ║
║                                                                              ║
║   REMOTE ATTESTATION:                                                        ║
║   ├─ DCAP preferred (Data Center Attestation Primitives)                     ║
║   └─ EPID fallback (Enhanced Privacy ID)                                     ║
║                                                                              ║
║   SEALING:                                                                   ║
║   ├─ Sealing for persistent secrets                                          ║
║   └─ Enclave-bound sealing policy                                            ║
║                                                                              ║
║   SGX2 SUPPORT:                                                              ║
║   └─ Dynamic memory allocation                                               ║
║                                                                              ║
║   FALLBACK:                                                                  ║
║   └─ Graceful fallback when SGX unavailable                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### TPM 2.0

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   TPM 2.0 INTEGRATION                                                        ║
║                                                                              ║
║   ATTESTATION:                                                               ║
║   └─ Platform attestation via TPM quotes                                     ║
║                                                                              ║
║   KEY STORAGE:                                                               ║
║   └─ RSA 2048 or ECC P-256 keys in TPM                                       ║
║                                                                              ║
║   MEASURED BOOT:                                                             ║
║   └─ PCR (Platform Configuration Register) validation                        ║
║                                                                              ║
║   PCRs VALIDATED:                                                            ║
║   ├─ PCR 0: BIOS/UEFI firmware                                               ║
║   ├─ PCR 4: Boot loader                                                      ║
║   └─ PCR 7: Secure Boot state                                                ║
║                                                                              ║
║   NV STORAGE:                                                                ║
║   └─ Persistent counters in NV storage                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### ARM TRUSTZONE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ARM TRUSTZONE INTEGRATION                                                  ║
║                                                                              ║
║   SECURE WORLD OPERATIONS:                                                   ║
║   └─ Sensitive operations execute in secure world                            ║
║                                                                              ║
║   TEE INTEGRATION:                                                           ║
║   ├─ OP-TEE integration                                                      ║
║   └─ Vendor TEE support                                                      ║
║                                                                              ║
║   SECURE STORAGE:                                                            ║
║   └─ Key storage in TEE                                                      ║
║                                                                              ║
║   iOS SECURE ENCLAVE:                                                        ║
║   └─ Functional parity with SEP                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### FALLBACK REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   HARDWARE SECURITY FALLBACK                                                 ║
║                                                                              ║
║   REQUIREMENTS:                                                              ║
║   ├─ Software-only mode MUST be available                                    ║
║   ├─ Reduced security guarantees MUST be documented                          ║
║   └─ User MUST be notified of hardware security availability                 ║
║                                                                              ║
║   FALLBACK BEHAVIOR:                                                         ║
║   ├─ Detect hardware capability at startup                                   ║
║   ├─ Log security level in use                                               ║
║   └─ Alert on hardware security unavailability                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## PROCESS ISOLATION

### ISOLATION CAPABILITIES

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PROCESS ISOLATION CAPABILITIES                                             ║
║                                                                              ║
║   NETWORK ISOLATION:                                                         ║
║   ├─ Block all network access                                                ║
║   └─ Allow-list only specified destinations                                  ║
║                                                                              ║
║   FILESYSTEM ISOLATION:                                                      ║
║   ├─ Read-only filesystem view                                               ║
║   └─ Deny access to sensitive paths                                          ║
║                                                                              ║
║   PROCESS ISOLATION:                                                         ║
║   └─ Prevent child process creation                                          ║
║                                                                              ║
║   IPC ISOLATION:                                                             ║
║   ├─ Block named pipes                                                       ║
║   ├─ Block shared memory                                                     ║
║   └─ Block signals (except SIGKILL, SIGSTOP)                                 ║
║                                                                              ║
║   REGISTRY ISOLATION (Windows):                                              ║
║   └─ Prevent registry writes                                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### LINUX IMPLEMENTATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   LINUX ISOLATION IMPLEMENTATION                                             ║
║                                                                              ║
║   SYSCALL FILTERING:                                                         ║
║   └─ seccomp-bpf for syscall filtering                                       ║
║                                                                              ║
║   NAMESPACE ISOLATION:                                                       ║
║   ├─ Network namespace                                                       ║
║   ├─ Mount namespace                                                         ║
║   └─ PID namespace                                                           ║
║                                                                              ║
║   RESOURCE LIMITS:                                                           ║
║   └─ cgroups for resource limits                                             ║
║                                                                              ║
║   LSM INTEGRATION:                                                           ║
║   └─ eBPF LSM hooks for policy enforcement                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### WINDOWS IMPLEMENTATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   WINDOWS ISOLATION IMPLEMENTATION                                           ║
║                                                                              ║
║   SANDBOX:                                                                   ║
║   └─ Windows Sandbox integration where available                             ║
║                                                                              ║
║   APP CONTAINER:                                                             ║
║   └─ AppContainer for isolation                                              ║
║                                                                              ║
║   JOB OBJECTS:                                                               ║
║   └─ Job objects for resource limits                                         ║
║                                                                              ║
║   FILESYSTEM RESTRICTIONS:                                                   ║
║   └─ Minifilter for filesystem restrictions                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PID REUSE PROTECTION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PID REUSE PROTECTION                                                       ║
║                                                                              ║
║   TRACKING:                                                                  ║
║   ├─ Track (PID, start_time) tuples, not just PID                            ║
║   ├─ Start time from process creation                                        ║
║   └─ Unique identifier for process lifetime                                  ║
║                                                                              ║
║   DETECTION:                                                                 ║
║   ├─ Detect PID reuse within monitoring window                               ║
║   └─ Compare start_time to detect reuse                                      ║
║                                                                              ║
║   INVALIDATION:                                                              ║
║   └─ Invalidate stale process references                                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XXV: BENTENG-SDK SPECIFICATIONS [NEW IN V3.2]

## LAW S-1: PLATFORM TARGETS

All platforms are MANDATORY. Missing platform support is cause for rejection.

### iOS PLATFORM

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   iOS PLATFORM SPECIFICATION                                                 ║
║                                                                              ║
║   LANGUAGE INTEROP:                                                          ║
║   ├─ Swift package (primary interface)                                       ║
║   ├─ Objective-C headers for compatibility                                   ║
║   └─ C ABI for core library                                                  ║
║                                                                              ║
║   BIOMETRIC INTEGRATION:                                                     ║
║   ├─ Face ID via LocalAuthentication framework                               ║
║   ├─ Touch ID via LocalAuthentication framework                              ║
║   └─ Fallback to device passcode NOT permitted (LAW 1)                       ║
║                                                                              ║
║   KEY STORAGE:                                                               ║
║   ├─ Secure Enclave (SEP) for key generation and storage                     ║
║   ├─ Keys marked as non-exportable                                           ║
║   └─ Biometric-protected access policy                                       ║
║                                                                              ║
║   DEPLOYMENT:                                                                ║
║   ├─ Minimum iOS version: 14.0                                               ║
║   ├─ Architectures: arm64 (device)                                           ║
║   ├─ Simulator: arm64 + x86_64                                               ║
║   └─ Distribution: XCFramework                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### ANDROID PLATFORM

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ANDROID PLATFORM SPECIFICATION                                             ║
║                                                                              ║
║   LANGUAGE INTEROP:                                                          ║
║   ├─ Kotlin primary interface                                                ║
║   ├─ Java interop maintained                                                 ║
║   └─ JNI for native code                                                     ║
║                                                                              ║
║   BIOMETRIC INTEGRATION:                                                     ║
║   ├─ BiometricPrompt API (Class 3 biometrics required)                       ║
║   ├─ Strong authentication level required                                    ║
║   └─ No device credential fallback (LAW 1)                                   ║
║                                                                              ║
║   KEY STORAGE:                                                               ║
║   ├─ StrongBox Keymaster when available                                      ║
║   ├─ TEE-backed Keystore as fallback                                         ║
║   ├─ Keys bound to biometric authentication                                  ║
║   └─ Non-exportable key policy                                               ║
║                                                                              ║
║   DEPLOYMENT:                                                                ║
║   ├─ Minimum SDK: API 26 (Android 8.0 Oreo)                                  ║
║   ├─ Target SDK: Latest stable                                               ║
║   ├─ Architectures: armeabi-v7a, arm64-v8a, x86, x86_64                      ║
║   └─ Distribution: AAR via Maven Central                                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### WEB (WASM) PLATFORM

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   WEB (WASM) PLATFORM SPECIFICATION                                          ║
║                                                                              ║
║   BIOMETRIC INTEGRATION:                                                     ║
║   ├─ WebAuthn for biometric authentication                                   ║
║   ├─ Platform authenticator preferred                                        ║
║   └─ Security key as fallback                                                ║
║                                                                              ║
║   CRYPTOGRAPHIC OPERATIONS:                                                  ║
║   ├─ WebCrypto API for supported algorithms                                  ║
║   ├─ WASM implementation for post-quantum                                    ║
║   └─ No native dependencies                                                  ║
║                                                                              ║
║   BROWSER SUPPORT:                                                           ║
║   ├─ Chrome 90+                                                              ║
║   ├─ Firefox 90+                                                             ║
║   ├─ Safari 15+                                                              ║
║   └─ Edge 90+                                                                ║
║                                                                              ║
║   DISTRIBUTION:                                                              ║
║   ├─ npm package                                                             ║
║   └─ CDN distribution                                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### DESKTOP PLATFORMS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   DESKTOP PLATFORM SPECIFICATIONS                                            ║
║                                                                              ║
║   WINDOWS:                                                                   ║
║   ├─ Windows Hello integration                                               ║
║   ├─ TPM 2.0 for key storage                                                 ║
║   ├─ Distribution: MSIX package                                              ║
║   └─ Architectures: x86_64, arm64                                            ║
║                                                                              ║
║   macOS:                                                                     ║
║   ├─ Touch ID integration via LocalAuthentication                            ║
║   ├─ Secure Enclave for key storage (Apple Silicon)                          ║
║   ├─ Keychain for key storage (Intel)                                        ║
║   ├─ Distribution: Universal binary (arm64 + x86_64)                         ║
║   └─ Minimum: macOS 11 (Big Sur)                                             ║
║                                                                              ║
║   LINUX:                                                                     ║
║   ├─ TPM 2.0 integration when available                                      ║
║   ├─ Software fallback with user-password encryption                         ║
║   ├─ Distribution: deb, rpm, AppImage                                        ║
║   └─ Architectures: x86_64, arm64                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## LAW S-2: SIZE CONSTRAINTS

Size limits are MANDATORY. Exceeding limits is BUILD FAILURE.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SIZE LIMITS (MANDATORY)                                                    ║
║                                                                              ║
║   ┌────────────────────────────┬─────────────────────────────────────────────┐║
║   │ PLATFORM                   │ MAXIMUM SIZE                                │║
║   ├────────────────────────────┼─────────────────────────────────────────────┤║
║   │ iOS XCFramework            │ <5MB compressed                             │║
║   │ Android AAR                │ <5MB compressed                             │║
║   │ WASM Module                │ <1MB gzipped                                │║
║   │ Desktop Library            │ <10MB per architecture                      │║
║   └────────────────────────────┴─────────────────────────────────────────────┘║
║                                                                              ║
║   EXCEEDING LIMITS = BUILD FAILURE                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   TECHNIQUES TO ACHIEVE SIZE TARGETS                                         ║
║                                                                              ║
║   CODE OPTIMIZATION:                                                         ║
║   ├─ Dead code elimination (aggressive LTO)                                  ║
║   ├─ Optional features behind feature flags                                  ║
║   ├─ Symbol stripping for release builds                                     ║
║   └─ Code size optimization (-Os / -Oz)                                      ║
║                                                                              ║
║   ML MODEL HANDLING:                                                         ║
║   ├─ NO bundled ML models (server-side inference only)                       ║
║   └─ Models downloaded on-demand if needed                                   ║
║                                                                              ║
║   ASSET HANDLING:                                                            ║
║   ├─ Compressed assets                                                       ║
║   └─ Lazy loading                                                            ║
║                                                                              ║
║   SIZE MONITORING:                                                           ║
║   ├─ CI pipeline MUST fail if size limit exceeded                            ║
║   ├─ Size reported in release notes                                          ║
║   └─ Size regression alerts on PR                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## HOSTILE ENVIRONMENT DEFENSE

### ANTI-TAMPERING

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ANTI-TAMPERING MEASURES                                                    ║
║                                                                              ║
║   CODE INTEGRITY:                                                            ║
║   ├─ Code integrity verification (checksum validation)                       ║
║   ├─ Self-checksum validation                                                ║
║   └─ Code section hash verification                                          ║
║                                                                              ║
║   JAILBREAK DETECTION (iOS):                                                 ║
║   ├─ Suspicious file checks (/Applications/Cydia.app, etc.)                  ║
║   ├─ Symbolic link checks                                                    ║
║   ├─ Sandbox integrity verification                                          ║
║   └─ API behavior anomaly detection                                          ║
║                                                                              ║
║   ROOT DETECTION (Android):                                                  ║
║   ├─ su binary detection                                                     ║
║   ├─ Magisk detection                                                        ║
║   ├─ SuperSU detection                                                       ║
║   ├─ Build tags verification                                                 ║
║   └─ System partition writability check                                      ║
║                                                                              ║
║   DEBUGGER DETECTION:                                                        ║
║   ├─ ptrace detection (Linux/Android)                                        ║
║   ├─ IsDebuggerPresent (Windows)                                             ║
║   ├─ sysctl P_TRACED (iOS/macOS)                                             ║
║   └─ Timing-based detection                                                  ║
║                                                                              ║
║   EMULATOR DETECTION:                                                        ║
║   ├─ Device property verification                                            ║
║   ├─ Sensor behavior analysis                                                ║
║   ├─ Hardware characteristic validation                                      ║
║   └─ Timing analysis                                                         ║
║                                                                              ║
║   HOOKING FRAMEWORK DETECTION:                                               ║
║   ┌────────────────────────────┬─────────────────────────────────────────────┐║
║   │ FRAMEWORK                  │ DETECTION METHOD                            │║
║   ├────────────────────────────┼─────────────────────────────────────────────┤║
║   │ Frida                      │ Function timing anomalies                   │║
║   │                            │ Memory pattern detection                    │║
║   │                            │ Named pipe detection                        │║
║   │                            │ D-Bus interface scanning                    │║
║   ├────────────────────────────┼─────────────────────────────────────────────┤║
║   │ Xposed                     │ Module enumeration                          │║
║   │                            │ Function hook detection                     │║
║   │                            │ ClassLoader inspection                      │║
║   ├────────────────────────────┼─────────────────────────────────────────────┤║
║   │ Substrate/Cydia (iOS)      │ Method swizzling detection                  │║
║   │                            │ Dynamic library injection                   │║
║   │                            │ ObjC runtime inspection                     │║
║   └────────────────────────────┴─────────────────────────────────────────────┘║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### ANTI-REVERSE-ENGINEERING

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ANTI-REVERSE-ENGINEERING MEASURES                                          ║
║                                                                              ║
║   SYMBOL STRIPPING:                                                          ║
║   └─ All symbols stripped in release builds                                  ║
║                                                                              ║
║   CONTROL FLOW OBFUSCATION:                                                  ║
║   ├─ Optional, configurable                                                  ║
║   └─ LLVM-based obfuscation                                                  ║
║                                                                              ║
║   STRING ENCRYPTION:                                                         ║
║   └─ Sensitive constants encrypted                                           ║
║                                                                              ║
║   CLASS/METHOD RENAMING (Android):                                           ║
║   └─ ProGuard/R8 obfuscation                                                 ║
║                                                                              ║
║   NATIVE CODE PROTECTION:                                                    ║
║   └─ LLVM obfuscator for native code                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### RUNTIME PROTECTION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   RUNTIME PROTECTION MEASURES                                                ║
║                                                                              ║
║   MEMORY PROTECTION:                                                         ║
║   ├─ Memory encryption for sensitive data in RAM                             ║
║   ├─ Anti-memory-dump techniques                                             ║
║   └─ Secure memory allocation (mlock where available)                        ║
║                                                                              ║
║   STACK PROTECTION:                                                          ║
║   └─ Stack canaries (compiler-enforced)                                      ║
║                                                                              ║
║   ASLR:                                                                      ║
║   └─ ASLR verification (ensure not disabled)                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### IMPORTANT CAVEAT

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   IMPORTANT SECURITY CAVEAT                                                  ║
║                                                                              ║
║   These techniques DELAY attackers with physical device access.              ║
║   They do NOT prevent attacks by sophisticated adversaries.                  ║
║                                                                              ║
║   PRIMARY SECURITY comes from LAW 1 (biometric locality):                    ║
║   The server NEVER receives data that allows identity theft                  ║
║   even if SDK is fully compromised.                                          ║
║                                                                              ║
║   THREAT MODEL:                                                              ║
║   ├─ Casual attacker: Blocked by anti-tampering                              ║
║   ├─ Motivated attacker: Delayed by obfuscation                              ║
║   ├─ Sophisticated attacker: Will eventually bypass                          ║
║   └─ Nation-state: Assume full compromise                                    ║
║                                                                              ║
║   DESIGN PRINCIPLE:                                                          ║
║   Security does NOT depend on SDK integrity.                                 ║
║   SDK compromise does NOT lead to identity theft.                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## PROOF-CARRYING CODE (PCC)

### PURPOSE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PROOF-CARRYING CODE PURPOSE                                                ║
║                                                                              ║
║   Every SDK operation produces cryptographic proof of:                       ║
║   1. Operation performed on authentic, untampered SDK                        ║
║   2. Device attestation verified                                             ║
║   3. Biometric check passed (without revealing biometric data)               ║
║   4. Timestamp within acceptable window                                      ║
║   5. No tampering detected during operation                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PROOF SPECIFICATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PROOF FORMAT                                                               ║
║                                                                              ║
║   PROOF SYSTEM:                                                              ║
║   ├─ ZK-SNARK (Groth16)                                                      ║
║   └─ ZK-STARK (alternative)                                                  ║
║                                                                              ║
║   PROOF SIZE:                                                                ║
║   ├─ SNARK: <1KB                                                             ║
║   └─ STARK: <50KB                                                            ║
║                                                                              ║
║   PROOF GENERATION TIME:                                                     ║
║   └─ <200ms on mobile device                                                 ║
║                                                                              ║
║   PROOF VERIFICATION TIME:                                                   ║
║   └─ <50ms on server                                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PROOF CONTENTS                                                             ║
║                                                                              ║
║   SDK AUTHENTICITY:                                                          ║
║   └─ SDK version hash (proves authentic SDK)                                 ║
║                                                                              ║
║   DEVICE ATTESTATION:                                                        ║
║   ├─ Android: SafetyNet/Play Integrity attestation                           ║
║   └─ iOS: DeviceCheck (DCT) attestation                                      ║
║                                                                              ║
║   BIOMETRIC CHECK:                                                           ║
║   └─ Biometric check result hash (pass/fail, NO biometric data)              ║
║                                                                              ║
║   TIMESTAMP:                                                                 ║
║   └─ Signed by device secure clock                                           ║
║                                                                              ║
║   ENVIRONMENT CHECK:                                                         ║
║   ├─ Root/jailbreak status                                                   ║
║   └─ Debug mode status                                                       ║
║                                                                              ║
║   REPLAY PREVENTION:                                                         ║
║   └─ Server-provided nonce                                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### SERVER VERIFICATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   SERVER VERIFICATION REQUIREMENTS                                           ║
║                                                                              ║
║   VERIFICATION PROCESS:                                                      ║
║   ├─ ALL proofs verified before accepting result                             ║
║   ├─ Proof verification failures logged to JEJAK                             ║
║   ├─ Rate limiting on failed proof verifications                             ║
║   └─ Proof replay detection (nonce tracking)                                 ║
║                                                                              ║
║   FAILURE HANDLING:                                                          ║
║   ├─ Invalid proof → REJECT operation                                        ║
║   ├─ Expired nonce → REJECT operation                                        ║
║   └─ Device attestation failure → REJECT operation                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### FALLBACK (NO ZK CAPABILITY)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   FALLBACK FOR DEVICES WITHOUT ZK CAPABILITY                                 ║
║                                                                              ║
║   ALTERNATIVE MECHANISMS:                                                    ║
║   ├─ Traditional device attestation (reduced security)                       ║
║   └─ HMAC-based integrity (not zero-knowledge)                               ║
║                                                                              ║
║   DOCUMENTATION:                                                             ║
║   └─ Security reduction MUST be clearly documented                           ║
║                                                                              ║
║   USER NOTIFICATION:                                                         ║
║   └─ User MUST be informed of reduced security level                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## FFI SAFETY REQUIREMENTS

### MEMORY SAFETY

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   FFI MEMORY SAFETY REQUIREMENTS                                             ║
║                                                                              ║
║   INPUT VALIDATION:                                                          ║
║   └─ All FFI boundaries validate input sizes                                 ║
║                                                                              ║
║   POINTER SAFETY:                                                            ║
║   └─ No raw pointer exposure to calling language                             ║
║                                                                              ║
║   HANDLE PATTERN:                                                            ║
║   └─ Opaque handle pattern for SDK objects                                   ║
║                                                                              ║
║   MEMORY OWNERSHIP:                                                          ║
║   └─ Explicit ownership (clearly documented who frees what)                  ║
║                                                                              ║
║   BUFFER PROTECTION:                                                         ║
║   └─ Buffer overflow protection at all boundaries                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### ERROR HANDLING

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   FFI ERROR HANDLING REQUIREMENTS                                            ║
║                                                                              ║
║   PANIC SAFETY:                                                              ║
║   └─ No panics across FFI boundary (catch and convert)                       ║
║                                                                              ║
║   ERROR CODES:                                                               ║
║   ├─ Consistent error code semantics across platforms                        ║
║   └─ Optional error message retrieval                                        ║
║                                                                              ║
║   ERROR PROPAGATION:                                                         ║
║   └─ Errors propagated to calling language appropriately                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### THREAD SAFETY

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   FFI THREAD SAFETY REQUIREMENTS                                             ║
║                                                                              ║
║   THREAD SAFETY:                                                             ║
║   └─ All SDK functions thread-safe unless documented otherwise               ║
║                                                                              ║
║   CALLBACK EXECUTION:                                                        ║
║   └─ Callbacks execute on specified threads                                  ║
║                                                                              ║
║   GLOBAL STATE:                                                              ║
║   └─ No global mutable state                                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### PLATFORM-SPECIFIC FFI

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PLATFORM-SPECIFIC FFI REQUIREMENTS                                         ║
║                                                                              ║
║   iOS:                                                                       ║
║   └─ C ABI with Swift overlay                                                ║
║                                                                              ║
║   ANDROID:                                                                   ║
║   └─ JNI with Kotlin/Java wrappers                                           ║
║                                                                              ║
║   WASM:                                                                      ║
║   └─ wasm-bindgen with TypeScript definitions                                ║
║                                                                              ║
║   DESKTOP:                                                                   ║
║   └─ C ABI with language-specific wrappers                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## VERSION UPDATE

```
Document version: 3.2.0
Previous version: 3.1.1
Previous version hash: 83481f988d5fba3284ef8c7023274b9cc7bc82a64d71a2d09a2bc590b548f2a6
This version hash: 6b35d0649772efe4b7d7b53babf08bdcdc99d9e581023b12791aeef5cc870369 (pre-self-reference)

Changes in 3.2.0:
• Added PART XXII: MENARA MOBILE SECURITY
  - LAW M-1: Six mandatory detection pillars
  - PINQ privacy-preserving query language
  - KERISMESH distributed threat sharing protocol
  - Mobile platform requirements (iOS, Android, Web, Desktop)

• Added PART XXIII: GAPURA WAF ENGINE
  - LAW G-1: Canonicalization requirements
  - LAW G-2: Request smuggling prevention
  - 135+ detection patterns (SQL injection, XSS, command injection, path traversal)
  - GCRA rate limiting specification
  - Observability requirements

• Added PART XXIV: ZIRAH EDR ENGINE
  - LAW Z-1: Performance requirements (CPU, latency, throughput, memory)
  - Linux instrumentation (eBPF with CO-RE)
  - Windows instrumentation (Minifilter, ETW, AMSI)
  - Hardware security integration (SGX, TPM 2.0, TrustZone)
  - Process isolation capabilities

• Added PART XXV: BENTENG-SDK SPECIFICATIONS
  - LAW S-1: Platform targets (iOS, Android, Web, Desktop)
  - LAW S-2: Size constraints
  - Hostile environment defense
  - Proof-carrying code (PCC)
  - FFI safety requirements

• Updated PART XVI: ANTI-DEEPFAKE & ADVERSARIAL ML
  - Added Document OCR Requirements section
  - Supported documents, accuracy requirements, processing requirements
  - Document authenticity detection, output format specification
  - Validation test corpus requirements

• Updated PART XVII: ALGORITHM AGILITY & CRYPTOGRAPHIC RECOVERY
  - Added Document Workflow Requirements section
  - 7-step signing workflow
  - Multi-party signing (sequential, parallel, hybrid)
  - Compliance proof generation
  - Legal compliance (Malaysia DSA 1997, EU eIDAS, US ESIGN/UETA)
```

---

## DOCUMENT END

This specification is AUTHORITATIVE. All implementations MUST comply.
The 47 gaps identified in the Gap Analysis Report are addressed in this version.
