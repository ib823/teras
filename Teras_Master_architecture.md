# TERAS MASTER ARCHITECTURE v3.1.0

> **CLASSIFICATION:** AUTHORITATIVE SPECIFICATION
> **VERSION:** 3.1.0
> **DATE:** 2025-12-30
> **STATUS:** BINDING
> **PREVIOUS VERSION HASH (V3.0.0):** [SHA-256 of V3.0.0 to be computed]

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
PART XV:   THREAT COVERAGE MATRIX (What is/isn't covered) [NEW]
PART XVI:  ANTI-DEEPFAKE & ADVERSARIAL ML [NEW]
PART XVII: ALGORITHM AGILITY & CRYPTOGRAPHIC RECOVERY [NEW]
PART XVIII: BEHAVIORAL DETECTION & 0-DAY DEFENSE [NEW]
PART XIX:  DDOS MITIGATION & AVAILABILITY [NEW]
PART XX:   AUDIT LOGGING & INSIDER THREAT [NEW]
PART XXI:  DEVICE BINDING & SIM-SWAP RESISTANCE [NEW]
```

---

# PART I: IMMUTABLE LAWS

These laws **CANNOT** be changed, relaxed, or "temporarily suspended for MVP."

## LAW 1: BIOMETRIC DATA LOCALITY

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   BIOMETRIC DATA (face images, fingerprints, voice prints, iris scans)      ║
║   MUST NEVER leave the user's device in any form that allows reconstruction.║
║                                                                              ║
║   PERMITTED:                                                                 ║
║   • Cryptographic hash of biometric (non-reversible)                        ║
║   • Zero-knowledge proof about biometric                                    ║
║   • Encrypted biometric that ONLY user can decrypt                          ║
║   • Signed attestation that matching succeeded (no biometric data)          ║
║                                                                              ║
║   PROHIBITED:                                                                ║
║   • Raw biometric to any server                                             ║
║   • Encrypted biometric where server has key                                ║
║   • "Anonymized" biometric (still reconstructable)                          ║
║   • Biometric "for debugging"                                               ║
║   • Biometric "with user consent" (consent doesn't change the law)          ║
║   • Biometric embeddings/vectors to server (reconstructable)                ║
║   • Face templates to server                                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**VALIDATION:** Any network packet containing >1KB of data derived from biometric source MUST be inspectable and proven to be non-reversible.

## LAW 2: CRYPTOGRAPHIC NON-NEGOTIABLES

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   CRYPTOGRAPHIC REQUIREMENTS                                                 ║
║                                                                              ║
║   KEY SIZES (MINIMUM):                                                       ║
║   • Symmetric: 256 bits                                                      ║
║   • Asymmetric (classical): 256 bits (EC) or 3072 bits (RSA)                ║
║   • Post-quantum KEM: ML-KEM-768 (NIST Level 3)                             ║
║   • Post-quantum Signature: ML-DSA-65 (NIST Level 3)                        ║
║   • Hash: 256 bits output minimum                                           ║
║                                                                              ║
║   ALGORITHMS (ALLOWED - PRIMARY):                                            ║
║   • Symmetric: AES-256-GCM, ChaCha20-Poly1305                               ║
║   • Hash: SHA-3-256, SHA-256, BLAKE3                                        ║
║   • KEM: ML-KEM-768, X25519 (classical), HYBRID of both (RECOMMENDED)       ║
║   • Signature: ML-DSA-65, Ed25519, SLH-DSA-SHAKE-128f                       ║
║   • KDF: HKDF-SHA256, HKDF-SHA3-256, Argon2id (passwords only)              ║
║                                                                              ║
║   ALGORITHMS (ALLOWED - BACKUP/EMERGENCY):                                   ║
║   • KEM: Classic McEliece (if ML-KEM breaks)                                ║
║   • Signature: SLH-DSA-SHAKE-256f (if ML-DSA breaks)                        ║
║   • Hash-based: XMSS, LMS (for long-term archival)                          ║
║                                                                              ║
║   ALGORITHMS (PROHIBITED):                                                   ║
║   • MD5, SHA-1 (any use)                                                     ║
║   • DES, 3DES, RC4, Blowfish                                                ║
║   • RSA < 3072 bits                                                          ║
║   • ECDSA with curves < 256 bits                                            ║
║   • Any algorithm not explicitly listed above                                ║
║                                                                              ║
║   HYBRID MODE (MANDATORY FOR ALL NEW DEPLOYMENTS):                           ║
║   • KEM: ML-KEM-768 + X25519 (both must succeed)                            ║
║   • Signature: ML-DSA-65 + Ed25519 (both must verify)                       ║
║   • Rationale: If either classical or PQ breaks, other provides security    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**VALIDATION:** Code review must grep for prohibited algorithm names. Any match is build failure.

## LAW 3: CONSTANT-TIME REQUIREMENT

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ALL operations on secret data MUST be constant-time.                       ║
║                                                                              ║
║   SECRET DATA INCLUDES:                                                      ║
║   • Private keys                                                             ║
║   • Session keys                                                             ║
║   • Passwords                                                                ║
║   • Biometric embeddings                                                     ║
║   • Any data used in cryptographic operations                                ║
║   • Comparison results before they are public                                ║
║                                                                              ║
║   CONSTANT-TIME MEANS:                                                       ║
║   • No branching based on secret values                                      ║
║   • No array indexing based on secret values                                 ║
║   • No early returns based on secret values                                  ║
║   • No variable-time CPU instructions on secrets                             ║
║   • No cache-timing variations based on secrets                              ║
║                                                                              ║
║   VERIFICATION METHOD:                                                       ║
║   • Run dudect with t-value threshold < 4.5                                  ║
║   • Minimum 1 million measurements                                           ║
║   • Test on target platform (not just dev machine)                           ║
║   • Re-run after ANY change to crypto code                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**VALIDATION:** dudect test must pass before any crypto code is merged.

## LAW 4: SECRET ZEROIZATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ALL secrets MUST be zeroized when no longer needed.                        ║
║                                                                              ║
║   ZEROIZATION REQUIREMENTS:                                                  ║
║   • Use volatile writes (prevent compiler optimization)                      ║
║   • Memory barrier after zeroing                                             ║
║   • Verification read in debug builds                                        ║
║                                                                              ║
║   IMPLEMENTATION (EXACT CODE):                                               ║
║                                                                              ║
║   ```rust                                                                    ║
║   pub fn zeroize_bytes(bytes: &mut [u8]) {                                  ║
║       use core::sync::atomic::{compiler_fence, Ordering};                   ║
║       for byte in bytes.iter_mut() {                                        ║
║           unsafe { std::ptr::write_volatile(byte, 0); }                     ║
║       }                                                                      ║
║       compiler_fence(Ordering::SeqCst);                                     ║
║   }                                                                          ║
║   ```                                                                        ║
║                                                                              ║
║   This exact implementation MUST be used. No variations.                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**VALIDATION:** Miri must not detect UB. ASAN must not detect use-after-free.

## LAW 5: NO TRUST IN INFRASTRUCTURE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   The following are considered HOSTILE and MUST NOT be trusted:              ║
║                                                                              ║
║   • Cloud providers (AWS, GCP, Azure, Vercel, etc.)                          ║
║   • Operating systems (iOS, Android, Windows, Linux, macOS)                  ║
║   • Network infrastructure (ISPs, routers, DNS)                              ║
║   • Certificate authorities                                                  ║
║   • App stores (Apple, Google)                                               ║
║   • Hardware (CPUs, TPMs, Secure Enclaves)                                   ║
║   • Third-party libraries (even audited ones)                                ║
║   • Build systems (compilers, linkers)                                       ║
║   • SMS networks (SIM swap vulnerable)                                       ║
║   • Email providers (account takeover vulnerable)                            ║
║   • Phone numbers as identity                                                ║
║                                                                              ║
║   WHAT THIS MEANS:                                                           ║
║   • Encryption MUST use our keys, not platform keys                          ║
║   • Verification MUST happen in our code, not platform APIs                  ║
║   • Secrets MUST be encrypted before touching platform storage               ║
║   • Network MUST be encrypted with our TLS, certificate-pinned               ║
║   • Identity MUST be device-bound, not phone-number-bound                    ║
║   • Authentication MUST NOT use SMS OTP or email OTP alone                   ║
║                                                                              ║
║   EXCEPTIONS (USE PLATFORM AS ADDITIONAL LAYER ONLY):                        ║
║   • Platform secure storage (Keychain, Keystore) for ADDITIONAL protection   ║
║   • Platform biometrics (Face ID) for ADDITIONAL authentication              ║
║   • NEVER as the ONLY protection                                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## LAW 6: FAIL SECURE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   On ANY error, the system MUST deny access.                                 ║
║                                                                              ║
║   PROHIBITED:                                                                ║
║   • "If verification fails, fall back to less secure method"                 ║
║   • "If crypto fails, proceed without encryption"                            ║
║   • "If network fails, cache credentials"                                    ║
║   • "If parsing fails, use default value"                                    ║
║   • "If liveness fails, try again with relaxed threshold"                    ║
║   • "If deepfake detection times out, skip it"                               ║
║   • Any form of "fail open"                                                  ║
║                                                                              ║
║   REQUIRED:                                                                  ║
║   • Error → Deny access                                                      ║
║   • Error → Log (without secrets)                                            ║
║   • Error → Alert user                                                       ║
║   • Error → Zeroize any partial state                                        ║
║   • Error → Increment failure counter for anomaly detection                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## LAW 7: REPRODUCIBLE BUILDS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   Every build MUST be reproducible.                                          ║
║                                                                              ║
║   Given:                                                                     ║
║   • Same source code (git commit hash)                                       ║
║   • Same toolchain version (exact rustc version)                             ║
║   • Same target platform                                                     ║
║                                                                              ║
║   Result:                                                                    ║
║   • Byte-identical binary                                                    ║
║                                                                              ║
║   REQUIREMENTS:                                                              ║
║   • Cargo.lock MUST be committed                                             ║
║   • All deps vendored with hash verification                                 ║
║   • No build timestamps embedded                                             ║
║   • No random values in build                                                ║
║   • Docker build environment with pinned versions                            ║
║   • Diverse double-compilation for compiler trust                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## LAW 8: COMPREHENSIVE AUDIT LOGGING [NEW IN V3.1]

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ALL security-relevant events MUST be logged.                               ║
║                                                                              ║
║   EVERY LOG ENTRY MUST CONTAIN:                                              ║
║   • Timestamp (NTP-synced, tamper-evident)                                   ║
║   • Actor (user ID, service account, system)                                 ║
║   • Action (what was attempted)                                              ║
║   • Object (what was accessed)                                               ║
║   • Result (success/failure)                                                 ║
║   • Context (IP, device fingerprint, location)                               ║
║                                                                              ║
║   LOG PROTECTION:                                                            ║
║   • Append-only (cannot delete or modify)                                    ║
║   • Cryptographically chained (tamper-evident hash chain)                    ║
║   • Replicated (minimum 2 geographically separate locations)                 ║
║   • Retention: 7 years minimum                                               ║
║   • Encrypted at rest and in transit                                         ║
║                                                                              ║
║   PROHIBITED IN LOGS:                                                        ║
║   • Secrets, keys, passwords                                                 ║
║   • Biometric data                                                           ║
║   • Full credit card numbers                                                 ║
║   • Unredacted personal data beyond what's needed                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART II: CURRENT REALITY

This section describes what **ACTUALLY EXISTS AND WORKS TODAY**. 
Not aspirational. Not future. Not "could be built."

## REALITY 1: TERAS-LANG DOES NOT EXIST

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STATUS: TERAS-LANG is a FUTURE VISION, not current reality.                ║
║                                                                              ║
║   CURRENT IMPLEMENTATION LANGUAGE: Rust                                      ║
║   CURRENT VERIFICATION TOOLS:                                                ║
║   • Kani (model checking)                                                    ║
║   • cargo-fuzz (fuzzing)                                                     ║
║   • Miri (UB detection)                                                      ║
║   • dudect (timing verification)                                             ║
║   • clippy (linting)                                                         ║
║                                                                              ║
║   DO NOT:                                                                    ║
║   • Claim to implement TERAS-LANG                                            ║
║   • Create a "simplified TERAS-LANG"                                         ║
║   • Use TERAS-LANG syntax in production code                                 ║
║                                                                              ║
║   DO:                                                                        ║
║   • Write Rust with verification annotations                                 ║
║   • Use Kani proofs for critical code                                        ║
║   • Follow the coding standards in Part IV                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## REALITY 2: ZK FOR BIOMETRICS IS RESEARCH-STAGE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STATUS: Zero-knowledge proofs for biometric matching are NOT production-   ║
║           ready for mobile devices.                                          ║
║                                                                              ║
║   CURRENT STATE OF THE ART:                                                  ║
║   • ZK for simple statements (age > 18): FEASIBLE, ~100ms                   ║
║   • ZK for hash preimage: FEASIBLE, ~500ms                                  ║
║   • ZK for 512-dim float cosine similarity: INFEASIBLE on mobile            ║
║     - Estimated circuit size: 10+ million constraints                        ║
║     - Estimated proving time: 10+ minutes on mobile                          ║
║     - Memory requirement: 8+ GB RAM                                          ║
║                                                                              ║
║   BENTENG PHASE 1 APPROACH (CURRENT):                                        ║
║   • Face matching happens ON-DEVICE (not server)                             ║
║   • Server receives: signed attestation "match succeeded" + liveness proof  ║
║   • NOT a ZK proof of the matching itself                                    ║
║   • This STILL satisfies LAW 1 (biometrics don't leave device)              ║
║                                                                              ║
║   BENTENG FUTURE (RESEARCH):                                                 ║
║   • Investigate ZK-friendly face embedding models                            ║
║   • Investigate integer-only similarity (avoid floats)                       ║
║   • Investigate proof aggregation                                            ║
║                                                                              ║
║   DO NOT:                                                                    ║
║   • Claim ZK face verification is implemented                                ║
║   • "Simplify" by sending face data to server                                ║
║   • Skip liveness detection "for MVP"                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## REALITY 3: AVAILABLE CRYPTOGRAPHIC LIBRARIES

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   APPROVED LIBRARIES (with exact versions):                                  ║
║                                                                              ║
║   POST-QUANTUM (PRIMARY):                                                    ║
║   • ml-kem = "=0.2.1"          # ML-KEM-768 key encapsulation                ║
║   • ml-dsa = "=0.1.0"          # ML-DSA-65 signatures                        ║
║   • slh-dsa = "=0.1.0"         # SLH-DSA-SHAKE-128f signatures (BACKUP)      ║
║                                                                              ║
║   CLASSICAL:                                                                 ║
║   • x25519-dalek = "=2.0.1"    # X25519 key exchange                         ║
║   • ed25519-dalek = "=2.1.1"   # Ed25519 signatures                          ║
║   • aes-gcm = "=0.10.3"        # AES-256-GCM                                  ║
║   • chacha20poly1305 = "=0.10.1" # ChaCha20-Poly1305                         ║
║   • sha3 = "=0.10.8"           # SHA-3                                        ║
║   • sha2 = "=0.10.8"           # SHA-256                                      ║
║   • blake3 = "=1.5.0"          # BLAKE3                                       ║
║   • hkdf = "=0.12.4"           # HKDF                                         ║
║   • argon2 = "=0.5.3"          # Argon2id                                     ║
║                                                                              ║
║   UTILITIES:                                                                 ║
║   • zeroize = "=1.7.0"         # Secure memory zeroing                       ║
║   • rand = "=0.8.5"            # Randomness (with OsRng)                     ║
║   • rand_core = "=0.6.4"       # RNG traits                                  ║
║   • subtle = "=2.5.0"          # Constant-time primitives                    ║
║                                                                              ║
║   PROHIBITED:                                                                ║
║   • ring (complex, some unsafe)                                              ║
║   • openssl (C, memory unsafe)                                               ║
║   • Any library not on this list                                             ║
║                                                                              ║
║   ADDING NEW LIBRARY REQUIRES:                                               ║
║   • Security audit                                                           ║
║   • Version pinning in Cargo.toml                                            ║
║   • Hash verification in Cargo.lock                                          ║
║   • Update to this document                                                  ║
║   • Approval from document maintainer                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## REALITY 4: PLATFORM CAPABILITIES (HONEST ASSESSMENT)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   iOS:                                                                       ║
║   ├─ CAN DO:                                                                 ║
║   │  • Run our crypto (in native code)                                       ║
║   │  • Store keys in Keychain (additional protection)                        ║
║   │  • Capture camera/document                                               ║
║   │  • Network with certificate pinning                                      ║
║   │  • Background refresh (limited)                                          ║
║   │  • Device attestation (DeviceCheck)                                      ║
║   ├─ CANNOT DO:                                                              ║
║   │  • Kernel monitoring (no eBPF)                                           ║
║   │  • JIT compilation                                                       ║
║   │  • System-wide threat detection                                          ║
║   │  • Access other apps' data                                               ║
║   └─ PRODUCT IMPLICATIONS:                                                   ║
║      • BENTENG: Fully possible                                               ║
║      • SANDI: Fully possible                                                 ║
║      • MENARA: Limited to app-level protection                               ║
║      • ZIRAH: Not possible (would be fake)                                   ║
║                                                                              ║
║   Android:                                                                   ║
║   ├─ CAN DO:                                                                 ║
║   │  • Everything iOS can do                                                 ║
║   │  • Accessibility Service monitoring (declared)                           ║
║   │  • VPN service for network filtering                                     ║
║   │  • Work Profile integration (enterprise)                                 ║
║   │  • Device attestation (SafetyNet/Play Integrity)                         ║
║   ├─ CANNOT DO:                                                              ║
║   │  • eBPF without root                                                     ║
║   │  • Kernel monitoring without root                                        ║
║   └─ PRODUCT IMPLICATIONS:                                                   ║
║      • BENTENG: Fully possible                                               ║
║      • SANDI: Fully possible                                                 ║
║      • MENARA: Good with Accessibility Service                               ║
║      • ZIRAH: Limited without root                                           ║
║                                                                              ║
║   Linux:                                                                     ║
║   ├─ CAN DO:                                                                 ║
║   │  • Everything                                                            ║
║   │  • Full eBPF                                                             ║
║   │  • Kernel tracing                                                        ║
║   │  • System-wide protection                                                ║
║   └─ PRODUCT IMPLICATIONS:                                                   ║
║      • All products: Fully possible                                          ║
║                                                                              ║
║   Windows:                                                                   ║
║   ├─ CAN DO:                                                                 ║
║   │  • Our crypto                                                            ║
║   │  • ETW tracing                                                           ║
║   │  • Kernel minifilter (with WHQL signing)                                 ║
║   ├─ REQUIRES:                                                               ║
║   │  • EV code signing certificate (~$400/year)                              ║
║   │  • WHQL certification for kernel components                              ║
║   └─ PRODUCT IMPLICATIONS:                                                   ║
║      • All products: Possible with proper signing                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## REALITY 5: WHAT CAN BE BUILT BY SOLO DEVELOPER

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   HONEST TIMELINE ASSESSMENT (solo developer, 20 hrs/week):                  ║
║                                                                              ║
║   CRYPTO CORE (KUNCI):                                                       ║
║   • Wrapper around approved libraries: 2-4 weeks                             ║
║   • Test vectors and validation: 2 weeks                                     ║
║   • Constant-time verification: 2 weeks                                      ║
║   • Hybrid mode (PQ + classical): 1 week                                     ║
║   • Total: 7-9 weeks                                                         ║
║                                                                              ║
║   MEMORY PROTECTION (LINDUNG):                                               ║
║   • Secret type with zeroization: 1-2 weeks                                  ║
║   • mlock integration: 1 week                                                ║
║   • Cross-platform: 2 weeks                                                  ║
║   • Total: 4-5 weeks                                                         ║
║                                                                              ║
║   BENTENG MVP (eKYC without ZK face proof):                                  ║
║   • Document capture: 4 weeks                                                ║
║   • Face capture + liveness (3 signals): 6 weeks                             ║
║   • Deepfake detection (basic): 3 weeks                                      ║
║   • On-device matching: 2 weeks                                              ║
║   • Device binding: 2 weeks                                                  ║
║   • Signed attestation: 2 weeks                                              ║
║   • iOS/Android SDK: 4 weeks                                                 ║
║   • Total: 23 weeks (5.75 months)                                            ║
║                                                                              ║
║   AUDIT LOGGING (ALL PRODUCTS):                                              ║
║   • Core logging framework: 2 weeks                                          ║
║   • Tamper-evident chain: 2 weeks                                            ║
║   • Anomaly detection: 3 weeks                                               ║
║   • Total: 7 weeks                                                           ║
║                                                                              ║
║   REALISTIC FIRST MILESTONE:                                                 ║
║   • KUNCI + LINDUNG + BENTENG MVP: 8-9 months                               ║
║                                                                              ║
║   NOT REALISTIC FOR SOLO DEVELOPER:                                          ║
║   • Custom programming language: 2-5 years                                   ║
║   • Verified compiler: 2-5 years                                             ║
║   • ZK face verification: Research project (unknown)                         ║
║   • Full EDR (ZIRAH): 1-2 years                                             ║
║   • Comprehensive formal proofs: 1-2 years                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## REALITY 6: EXISTING REPOSITORIES

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   CURRENT REPOSITORY STATUS (as of 2025-12-30):                              ║
║                                                                              ║
║   menara (github.com/ib823/menara):                                          ║
║   • Status: PINQ engine complete                                             ║
║   • Language: Python/Rust hybrid                                             ║
║   • Extractable: KUNCI patterns, UNDANG policy, JARING network               ║
║   • Commits: 147                                                             ║
║                                                                              ║
║   gapura (github.com/ib823/gapura):                                          ║
║   • Status: WAF production-ready                                             ║
║   • Language: Mixed                                                          ║
║   • Extractable: BENTUK serialization, UNDANG policy                         ║
║   • Commits: 58                                                              ║
║                                                                              ║
║   zirah (github.com/ib823/zirah):                                            ║
║   • Status: Attestation 3M/sec, eBPF STUBS                                   ║
║   • Language: Rust                                                           ║
║   • Extractable: BUKTI proofs, LINDUNG memory                                ║
║   • Commits: 64                                                              ║
║                                                                              ║
║   benteng (github.com/ib823/benteng):                                        ║
║   • Status: eKYC complete (basic)                                            ║
║   • Language: Mixed                                                          ║
║   • Extractable: BUKTI proofs, KUNCI crypto                                  ║
║   • Commits: 99                                                              ║
║                                                                              ║
║   sandi (github.com/ib823/sandi):                                            ║
║   • Status: PQ crypto in Python                                              ║
║   • Language: Python (MUST PORT TO RUST)                                     ║
║   • Extractable: KUNCI crypto (needs rewrite)                                ║
║   • Commits: 37                                                              ║
║   • CRITICAL: This is the PQ crypto reference, must be Rust-ified           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART III: CONCRETE SPECIFICATIONS

## SPEC 1: KEY FORMATS

### 1.1 Secret Key Serialization

```
ALL secret keys use this EXACT format:

┌────────────────────────────────────────────────────────────────┐
│ Offset │ Size   │ Field          │ Description                │
├────────┼────────┼────────────────┼────────────────────────────┤
│ 0      │ 4      │ magic          │ 0x54455253 ("TERS")        │
│ 4      │ 2      │ version        │ 0x0001                     │
│ 6      │ 2      │ key_type       │ See key type table         │
│ 8      │ 4      │ key_length     │ Length in bytes (LE)       │
│ 12     │ 32     │ key_id         │ SHA-256(public_key)        │
│ 44     │ 8      │ created_at     │ Unix timestamp (LE)        │
│ 52     │ 8      │ expires_at     │ Unix timestamp (LE), 0=never│
│ 60     │ 4      │ reserved       │ 0x00000000                 │
│ 64     │ N      │ key_data       │ Raw key bytes              │
│ 64+N   │ 32     │ checksum       │ SHA-256(bytes 0 to 64+N-1) │
└────────────────────────────────────────────────────────────────┘

Key Type Table:
┌────────┬─────────────────────────────────────────────────────────┐
│ Value  │ Algorithm                                               │
├────────┼─────────────────────────────────────────────────────────┤
│ 0x0001 │ X25519 private key (32 bytes)                          │
│ 0x0002 │ Ed25519 private key (32 bytes)                         │
│ 0x0003 │ ML-KEM-768 decapsulation key (2400 bytes)              │
│ 0x0004 │ ML-DSA-65 private key (4032 bytes)                     │
│ 0x0005 │ SLH-DSA-SHAKE-128f private key (64 bytes)              │
│ 0x0006 │ AES-256 symmetric key (32 bytes)                       │
│ 0x0007 │ ChaCha20 symmetric key (32 bytes)                      │
│ 0x0008 │ HYBRID KEM (X25519 + ML-KEM-768) (2432 bytes)          │
│ 0x0009 │ HYBRID SIG (Ed25519 + ML-DSA-65) (4064 bytes)          │
└────────┴─────────────────────────────────────────────────────────┘

VALIDATION:
• magic MUST be 0x54455253
• version MUST be 0x0001 (reject unknown versions)
• key_type MUST be in table (reject unknown types)
• key_length MUST match expected for key_type
• checksum MUST match computed SHA-256
• IF expires_at != 0 AND expires_at < now, reject key
```

### 1.2 Encrypted Key Storage

```
Secret keys at rest are encrypted using this EXACT format:

┌────────────────────────────────────────────────────────────────┐
│ Offset │ Size   │ Field          │ Description                │
├────────┼────────┼────────────────┼────────────────────────────┤
│ 0      │ 4      │ magic          │ 0x454E4352 ("ENCR")        │
│ 4      │ 2      │ version        │ 0x0001                     │
│ 6      │ 2      │ cipher         │ 0x0001=AES-256-GCM         │
│ 8      │ 2      │ kdf            │ 0x0001=Argon2id            │
│ 10     │ 2      │ reserved       │ 0x0000                     │
│ 12     │ 16     │ salt           │ Random salt for KDF        │
│ 28     │ 4      │ time_cost      │ Argon2 time cost (LE)      │
│ 32     │ 4      │ memory_cost    │ Argon2 memory KB (LE)      │
│ 36     │ 4      │ parallelism    │ Argon2 parallelism (LE)    │
│ 40     │ 12     │ nonce          │ AES-GCM nonce              │
│ 52     │ 4      │ ciphertext_len │ Length of ciphertext (LE)  │
│ 56     │ N      │ ciphertext     │ Encrypted key (above fmt)  │
│ 56+N   │ 16     │ tag            │ AES-GCM auth tag           │
└────────────────────────────────────────────────────────────────┘

KDF Parameters (MINIMUM):
• time_cost: 3
• memory_cost: 65536 (64 MB)
• parallelism: 4

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

┌────────────────────────────────────────────────────────────────┐
│ Offset │ Size   │ Field               │ Description           │
├────────┼────────┼─────────────────────┼───────────────────────┤
│ 0      │ 4      │ magic               │ 0x41545354 ("ATST")   │
│ 4      │ 2      │ version             │ 0x0001                │
│ 6      │ 2      │ attestation_type    │ See table             │
│ 8      │ 32     │ device_id           │ SHA-256(device_key)   │
│ 40     │ 32     │ session_nonce       │ From server challenge │
│ 72     │ 8      │ timestamp           │ Unix timestamp (LE)   │
│ 80     │ 1      │ result              │ 0x00=fail, 0x01=pass  │
│ 81     │ 1      │ confidence          │ 0-100                 │
│ 82     │ 1      │ liveness_score      │ 0-100 [NEW]           │
│ 83     │ 1      │ deepfake_score      │ 0-100 (0=real) [NEW]  │
│ 84     │ 32     │ document_hash       │ SHA-256(document)     │
│ 116    │ N      │ signature           │ ML-DSA-65 signature   │
└────────────────────────────────────────────────────────────────┘

Attestation Type Table:
┌────────┬─────────────────────────────────────────────────────────┐
│ Value  │ Meaning                                                 │
├────────┼─────────────────────────────────────────────────────────┤
│ 0x0001 │ Face matches document                                   │
│ 0x0002 │ Liveness check passed                                   │
│ 0x0003 │ Document is valid                                       │
│ 0x0004 │ Age >= threshold (threshold in confidence field)        │
│ 0x0005 │ Nationality matches                                     │
│ 0x0006 │ Deepfake detection passed [NEW]                         │
│ 0x0007 │ All PAD checks passed [NEW]                             │
└────────┴─────────────────────────────────────────────────────────┘

VERIFICATION PROCESS:
1. Check magic, version
2. Verify session_nonce matches server-issued challenge
3. Verify timestamp within acceptable window (±5 minutes)
4. Verify liveness_score >= 80 (MINIMUM)
5. Verify deepfake_score <= 20 (MAXIMUM - lower is more real)
6. Verify signature using known device public key
7. Return result only if all checks pass
```

## SPEC 3: NETWORK PROTOCOL

```
All TERAS network communication uses this envelope:

┌────────────────────────────────────────────────────────────────┐
│ Offset │ Size   │ Field          │ Description                │
├────────┼────────┼────────────────┼────────────────────────────┤
│ 0      │ 4      │ magic          │ 0x54455250 ("TERP")        │
│ 4      │ 2      │ version        │ 0x0001                     │
│ 6      │ 2      │ message_type   │ See table                  │
│ 8      │ 4      │ sequence       │ Monotonic counter (LE)     │
│ 12     │ 4      │ payload_len    │ Length of payload (LE)     │
│ 16     │ N      │ payload        │ Encrypted payload          │
│ 16+N   │ 16     │ mac            │ HMAC-SHA256 truncated      │
└────────────────────────────────────────────────────────────────┘

Message Types:
┌────────┬─────────────────────────────────────────────────────────┐
│ Value  │ Message                                                 │
├────────┼─────────────────────────────────────────────────────────┤
│ 0x0001 │ Challenge request (server → client)                     │
│ 0x0002 │ Challenge response (client → server)                    │
│ 0x0003 │ Attestation submit                                      │
│ 0x0004 │ Attestation result                                      │
│ 0x0005 │ Threat pattern update                                   │
│ 0x0006 │ Heartbeat                                               │
│ 0x0007 │ Audit log batch [NEW]                                   │
│ 0x0008 │ Algorithm rotation notice [NEW]                         │
│ 0xFFFF │ Error                                                   │
└────────┴─────────────────────────────────────────────────────────┘

ENCRYPTION:
• Payload encrypted with session key (established via ML-KEM+X25519 HYBRID)
• Cipher: ChaCha20-Poly1305
• Nonce: sequence number (4 bytes) + random (8 bytes)

REPLAY PROTECTION:
• Server tracks highest sequence per client
• Reject if sequence <= last seen
• Reject if sequence > last seen + 1000 (window)
```

## SPEC 4: AUDIT LOG ENTRY FORMAT [NEW IN V3.1]

```
All audit log entries use this EXACT format:

┌────────────────────────────────────────────────────────────────┐
│ Offset │ Size   │ Field          │ Description                │
├────────┼────────┼────────────────┼────────────────────────────┤
│ 0      │ 4      │ magic          │ 0x4C4F4745 ("LOGE")        │
│ 4      │ 2      │ version        │ 0x0001                     │
│ 6      │ 2      │ event_type     │ See event type table       │
│ 8      │ 8      │ timestamp      │ Unix timestamp (LE)        │
│ 16     │ 32     │ actor_id       │ SHA-256(actor identity)    │
│ 48     │ 32     │ object_id      │ SHA-256(object identity)   │
│ 80     │ 1      │ result         │ 0x00=fail, 0x01=success    │
│ 81     │ 1      │ severity       │ 0=info, 1=warn, 2=error    │
│ 82     │ 2      │ context_len    │ Length of context (LE)     │
│ 84     │ M      │ context        │ JSON context (no secrets)  │
│ 84+M   │ 32     │ prev_hash      │ SHA-256(previous entry)    │
│ 116+M  │ N      │ signature      │ ML-DSA-65 signature        │
└────────────────────────────────────────────────────────────────┘

Event Type Table:
┌────────┬─────────────────────────────────────────────────────────┐
│ Value  │ Event                                                   │
├────────┼─────────────────────────────────────────────────────────┤
│ 0x0001 │ Authentication attempt                                  │
│ 0x0002 │ Key generation                                          │
│ 0x0003 │ Key usage                                               │
│ 0x0004 │ Key destruction                                         │
│ 0x0005 │ Verification attempt                                    │
│ 0x0006 │ Attestation generated                                   │
│ 0x0007 │ Configuration change                                    │
│ 0x0008 │ Anomaly detected                                        │
│ 0x0009 │ Algorithm rotation                                      │
│ 0x000A │ Privilege escalation                                    │
│ 0x000B │ Data access                                             │
│ 0x000C │ Network connection                                      │
└────────┴─────────────────────────────────────────────────────────┘

CHAIN INTEGRITY:
• Each entry contains SHA-256 of previous entry
• Genesis entry has prev_hash = all zeros
• Signature covers bytes 0 to 116+M-1
• Any modification breaks the chain
```

---

# PART IV: IMPLEMENTATION SKELETON

## SKELETON 1: Project Structure

```
teras/
├── Cargo.toml                    # Workspace root
├── Cargo.lock                    # MUST be committed
├── rust-toolchain.toml           # Pin exact Rust version
├── .cargo/
│   └── config.toml               # Cargo configuration
├── vendor/                       # Vendored dependencies
│   └── .vendor-checksum          # SHA-256 of all vendored crates
│
├── crates/
│   ├── teras-core/              # Core types, no crypto
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs         # Error types
│   │       └── types.rs         # Common types
│   │
│   ├── teras-kunci/             # Cryptography
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── kem.rs           # Key encapsulation (HYBRID)
│   │       ├── sign.rs          # Signatures (HYBRID)
│   │       ├── symmetric.rs     # AES, ChaCha
│   │       ├── hash.rs          # Hashing
│   │       ├── kdf.rs           # Key derivation
│   │       ├── rand.rs          # RNG
│   │       ├── agility.rs       # Algorithm rotation [NEW]
│   │       └── tests/
│   │           └── vectors.rs   # Test vector validation
│   │
│   ├── teras-lindung/           # Memory protection
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── secret.rs        # Secret<T> type
│   │       ├── zeroize.rs       # Zeroization
│   │       └── mlock.rs         # Memory locking
│   │
│   ├── teras-jejak/             # Audit logging [NEW]
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── entry.rs         # Log entry format
│   │       ├── chain.rs         # Hash chain
│   │       ├── anomaly.rs       # Anomaly detection
│   │       └── storage.rs       # Append-only storage
│   │
│   └── teras-benteng/           # eKYC (builds on above)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── document.rs      # Document processing
│           ├── face.rs          # Face processing
│           ├── liveness.rs      # Liveness detection (3+ signals)
│           ├── deepfake.rs      # Deepfake detection [NEW]
│           ├── binding.rs       # Device binding [NEW]
│           └── attestation.rs   # Attestation generation
│
├── tests/
│   ├── crypto_vectors.rs        # MUST pass
│   ├── timing_tests.rs          # MUST pass
│   ├── audit_chain.rs           # MUST pass [NEW]
│   └── integration/
│
└── tools/
    ├── verify-build.sh          # Reproducibility check
    ├── run-dudect.sh            # Timing verification
    └── audit-deps.sh            # Dependency audit
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
rust-version = "1.75.0"
license = "PROPRIETARY"
repository = "https://github.com/ib823/teras"

[workspace.dependencies]
# Post-quantum crypto - EXACT VERSIONS
ml-kem = "=0.2.1"
ml-dsa = "=0.1.0"
slh-dsa = "=0.1.0"

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

use crate::error::{TerasError, TerasResult};
use teras_lindung::Secret;
use ml_kem::{KemCore, MlKem768};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Hybrid KEM combining ML-KEM-768 and X25519.
/// 
/// Both algorithms must succeed for encapsulation/decapsulation.
/// If either fails, the operation fails.
/// 
/// This provides security if EITHER:
/// - Classical crypto (X25519) remains secure, OR
/// - Post-quantum crypto (ML-KEM) remains secure
pub struct HybridKem {
    ml_kem_dk: Secret<[u8; 2400]>,  // ML-KEM decapsulation key
    x25519_sk: Secret<[u8; 32]>,     // X25519 secret key
}

/// Hybrid encapsulation key (public)
pub struct HybridEncapsulationKey {
    ml_kem_ek: [u8; 1184],  // ML-KEM encapsulation key
    x25519_pk: [u8; 32],     // X25519 public key
}

/// Hybrid ciphertext
pub struct HybridCiphertext {
    ml_kem_ct: [u8; 1088],  // ML-KEM ciphertext
    x25519_ct: [u8; 32],     // X25519 ephemeral public key
}

impl HybridKem {
    /// Generate new hybrid keypair.
    pub fn generate() -> TerasResult<(Self, HybridEncapsulationKey)> {
        use rand::rngs::OsRng;
        
        // Generate ML-KEM keypair
        let (ml_kem_dk, ml_kem_ek) = MlKem768::generate(&mut OsRng);
        
        // Generate X25519 keypair
        let x25519_sk = X25519Secret::random_from_rng(OsRng);
        let x25519_pk = X25519Public::from(&x25519_sk);
        
        let private = HybridKem {
            ml_kem_dk: Secret::new(ml_kem_dk.as_bytes().try_into().unwrap()),
            x25519_sk: Secret::new(x25519_sk.as_bytes().clone()),
        };
        
        let public = HybridEncapsulationKey {
            ml_kem_ek: ml_kem_ek.as_bytes().try_into().unwrap(),
            x25519_pk: x25519_pk.as_bytes().clone(),
        };
        
        Ok((private, public))
    }
    
    /// Decapsulate to get shared secret.
    /// 
    /// Returns 64-byte shared secret (32 from each algorithm, concatenated).
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> TerasResult<Secret<[u8; 64]>> {
        // Decapsulate ML-KEM
        let ml_kem_ss = MlKem768::decapsulate(
            &self.ml_kem_dk.expose().into(),
            &ct.ml_kem_ct.into(),
        ).map_err(|_| TerasError::DecryptionFailed)?;
        
        // Decapsulate X25519
        let x25519_their_public = X25519Public::from(ct.x25519_ct);
        let x25519_sk = X25519Secret::from(self.x25519_sk.expose().clone());
        let x25519_ss = x25519_sk.diffie_hellman(&x25519_their_public);
        
        // Combine shared secrets
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(ml_kem_ss.as_bytes());
        combined[32..].copy_from_slice(x25519_ss.as_bytes());
        
        Ok(Secret::new(combined))
    }
}

impl HybridEncapsulationKey {
    /// Encapsulate to create ciphertext and shared secret.
    pub fn encapsulate(&self) -> TerasResult<(HybridCiphertext, Secret<[u8; 64]>)> {
        use rand::rngs::OsRng;
        
        // Encapsulate ML-KEM
        let (ml_kem_ct, ml_kem_ss) = MlKem768::encapsulate(
            &self.ml_kem_ek.into(),
            &mut OsRng,
        ).map_err(|_| TerasError::KeyDerivationFailed)?;
        
        // Encapsulate X25519
        let x25519_ephemeral = X25519Secret::random_from_rng(OsRng);
        let x25519_ephemeral_public = X25519Public::from(&x25519_ephemeral);
        let x25519_their_public = X25519Public::from(self.x25519_pk);
        let x25519_ss = x25519_ephemeral.diffie_hellman(&x25519_their_public);
        
        let ct = HybridCiphertext {
            ml_kem_ct: ml_kem_ct.as_bytes().try_into().unwrap(),
            x25519_ct: x25519_ephemeral_public.as_bytes().clone(),
        };
        
        // Combine shared secrets
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(ml_kem_ss.as_bytes());
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

□ cargo fmt --check
  Fails if code is not formatted

□ cargo clippy -- -D warnings
  Fails if any clippy warnings

□ cargo test
  Fails if any test fails

□ cargo test --release
  Fails if release tests fail (different from debug)

□ grep -r "unsafe" --include="*.rs" | wc -l
  Must be <= APPROVED_UNSAFE_COUNT (currently: 10)
  Each unsafe block must have safety comment

□ No println!/dbg!/eprintln! in crypto code
  Grep must return 0 for these in teras-kunci, teras-lindung

COMMIT BLOCKED if any check fails.
```

## CHECKPOINT 2: Before Merge to Main

```
EVERY merge must pass:

□ All CHECKPOINT 1 items

□ cargo +nightly miri test
  Fails if undefined behavior detected

□ ./tools/run-dudect.sh
  Fails if any t-value > 4.5

□ ./tools/verify-vectors.sh
  Fails if test vectors don't match

□ cargo deny check
  Fails if prohibited dependency detected

□ ./tools/verify-build.sh
  Fails if build not reproducible

□ Audit log tests pass
  ./tools/verify-audit-chain.sh

MERGE BLOCKED if any check fails.
```

## CHECKPOINT 3: Before Release

```
EVERY release must pass:

□ All CHECKPOINT 2 items

□ Full Kani verification
  cargo kani --all-features

□ Security review checklist
  - [ ] No new unsafe blocks without review
  - [ ] No new dependencies without audit
  - [ ] All secrets use Secret<T> type
  - [ ] All crypto uses approved algorithms
  - [ ] All network uses TLS with pinning
  - [ ] No biometric data leaves device
  - [ ] Audit logging captures all security events
  - [ ] Deepfake detection enabled for face matching
  - [ ] Device binding enforced

□ Reproducibility verification
  Build on 3 different machines
  Compare SHA-256 of outputs
  Must be identical

□ Diverse double-compilation
  Build with different compilers
  Compare behavior

RELEASE BLOCKED if any check fails.
```

---

# PART VI: PROHIBITED ACTIONS

## PROHIBITION 1: Data Handling

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ NEVER:                                                                        ║
║ • Send raw biometric data to any server                                       ║
║ • Send face embeddings/templates to server                                    ║
║ • Store biometric data in cloud storage                                       ║
║ • Log any secret or key material                                              ║
║ • Log any biometric data                                                      ║
║ • Store secrets in plain text                                                 ║
║ • Use platform storage without our encryption                                 ║
║ • Share secrets between users                                                 ║
║ • Transmit secrets without TLS + certificate pinning                          ║
║ • Use SMS OTP as sole authentication factor                                   ║
║ • Use email OTP as sole authentication factor                                 ║
║ • Trust phone numbers as identity                                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## PROHIBITION 2: Implementation

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ NEVER:                                                                        ║
║ • Use algorithms not in the approved list                                     ║
║ • Use libraries not in the approved list                                      ║
║ • Add dependencies without updating Cargo.lock                                ║
║ • Use version ranges in Cargo.toml (use exact versions)                       ║
║ • Implement crypto primitives (use approved libraries)                        ║
║ • Use unsafe without safety comment                                           ║
║ • Use unwrap() or expect() on user input                                      ║
║ • Panic on error (fail secure, don't crash)                                   ║
║ • Use println!/dbg! for secrets (even in development)                        ║
║ • Clone Secret<T> (even if it "seems convenient")                            ║
║ • Use non-hybrid KEM for new deployments                                      ║
║ • Skip deepfake detection "for performance"                                   ║
║ • Skip liveness detection "for convenience"                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## PROHIBITION 3: Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ NEVER:                                                                        ║
║ • Build "simplified version" that violates laws                               ║
║ • Skip validation "for MVP"                                                   ║
║ • Add "temporary" workarounds to security                                     ║
║ • Claim TERAS-LANG implementation exists (it doesn't)                        ║
║ • Claim ZK face verification works (it's research)                           ║
║ • Promise timelines not in REALITY section                                   ║
║ • Modify wire formats without updating this spec                             ║
║ • Change test vectors without cryptographic review                           ║
║ • Disable audit logging in production                                         ║
║ • Implement "backdoor" for any reason                                         ║
║ • Create single point of key escrow                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## PROHIBITION 4: Claims

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ NEVER CLAIM:                                                                  ║
║ • "Zero-knowledge face verification" (not implemented)                        ║
║ • "Formally verified" (until actual proofs exist)                            ║
║ • "Quantum-resistant" (say "quantum-ready with hybrid crypto")               ║
║ • "Unhackable" (nothing is)                                                   ║
║ • "100% secure" (nothing is)                                                  ║
║ • "Deepfake-proof" (say "deepfake-resistant")                                ║
║ • "Unbreakable encryption" (algorithms may be broken in future)              ║
║ • Features that don't exist                                                   ║
║ • Timelines that aren't validated                                            ║
║ • Protection against threats not in Part XV                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART VII: DECISION LOG

## DECISION 1: Use Rust Instead of TERAS-LANG (For Now)

```
DATE: 2025-12-30
DECISION: Implement in Rust with verification tools, not TERAS-LANG

RATIONALE:
• TERAS-LANG doesn't exist
• Creating a new language is 2-5 year project
• Rust with Kani/Verus provides verification today
• Migration to TERAS-LANG possible later

ALTERNATIVES REJECTED:
• C/C++: Memory safety issues
• Go: GC unpredictable, no verification tools
• TERAS-LANG: Doesn't exist

MIGRATION PATH:
• Rust code follows strict patterns (Secret<T>, etc.)
• When TERAS-LANG exists, transpiler can convert
• Core logic is algorithm, not language
```

## DECISION 2: Signed Attestation Instead of ZK Face Proof

```
DATE: 2025-12-30
DECISION: Use signed attestation for face matching, not ZK proof

RATIONALE:
• ZK for 512-dim float cosine similarity is infeasible on mobile
• Estimated proving time: 10+ minutes
• Estimated memory: 8+ GB
• This is a research problem, not engineering

WHAT WE DO INSTEAD:
• Face matching happens on device (Law 1 satisfied)
• Device signs attestation "match succeeded"
• Server verifies device signature
• Biometrics never leave device

SECURITY PROPERTY PRESERVED:
• Server cannot see face (only attestation)
• Server cannot reconstruct face from attestation
• Law 1 is fully satisfied

FUTURE RESEARCH:
• Investigate ZK-friendly embedding models
• Investigate integer-only similarity
• Track academic progress
```

## DECISION 3: Exact Version Pinning

```
DATE: 2025-12-30
DECISION: Pin exact versions of all dependencies

RATIONALE:
• Semver allows breaking changes
• Supply chain attacks happen
• Reproducible builds require exact versions

IMPLICATIONS:
• No automatic updates
• Must manually review and update
• Slower, but safer
```

## DECISION 4: Hybrid Cryptography Mandatory [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: All new deployments MUST use hybrid (classical + PQ) crypto

RATIONALE:
• ML-KEM and ML-DSA are new algorithms
• Cryptographic breaks may be discovered
• Classical algorithms have decades of analysis
• Hybrid provides security if either survives

IMPLEMENTATION:
• KEM: ML-KEM-768 + X25519 (both required)
• Signatures: ML-DSA-65 + Ed25519 (both must verify)
• Shared secrets: Concatenated, then HKDF

MIGRATION:
• Existing single-algorithm deployments: Migrate within 6 months
• New deployments: Hybrid from day 1
```

## DECISION 5: Multi-Signal Liveness Required [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: Liveness detection requires minimum 3 independent signals

RATIONALE:
• Single-signal liveness is easily defeated
• Deepfakes are increasingly sophisticated
• Defense in depth for biometric verification

REQUIRED SIGNALS (minimum 3):
• Texture analysis (2D vs 3D)
• Behavioral (blink, head turn, random challenge)
• Reflection analysis (screen vs real light)
• Temporal consistency (frame-to-frame)
• Depth estimation (if available)

THRESHOLD:
• Each signal: >70% confidence
• Combined: >80% confidence
• Any signal <50%: Automatic failure
```

## DECISION 6: Device Binding Over Phone Numbers [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: Identity bound to device keys, not phone numbers

RATIONALE:
• SIM swap attacks are common
• Phone numbers are not secure identifiers
• Email accounts can be compromised
• Cryptographic device binding is stronger

IMPLEMENTATION:
• Device generates keypair on first launch
• Private key never leaves device
• Public key registered with server
• All attestations signed by device key
• Recovery: Multi-device registration before loss

PROHIBITED:
• SMS OTP as sole factor
• Email OTP as sole factor
• Phone number as identity
```

## DECISION 7: Comprehensive Audit Logging [NEW IN V3.1]

```
DATE: 2025-12-30
DECISION: All security events must be audit logged

RATIONALE:
• Insider threats require detection
• Forensics require complete history
• Compliance requires audit trails
• Anomaly detection requires data

IMPLEMENTATION:
• Every security event logged (Part III, SPEC 4)
• Cryptographic hash chain (tamper-evident)
• Append-only storage (cannot delete)
• 7-year retention minimum
• Anomaly detection on logs

LOG EVENTS:
• Authentication attempts
• Key operations
• Data access
• Configuration changes
• Privilege escalation
```

---

# PART VIII: FUTURE VISION

**THIS SECTION IS ASPIRATIONAL. DO NOT IMPLEMENT.**

## VISION 1: TERAS-LANG

```
STATUS: FUTURE (2-5 years)

DESCRIPTION:
A purpose-built language with:
• Dependent types
• Linear types
• Refinement types
• Built-in ZK DSL
• Integrated SMT verification

CURRENT STATE: Does not exist
WORK REQUIRED: New language, compiler, tools
TIMELINE: Unknown

DO NOT:
• Claim TERAS-LANG is implemented
• "Approximate" TERAS-LANG features
• Start TERAS-LANG without completing current milestones
```

## VISION 2: Zero-Knowledge Face Verification

```
STATUS: FUTURE (Research)

DESCRIPTION:
True ZK proof that face matches document without revealing face.

CURRENT STATE: Infeasible on mobile (10+ min proving time)
WORK REQUIRED: Research breakthroughs

RESEARCH DIRECTIONS:
• ZK-friendly face embedding models
• Integer-only similarity metrics
• Proof aggregation
• Hardware acceleration

DO NOT:
• Claim this is implemented
• "Simplify" by leaking biometrics
• Promise timeline
```

## VISION 3: SARAF/NADI Collective Immunity

```
STATUS: FUTURE (Post-BENTENG)

DESCRIPTION:
Collective threat intelligence sharing via ZK proofs.

CURRENT STATE: Design only
WORK REQUIRED: Full implementation after core products

DO NOT:
• Implement before BENTENG MVP complete
• Claim collective immunity exists
```

## VISION 4: Formal Proofs for All Components

```
STATUS: FUTURE (1-2 years after MVP)

DESCRIPTION:
Complete formal verification in Coq/Lean:
• Functional correctness proofs
• Security property proofs
• Side-channel freedom proofs

CURRENT STATE: Partial Kani coverage only
WORK REQUIRED: Significant theorem prover expertise

DO NOT:
• Claim "formally verified" until proofs exist
• Skip Kani as intermediate step
```

---

# PART IX: GLOSSARY

```
TERM                    DEFINITION
────                    ──────────
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

┌────────────────────────────────────────────────────────────────────────────────┐
│ ID   │ Input (hex)                        │ Expected SHA-256 (hex)            │
├──────┼────────────────────────────────────┼───────────────────────────────────┤
│ S001 │ (empty)                            │ e3b0c44298fc1c149afbf4c8996fb924  │
│      │                                    │ 27ae41e4649b934ca495991b7852b855  │
├──────┼────────────────────────────────────┼───────────────────────────────────┤
│ S002 │ 616263                             │ ba7816bf8f01cfea414140de5dae2223  │
│      │ ("abc")                            │ b00361a396177a9cb410ff61f20015ad  │
├──────┼────────────────────────────────────┼───────────────────────────────────┤
│ S003 │ 6162636462636465636465666465666764 │ 248d6a61d20638b8e5c026930c3e6039  │
│      │ 6566676866676869676869696a686a6b69 │ a33ce45964ff2167f6ecedd419db06c1  │
│      │ 6a6b6a6b6c6b6c6d6c6d6e6d6e6f6e6f70 │                                   │
│      │ 6f7071                             │                                   │
│      │ ("abcdbcdecdefdefgefghfghighij..." │                                   │
├──────┼────────────────────────────────────┼───────────────────────────────────┤
│ S004 │ 5445524153 ("TERAS")               │ a8d3c26ae4c3a3d...                │
│      │                                    │ (COMPUTE EXACT VALUE)             │
└──────┴────────────────────────────────────┴───────────────────────────────────┘

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

┌────────────────────────────────────────────────────────────────────────────────┐
│ ID   │ Key (hex)                          │ Nonce (hex)    │ AAD (hex)        │
│      │ Plaintext (hex)                    │ Ciphertext+Tag (hex)              │
├──────┼────────────────────────────────────┼────────────────┼──────────────────┤
│ A001 │ 00000000000000000000000000000000   │ 000000000000   │ (none)           │
│      │ 00000000000000000000000000000000   │ 000000000000   │                  │
│      │ (32 zero bytes key)                │                │                  │
│      │                                    │                │                  │
│      │ Plaintext: (empty)                 │                │                  │
│      │ Ciphertext: (empty)                │                │                  │
│      │ Tag: 530f8afbc74536b9a963b4f1c4cb738b                                  │
├──────┼────────────────────────────────────┴────────────────┴──────────────────┤
│ A002 │ Key: feffe9928665731c6d6a8f9467308308                                  │
│      │      feffe9928665731c6d6a8f9467308308                                  │
│      │ Nonce: cafebabefacedbaddecaf888                                        │
│      │ Plaintext: d9313225f88406e5a55909c5aff5269a                            │
│      │            86a7a9531534f7da2e4c303d8a318a72                            │
│      │            1c3c0c95956809532fcf0e2449a6b525                            │
│      │            b16aedf5aa0de657ba637b391aafd255                            │
│      │ Ciphertext: 522dc1f099567d07f47f37a32a84427d                           │
│      │             643a8cdcbfe5c0c97598a2bd2555d1aa                           │
│      │             8cb08e48590dbb3da7b08b1056828838                           │
│      │             c5f61e6393ba7a0abcc9f662898015ad                           │
│      │ Tag: b094dac5d93471bdec1a502270e3cc6c                                  │
└──────┴────────────────────────────────────────────────────────────────────────┘

BUILD MUST FAIL if these vectors don't match.
```

## TEST VECTOR SET 3: Ed25519

```
MANDATORY: Implementation MUST produce EXACT outputs below.
Source: RFC 8032

┌────────────────────────────────────────────────────────────────────────────────┐
│ ID   │ Private Key (seed, 32 bytes hex)                                       │
│      │ Public Key (32 bytes hex)                                              │
│      │ Message (hex)                                                          │
│      │ Signature (64 bytes hex)                                               │
├──────┼────────────────────────────────────────────────────────────────────────┤
│ E001 │ Private: 9d61b19deffd5a60ba844af492ec2cc4                              │
│      │          4449c5697b326919703bac031cae7f60                              │
│      │ Public:  d75a980182b10ab7d54bfed3c964073a                              │
│      │          0ee172f3daa62325af021a68f707511a                              │
│      │ Message: (empty)                                                       │
│      │ Signature: e5564300c360ac729086e2cc806e828a                            │
│      │            84877f1eb8e5d974d873e06522490155                            │
│      │            5fb8821590a33bacc61e39701cf9b46b                            │
│      │            d25bf5f0595bbe24655141438e7a100b                            │
├──────┼────────────────────────────────────────────────────────────────────────┤
│ E002 │ Private: 4ccd089b28ff96da9db6c346ec114e0f                              │
│      │          5b8a319f35aba624da8cf6ed4fb8a6fb                              │
│      │ Public:  3d4017c3e843895a92b70aa74d1b7ebc                              │
│      │          9c982ccf2ec4968cc0cd55f12af4660c                              │
│      │ Message: 72                                                            │
│      │ Signature: 92a009a9f0d4cab8720e820b5f642540                            │
│      │            a2b27b5416503f8fb3762223ebdb69da                            │
│      │            085ac1e43e15996e458f3613d0f11d8c                            │
│      │            387b2eaeb4302aeeb00d291612bb0c00                            │
└──────┴────────────────────────────────────────────────────────────────────────┘

BUILD MUST FAIL if these vectors don't match.
```

## TEST VECTOR SET 4: X25519

```
MANDATORY: Implementation MUST produce EXACT outputs below.
Source: RFC 7748

┌────────────────────────────────────────────────────────────────────────────────┐
│ ID   │ Alice Private / Public             │ Bob Private / Public              │
│      │ Shared Secret                                                           │
├──────┼─────────────────────────────────────────────────────────────────────────┤
│ X001 │ Private A: 77076d0a7318a57d3c16c17251b26645                            │
│      │            df4c2f87ebc0992ab177fba51db92c2a                            │
│      │ Public A:  8520f0098930a754748b7ddcb43ef75a                            │
│      │            0dbf3a0d26381af4eba4a98eaa9b4e6a                            │
│      │                                                                         │
│      │ Private B: 5dab087e624a8a4b79e17f8b83800ee6                            │
│      │            6f3bb1292618b6fd1c2f8b27ff88e0eb                            │
│      │ Public B:  de9edb7d7b7dc1b4d35b61c2ece43537                            │
│      │            3f8343c85b78674dadfc7e146f882b4f                            │
│      │                                                                         │
│      │ Shared: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742│
└──────┴─────────────────────────────────────────────────────────────────────────┘

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
│ prev_hash: 0000000000000000000000000000000000000000000000000000000000000000
│ entry_hash: SHA-256(genesis_entry_bytes)

Entry N:
│ prev_hash: entry_hash of Entry N-1
│ entry_hash: SHA-256(entry_N_bytes excluding signature)

VALIDATION:
• For each entry E[i] where i > 0:
  - E[i].prev_hash MUST equal SHA-256(E[i-1])
  - Signature MUST verify over E[i] bytes 0 to 116+M-1
• Chain broken = immediate security alert
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
APPROVED="ml-kem ml-dsa slh-dsa x25519-dalek ed25519-dalek aes-gcm chacha20poly1305 sha3 sha2 blake3 hkdf argon2 zeroize rand rand_core subtle"
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

□ LAW 1 (Biometric Locality)
  □ No biometric data in network requests
  □ No biometric embeddings/templates in network requests
  □ No biometric data in logs
  □ No biometric data in crash reports
  □ Biometrics processed only on device

□ LAW 2 (Cryptographic Standards)
  □ Only approved algorithms used
  □ Only approved libraries used
  □ Key sizes meet minimums
  □ No prohibited algorithms
  □ Hybrid mode used for new KEM/signatures

□ LAW 3 (Constant-Time)
  □ All secret operations are constant-time
  □ dudect tests pass (t < 4.5)
  □ No early returns on secrets
  □ No secret-dependent branches
  □ Uses subtle crate for comparisons

□ LAW 4 (Zeroization)
  □ All secrets use Secret<T>
  □ Drop implementations call zeroize
  □ Compiler fence present
  □ Miri shows no UB

□ LAW 5 (No Trust)
  □ Our encryption used, not platform
  □ TLS with certificate pinning
  □ Secrets encrypted before platform storage
  □ No SMS OTP as sole factor
  □ Device binding used

□ LAW 6 (Fail Secure)
  □ No "fail open" paths
  □ All errors return Err, don't panic
  □ Partial state zeroized on error
  □ No fallback to less secure methods

□ LAW 7 (Reproducible)
  □ Cargo.lock committed
  □ No build timestamps
  □ Exact versions in Cargo.toml

□ LAW 8 (Audit Logging) [NEW]
  □ All security events logged
  □ No secrets in logs
  □ Hash chain maintained
  □ Signature on each entry

ALL BOXES MUST BE CHECKED FOR MERGE.
```

---

# PART XIV: QUICK REFERENCE CARD

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                      TERAS QUICK REFERENCE v3.1                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  APPROVED CRYPTO:                                                            ║
║  ├─ Symmetric: AES-256-GCM, ChaCha20-Poly1305                               ║
║  ├─ Hash: SHA-256, SHA3-256, BLAKE3                                         ║
║  ├─ KEM: ML-KEM-768 + X25519 (HYBRID MANDATORY)                             ║
║  ├─ Sign: ML-DSA-65 + Ed25519 (HYBRID MANDATORY)                            ║
║  └─ KDF: HKDF, Argon2id                                                     ║
║                                                                              ║
║  PROHIBITED:                                                                 ║
║  ├─ MD5, SHA-1, DES, 3DES, RC4, Blowfish                                   ║
║  ├─ RSA < 3072, ECDSA < 256 bit                                            ║
║  ├─ ring, openssl, any unlisted library                                     ║
║  └─ SMS OTP, email OTP as sole factor                                       ║
║                                                                              ║
║  SECRET HANDLING:                                                            ║
║  ├─ Always use Secret<T>                                                    ║
║  ├─ Never Clone, Debug, or Display secrets                                  ║
║  ├─ Zeroize on drop                                                         ║
║  └─ mlock on supported platforms                                            ║
║                                                                              ║
║  ERROR HANDLING:                                                             ║
║  ├─ Return Result<T, TerasError>                                            ║
║  ├─ Never unwrap() or expect() user input                                   ║
║  ├─ Never panic on error                                                    ║
║  └─ Fail secure (deny access)                                               ║
║                                                                              ║
║  BIOMETRICS (BENTENG):                                                       ║
║  ├─ 3+ liveness signals required                                            ║
║  ├─ Deepfake detection required                                             ║
║  ├─ Device binding required                                                 ║
║  └─ NEVER send to server                                                    ║
║                                                                              ║
║  BEFORE COMMIT:                                                              ║
║  ├─ cargo fmt                                                               ║
║  ├─ cargo clippy -- -D warnings                                             ║
║  ├─ cargo test                                                              ║
║  ├─ No debug prints in crypto code                                          ║
║  └─ Unsafe blocks have SAFETY comment                                       ║
║                                                                              ║
║  BEFORE MERGE:                                                               ║
║  ├─ All above +                                                             ║
║  ├─ cargo +nightly miri test                                                ║
║  ├─ ./tools/run-dudect.sh                                                   ║
║  ├─ ./tools/verify-build.sh                                                 ║
║  └─ ./tools/verify-audit-chain.sh                                           ║
║                                                                              ║
║  NEVER:                                                                      ║
║  ├─ Send biometrics to server                                               ║
║  ├─ Log secrets                                                             ║
║  ├─ Skip validation "for MVP"                                               ║
║  ├─ Claim features that don't exist                                         ║
║  ├─ Use non-hybrid crypto for new code                                      ║
║  └─ Modify this spec without version update                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XV: THREAT COVERAGE MATRIX [NEW IN V3.1]

## WHAT TERAS COVERS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ THREAT                        │ PRODUCT    │ MITIGATION              │STATUS ║
╠═══════════════════════════════╪════════════╪═════════════════════════╪═══════╣
║ Biometric data theft          │ BENTENG    │ Never leaves device     │ ✅    ║
║ Classical crypto break        │ SANDI      │ Hybrid PQ + classical   │ ✅    ║
║ Quantum computer attack       │ SANDI      │ ML-KEM-768, ML-DSA-65   │ ✅    ║
║ Timing side-channels          │ ALL        │ Constant-time code      │ ✅    ║
║ Memory disclosure             │ ALL        │ Secret<T>, mlock        │ ✅    ║
║ Fail-open vulnerabilities     │ ALL        │ Fail-secure by design   │ ✅    ║
║ Supply chain (dependencies)   │ BUILD      │ Vendoring, exact pins   │ ✅    ║
║ Photo/video spoofing          │ BENTENG    │ Multi-signal liveness   │ ✅    ║
║ Deepfakes                     │ BENTENG    │ Deepfake detection      │ ✅    ║
║ SIM swapping                  │ BENTENG    │ Device binding          │ ✅    ║
║ Replay attacks                │ ALL        │ Nonces, timestamps      │ ✅    ║
║ Insider threats (detection)   │ ALL        │ Audit logging           │ ✅    ║
║ Algorithm break (future)      │ SANDI      │ Algorithm agility       │ ✅    ║
║ Key compromise                │ ALL        │ Key rotation, hybrid    │ ✅    ║
║ Log tampering                 │ ALL        │ Hash chain, signatures  │ ✅    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## WHAT TERAS PARTIALLY COVERS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ THREAT                        │ PRODUCT    │ STATUS       │ LIMITATION       ║
╠═══════════════════════════════╪════════════╪══════════════╪══════════════════╣
║ Nation-state 0-days           │ ZIRAH      │ ⚠️ PARTIAL   │ Detection only   ║
║ Sophisticated deepfakes       │ BENTENG    │ ⚠️ PARTIAL   │ Arms race        ║
║ Compiler backdoors            │ BUILD      │ ⚠️ PARTIAL   │ Diverse compile  ║
║ Supply chain (hardware)       │ N/A        │ ⚠️ PARTIAL   │ Accept risk      ║
║ DDoS attacks                  │ GAPURA     │ ⚠️ PARTIAL   │ Basic mitigation ║
║ Logic bugs                    │ ALL        │ ⚠️ PARTIAL   │ Kani, not formal ║
║ Behavioral anomalies          │ ZIRAH      │ ⚠️ PARTIAL   │ Baseline needed  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## WHAT TERAS DOES NOT COVER

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ THREAT                        │ WHY NOT COVERED                    │ ACCEPT? ║
╠═══════════════════════════════╪════════════════════════════════════╪═════════╣
║ Power/EM side-channels        │ Requires hardware isolation        │ YES     ║
║ Spectre/Meltdown variants     │ Kernel-level, complex             │ PARTIAL ║
║ Physical access attacks       │ Cannot prevent physical access     │ YES     ║
║ Social engineering            │ Human problem, not technical       │ YES     ║
║ Government backdoor laws      │ Cannot prevent legally             │ YES     ║
║ Custom silicon backdoors      │ Cannot verify without fab          │ YES     ║
║ Perfect forward secrecy break │ Past data already captured         │ YES     ║
║ Complete formal verification  │ Requires 1-2 years additional      │ LATER   ║
║ True ZK face verification     │ Research problem, infeasible now   │ LATER   ║
╚══════════════════════════════════════════════════════════════════════════════╝

ACKNOWLEDGMENT: No security system is complete. TERAS provides defense-in-depth
for the threats it addresses. Users must understand the limitations.
```

---

# PART XVI: ANTI-DEEPFAKE & ADVERSARIAL ML [NEW IN V3.1]

## BENTENG ANTI-DEEPFAKE REQUIREMENTS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   PRESENTATION ATTACK DETECTION (PAD)                                        ║
║                                                                              ║
║   MINIMUM COMPLIANCE: ISO 30107-3 Level 2                                    ║
║                                                                              ║
║   REQUIRED DETECTIONS:                                                       ║
║   ├─ Photo attack (printed photo): MUST detect (>99%)                       ║
║   ├─ Screen replay (photo/video on screen): MUST detect (>99%)              ║
║   ├─ Video replay: MUST detect (>95%)                                       ║
║   ├─ 2D mask: MUST detect (>95%)                                            ║
║   ├─ 3D mask: SHOULD detect (>80%) - Level 2                                ║
║   └─ Deepfake video: SHOULD detect (>80%)                                   ║
║                                                                              ║
║   LIVENESS SIGNALS (MINIMUM 3 REQUIRED):                                     ║
║   ├─ Texture analysis (2D vs 3D surface)                                    ║
║   ├─ Depth estimation (if hardware available)                               ║
║   ├─ Behavioral challenges (blink, head turn, smile)                        ║
║   ├─ Reflection analysis (screen glare vs natural light)                    ║
║   ├─ Temporal consistency (frame-to-frame coherence)                        ║
║   ├─ Moiré pattern detection (screen pixels)                                ║
║   └─ Edge detection (mask boundaries)                                       ║
║                                                                              ║
║   SCORE THRESHOLDS:                                                          ║
║   ├─ Individual signal: >70% confidence required                            ║
║   ├─ Combined liveness: >80% confidence required                            ║
║   ├─ Deepfake score: <20% (lower = more likely real)                        ║
║   └─ Any signal <50%: Automatic FAIL                                        ║
║                                                                              ║
║   FAILURE BEHAVIOR (LAW 6 - FAIL SECURE):                                    ║
║   ├─ Score below threshold → DENY verification                              ║
║   ├─ Insufficient signals → DENY verification                               ║
║   ├─ Detection timeout → DENY verification (never skip)                     ║
║   └─ All failures logged to audit trail                                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
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
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ADVERSARIAL ATTACK MITIGATIONS                                             ║
║                                                                              ║
║   INPUT VALIDATION:                                                          ║
║   ├─ Image size bounds: 320x240 to 4096x3072                                ║
║   ├─ File format: JPEG, PNG only (no exotic formats)                        ║
║   ├─ Metadata stripped before processing                                    ║
║   └─ Pixel value normalization                                              ║
║                                                                              ║
║   MODEL HARDENING:                                                           ║
║   ├─ Adversarial training with PGD attacks                                  ║
║   ├─ Input randomization (small random transforms)                          ║
║   ├─ Ensemble of multiple models (>50% must agree)                          ║
║   └─ Gradient masking (obfuscate gradients)                                 ║
║                                                                              ║
║   RUNTIME DEFENSE:                                                           ║
║   ├─ Input perturbation detection                                           ║
║   ├─ Confidence threshold (reject low-confidence)                           ║
║   ├─ Rate limiting per device/user                                          ║
║   └─ Anomaly detection on repeated failures                                 ║
║                                                                              ║
║   LIMITATIONS (HONEST):                                                      ║
║   ├─ Adversarial ML is an arms race                                         ║
║   ├─ Novel attacks may succeed                                              ║
║   ├─ Defense improves with attack data                                      ║
║   └─ Cannot guarantee 100% detection                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XVII: ALGORITHM AGILITY & CRYPTOGRAPHIC RECOVERY [NEW IN V3.1]

## ALGORITHM AGILITY ARCHITECTURE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ALGORITHM STATUS LEVELS                                                    ║
║                                                                              ║
║   ACTIVE (use for all new operations):                                       ║
║   ├─ KEM: ML-KEM-768 + X25519 (hybrid, both required)                       ║
║   ├─ Signature: ML-DSA-65 + Ed25519 (hybrid, both must verify)              ║
║   ├─ Symmetric: ChaCha20-Poly1305 (primary), AES-256-GCM (alternate)        ║
║   └─ Hash: SHA3-256 (primary), SHA-256 (compatibility)                      ║
║                                                                              ║
║   BACKUP (ready to activate within 24 hours):                                ║
║   ├─ KEM: Classic McEliece (if ML-KEM breaks)                               ║
║   ├─ Signature: SLH-DSA-SHAKE-256f (if ML-DSA breaks)                       ║
║   └─ Hash: BLAKE3 (if SHA-3 has issues)                                     ║
║                                                                              ║
║   DEPRECATED (accept for verification, don't create new):                    ║
║   ├─ Single-algorithm KEM (non-hybrid)                                      ║
║   ├─ Single-algorithm signatures (non-hybrid)                               ║
║   └─ SHA-256 only (without SHA3)                                            ║
║                                                                              ║
║   PROHIBITED (reject always):                                                ║
║   ├─ MD5, SHA-1, DES, 3DES, RC4                                             ║
║   ├─ RSA < 3072 bits                                                         ║
║   └─ Non-approved algorithms                                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## ALGORITHM ROTATION TRIGGERS

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   TRIGGER                          │ ACTION           │ TIMELINE            ║
║   ─────────────────────────────────┼──────────────────┼─────────────────────║
║   NIST announces algorithm break   │ Activate backup  │ 24 hours            ║
║   Academic paper shows weakness    │ Activate backup  │ 7 days              ║
║   Cryptanalysis concern raised     │ Enable hybrid    │ 30 days             ║
║   New NIST standard published      │ Evaluate, plan   │ 90 days             ║
║   Algorithm deprecated by NIST     │ Migrate away     │ 1 year              ║
║                                                                              ║
║   ROTATION PROCESS:                                                          ║
║   1. Announcement: Notify all clients of pending rotation                    ║
║   2. Dual-support: Accept both old and new for transition period            ║
║   3. Migration: Re-encrypt/re-sign with new algorithm                        ║
║   4. Deprecation: Stop accepting old algorithm                               ║
║   5. Purge: Remove old algorithm code (after all data migrated)             ║
║                                                                              ║
║   KEY ROTATION (independent of algorithm rotation):                          ║
║   ├─ Session keys: <24 hours                                                ║
║   ├─ Device keys: <1 year                                                   ║
║   ├─ Long-term keys: <2 years                                               ║
║   └─ On algorithm change: Immediate rotation                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KemAlgorithm {
    HybridMlKemX25519 = 0x0001,  // Active
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

---

# PART XVIII: BEHAVIORAL DETECTION & 0-DAY DEFENSE [NEW IN V3.1]

## ZIRAH BEHAVIORAL DETECTION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   BEHAVIORAL DETECTION (ASSUMES 0-DAYS EXIST)                                ║
║                                                                              ║
║   PHILOSOPHY:                                                                ║
║   We cannot prevent all 0-days. We CAN detect abnormal behavior.             ║
║                                                                              ║
║   BASELINE ESTABLISHMENT (per application):                                  ║
║   ├─ Normal process spawn patterns                                          ║
║   ├─ Normal network connection patterns                                     ║
║   ├─ Normal file access patterns                                            ║
║   ├─ Normal memory allocation patterns                                      ║
║   └─ Normal system call sequences                                           ║
║                                                                              ║
║   ANOMALY DETECTION:                                                         ║
║   ├─ Deviation from baseline > 3σ → ALERT                                   ║
║   ├─ Process spawning sensitive child → ALERT                               ║
║   ├─ Unexpected outbound connection → ALERT                                 ║
║   ├─ Memory pattern matching exploit signatures → ALERT                     ║
║   ├─ Unusual system call sequence → ALERT                                   ║
║   └─ Privilege escalation attempt → BLOCK + ALERT                           ║
║                                                                              ║
║   SPECTRE/MELTDOWN INDICATORS (Linux only):                                  ║
║   ├─ High-frequency timer access → FLAG                                     ║
║   ├─ Cache timing patterns → FLAG                                           ║
║   ├─ Speculative execution markers → FLAG                                   ║
║   └─ Kernel memory access attempts → BLOCK                                  ║
║                                                                              ║
║   LIMITATIONS (HONEST):                                                      ║
║   ├─ Baseline requires learning period                                      ║
║   ├─ Novel attacks may evade detection                                      ║
║   ├─ False positives possible                                               ║
║   └─ Cannot prevent exploitation, only detect                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## 0-DAY RESPONSE PROCEDURE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   WHEN ANOMALY DETECTED:                                                     ║
║                                                                              ║
║   IMMEDIATE (automated):                                                     ║
║   1. Log full context to audit trail                                         ║
║   2. Capture memory snapshot (if safe)                                       ║
║   3. Block suspicious activity (if high confidence)                          ║
║   4. Alert security team                                                     ║
║                                                                              ║
║   SHORT-TERM (human review):                                                 ║
║   1. Analyze captured data                                                   ║
║   2. Determine if true positive                                              ║
║   3. Isolate affected systems if confirmed                                   ║
║   4. Begin forensics                                                         ║
║                                                                              ║
║   LONG-TERM (if confirmed 0-day):                                            ║
║   1. Develop signature/detection rule                                        ║
║   2. Push to all ZIRAH instances                                            ║
║   3. Coordinate disclosure if appropriate                                    ║
║   4. Update baseline models                                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XIX: DDOS MITIGATION & AVAILABILITY [NEW IN V3.1]

## GAPURA DDOS MITIGATION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   LAYER 7 (APPLICATION):                                                     ║
║   ├─ Rate limiting per IP: 100 req/min (configurable)                       ║
║   ├─ Rate limiting per session: 1000 req/min                                ║
║   ├─ Rate limiting per user: 5000 req/min                                   ║
║   ├─ Proof-of-work challenge if threshold exceeded                          ║
║   ├─ CAPTCHA fallback (accessibility concerns noted)                        ║
║   └─ Slowloris protection (connection timeouts)                             ║
║                                                                              ║
║   LAYER 4 (TRANSPORT):                                                       ║
║   ├─ SYN cookie enforcement                                                  ║
║   ├─ Connection limits per IP: 100 concurrent                               ║
║   ├─ TCP window validation                                                   ║
║   └─ UDP amplification protection                                            ║
║                                                                              ║
║   LAYER 3 (NETWORK):                                                         ║
║   ├─ Upstream provider filtering (requires ISP cooperation)                 ║
║   ├─ Geographic filtering (optional, configurable)                          ║
║   ├─ BGP blackholing (requires ISP cooperation)                             ║
║   └─ Anycast distribution (future enhancement)                               ║
║                                                                              ║
║   CHALLENGE-RESPONSE:                                                        ║
║   ├─ JavaScript challenge (bot detection)                                   ║
║   ├─ Cryptographic puzzle (adjustable difficulty)                           ║
║   └─ Behavioral analysis (human vs bot patterns)                            ║
║                                                                              ║
║   LIMITATIONS:                                                               ║
║   ├─ Large-scale attacks require upstream help                              ║
║   ├─ Sophisticated botnets may solve challenges                             ║
║   └─ Geographic filtering may block legitimate users                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XX: AUDIT LOGGING & INSIDER THREAT [NEW IN V3.1]

## COMPREHENSIVE AUDIT LOGGING

See LAW 8 in Part I and SPEC 4 in Part III.

## INSIDER THREAT DETECTION

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ANOMALY DETECTION ON AUDIT LOGS                                            ║
║                                                                              ║
║   BASELINE PATTERNS (per user/service):                                      ║
║   ├─ Normal access times                                                     ║
║   ├─ Normal access locations (IP ranges)                                    ║
║   ├─ Normal data access volumes                                             ║
║   ├─ Normal privilege usage                                                 ║
║   └─ Normal operation sequences                                             ║
║                                                                              ║
║   ALERTS:                                                                    ║
║   ├─ Access outside normal hours → ALERT                                    ║
║   ├─ Access from unusual location → ALERT                                   ║
║   ├─ Bulk data access → ALERT                                               ║
║   ├─ Privilege escalation → ALERT                                           ║
║   ├─ Accessing data outside role → ALERT                                    ║
║   ├─ Failed authentication spike → ALERT                                    ║
║   └─ Pattern matching known attack → BLOCK + ALERT                          ║
║                                                                              ║
║   SEPARATION OF DUTIES:                                                      ║
║   ├─ Key generation ≠ key usage                                             ║
║   ├─ Admin access ≠ user data access                                        ║
║   ├─ Log access ≠ log deletion (deletion prohibited)                        ║
║   └─ Config change requires 2 approvals                                     ║
║                                                                              ║
║   LOG PROTECTION:                                                            ║
║   ├─ Append-only storage                                                     ║
║   ├─ Cryptographic hash chain                                                ║
║   ├─ Signature on each entry                                                 ║
║   ├─ Replicated to 2+ locations                                              ║
║   └─ 7-year retention                                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# PART XXI: DEVICE BINDING & SIM-SWAP RESISTANCE [NEW IN V3.1]

## DEVICE BINDING ARCHITECTURE

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   DEVICE IDENTITY (NOT PHONE NUMBER)                                         ║
║                                                                              ║
║   DEVICE KEY GENERATION:                                                     ║
║   1. On first app launch, generate ML-DSA-65 + Ed25519 keypair              ║
║   2. Store private key in Secret<T> with mlock                               ║
║   3. Additional protection: Platform keystore (Keychain/Keystore)            ║
║   4. Private key NEVER leaves device                                         ║
║   5. Public key registered with server                                       ║
║                                                                              ║
║   DEVICE ATTESTATION:                                                        ║
║   ├─ iOS: DeviceCheck + our signature                                        ║
║   ├─ Android: Play Integrity + our signature                                 ║
║   └─ Desktop: TPM attestation + our signature (if available)                ║
║                                                                              ║
║   ALL OPERATIONS REQUIRE:                                                    ║
║   ├─ Valid device signature                                                  ║
║   ├─ Device ID matches registered                                            ║
║   └─ Platform attestation (where available)                                  ║
║                                                                              ║
║   PROHIBITED:                                                                ║
║   ├─ Phone number as identity                                                ║
║   ├─ SMS OTP as sole authentication factor                                   ║
║   ├─ Email OTP as sole authentication factor                                 ║
║   └─ Any non-cryptographic device identification                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## RECOVERY MECHANISM

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   DEVICE LOSS RECOVERY                                                       ║
║                                                                              ║
║   PREVENTION (before loss):                                                  ║
║   ├─ Multi-device registration (recommended)                                ║
║   ├─ Recovery key generation (stored offline by user)                        ║
║   └─ Trusted contact designation (optional)                                  ║
║                                                                              ║
║   RECOVERY PROCESS:                                                          ║
║   1. User initiates recovery from new device                                 ║
║   2. Requires recovery key OR trusted contact approval                       ║
║   3. Waiting period: 72 hours (security delay)                               ║
║   4. Notification to all registered devices                                  ║
║   5. Old device key revoked after waiting period                             ║
║   6. New device key generated and registered                                 ║
║                                                                              ║
║   WAITING PERIOD CANNOT BE BYPASSED:                                         ║
║   ├─ Even with recovery key, 72-hour wait applies                           ║
║   ├─ Provides window for legitimate owner to cancel                          ║
║   └─ Alerts sent to all known contact methods                                ║
║                                                                              ║
║   LIMITATIONS:                                                               ║
║   ├─ Recovery key loss + single device = account lost                        ║
║   ├─ 72-hour delay may be inconvenient                                       ║
║   └─ No "customer support" bypass possible                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

# APPENDIX A: VERSION CONTROL

```
This document version: 3.1.0
Previous version (V3.0.0) hash: [COMPUTE SHA-256 OF V3.0.0]
This version hash: [COMPUTE SHA-256 AFTER FINALIZATION]

MODIFICATION RULES:
1. Any change creates new version (3.1.0 → 3.2.0)
2. New version must include hash of previous
3. Laws (Part I) cannot be weakened, only strengthened
4. Prohibitions (Part VI) cannot be removed
5. All changes must be logged in DECISION LOG

CHANGES IN V3.1.0:
- Added LAW 8 (Audit Logging)
- Added Part XV (Threat Coverage Matrix)
- Added Part XVI (Anti-Deepfake & Adversarial ML)
- Added Part XVII (Algorithm Agility)
- Added Part XVIII (Behavioral Detection)
- Added Part XIX (DDoS Mitigation)
- Added Part XX (Audit Logging Details)
- Added Part XXI (Device Binding)
- Added DECISION 4-7 in Decision Log
- Updated Reality 5 with revised timelines
- Added subtle crate to approved libraries
- Enhanced attestation format with liveness/deepfake scores
- Added new error types for biometric and audit failures
```

---

# DOCUMENT END

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   TERAS MASTER ARCHITECTURE v3.1.0                                          ║
║                                                                              ║
║   This document is COMPLETE and AUTHORITATIVE.                              ║
║                                                                              ║
║   Any Claude instance or developer working on TERAS:                        ║
║   1. MUST read this document fully before any implementation                ║
║   2. MUST NOT deviate from specifications                                   ║
║   3. MUST NOT implement features not specified                              ║
║   4. MUST ask for clarification if spec is unclear                          ║
║   5. MUST report if spec seems impossible                                   ║
║   6. MUST quote relevant LAW/PART when making decisions                     ║
║   7. MUST acknowledge threat coverage limitations (Part XV)                 ║
║                                                                              ║
║   Compliance is MANDATORY. Exceptions are NOT GRANTED.                      ║
║                                                                              ║
║   Document Hash (SHA-256): [COMPUTE AFTER FINALIZATION]                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

# TERAS V3.1 ARCHITECTURE DIAGRAMS
# The Revolutionary Security Ecosystem

> "A living organism, not a collection of tools"
> Version: 3.1.0 | Date: 2025-12-30

═══════════════════════════════════════════════════════════════════════════════
                        DIAGRAM 1: THE TERAS UNIVERSE
═══════════════════════════════════════════════════════════════════════════════

This is what the customer sees vs what actually exists:

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                    WHAT CUSTOMERS SEE (5 PRODUCTS)                          │
│                                                                             │
│    ╔═══════════╗   ╔═══════════╗   ╔═══════════╗   ╔═══════════╗   ╔═══════════╗
│    ║  MENARA   ║   ║  GAPURA   ║   ║   ZIRAH   ║   ║  BENTENG  ║   ║   SANDI   ║
│    ║───────────║   ║───────────║   ║───────────║   ║───────────║   ║───────────║
│    ║  Mobile   ║   ║    WAF    ║   ║    EDR    ║   ║   eKYC    ║   ║  DigiSig  ║
│    ║ Security  ║   ║  Gateway  ║   ║  Endpoint ║   ║ Identity  ║   ║ Signatures║
│    ╚═════╤═════╝   ╚═════╤═════╝   ╚═════╤═════╝   ╚═════╤═════╝   ╚═════╤═════╝
│          │               │               │               │               │
│          │               │               │               │               │
│    ══════╧═══════════════╧═══════════════╧═══════════════╧═══════════════╧══════
│                                      │
│                                      │
│    ┌─────────────────────────────────▼─────────────────────────────────┐
│    │                                                                   │
│    │                    ████████╗███████╗██████╗  █████╗ ███████╗      │
│    │                    ╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██╔════╝      │
│    │                       ██║   █████╗  ██████╔╝███████║███████╗      │
│    │                       ██║   ██╔══╝  ██╔══██╗██╔══██║╚════██║      │
│    │                       ██║   ███████╗██║  ██║██║  ██║███████║      │
│    │                       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝      │
│    │                                                                   │
│    │                    THE INVISIBLE FOUNDATION                       │
│    │                    (Customers never see this)                     │
│    │                                                                   │
│    └───────────────────────────────────────────────────────────────────┘
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
                   DIAGRAM 2: TERAS CORE COMPONENT ARCHITECTURE
═══════════════════════════════════════════════════════════════════════════════

The foundation that powers everything:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                              TERAS CORE CRATES                                  │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         LAYER 4: PRODUCTS                                │   │
│  │                                                                          │   │
│  │   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │   │
│  │   │teras-    │ │teras-    │ │teras-    │ │teras-    │ │teras-    │     │   │
│  │   │menara    │ │gapura    │ │zirah     │ │benteng   │ │sandi     │     │   │
│  │   │          │ │          │ │          │ │          │ │          │     │   │
│  │   │• Mobile  │ │• HTTP/S  │ │• eBPF    │ │• Doc OCR │ │• PDF Sign│     │   │
│  │   │  agent   │ │  inspect │ │  probes  │ │• Face ML │ │• Workflow│     │   │
│  │   │• Mesh    │ │• Bot     │ │• Behavior│ │• Liveness│ │• Archive │     │   │
│  │   │  network │ │  detect  │ │  analysis│ │• ZK proof│ │• LTV     │     │   │
│  │   └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘     │   │
│  └────────┼────────────┼────────────┼────────────┼────────────┼───────────┘   │
│           │            │            │            │            │               │
│           └────────────┴────────────┼────────────┴────────────┘               │
│                                     │                                         │
│  ┌──────────────────────────────────▼──────────────────────────────────────┐  │
│  │                         LAYER 3: SERVICES                                │  │
│  │                                                                          │  │
│  │   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐        │  │
│  │   │teras-saraf │  │teras-nadi  │  │teras-jejak │  │teras-undang│        │  │
│  │   │            │  │            │  │            │  │            │        │  │
│  │   │• Command   │  │• Pulse     │  │• Audit     │  │• Policy    │        │  │
│  │   │  mesh      │  │  network   │  │  logging   │  │  engine    │        │  │
│  │   │• ZK threat │  │• Health    │  │• Hash chain│  │• Rules     │        │  │
│  │   │  sharing   │  │  consensus │  │• Forensics │  │• RBAC      │        │  │
│  │   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘        │  │
│  └─────────┼───────────────┼───────────────┼───────────────┼────────────────┘  │
│            │               │               │               │                   │
│            └───────────────┴───────┬───────┴───────────────┘                   │
│                                    │                                           │
│  ┌─────────────────────────────────▼───────────────────────────────────────┐  │
│  │                         LAYER 2: PRIMITIVES                              │  │
│  │                                                                          │  │
│  │   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │  │
│  │   │teras-    │ │teras-    │ │teras-    │ │teras-    │ │teras-    │     │  │
│  │   │kunci     │ │lindung   │ │jaring    │ │bentuk    │ │aliran    │     │  │
│  │   │          │ │          │ │          │ │          │ │          │     │  │
│  │   │• ML-KEM  │ │• Secret  │ │• TLS 1.3 │ │• Binary  │ │• Events  │     │  │
│  │   │• ML-DSA  │ │  <T>     │ │• HTTP/3  │ │  serial  │ │• OCSF    │     │  │
│  │   │• SLH-DSA │ │• mlock   │ │• Cert    │ │• Schema  │ │• Pub/Sub │     │  │
│  │   │• Hybrid  │ │• zeroize │ │  pinning │ │  valid   │ │          │     │  │
│  │   └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘     │  │
│  └────────┼────────────┼────────────┼────────────┼────────────┼───────────┘  │
│           │            │            │            │            │               │
│           └────────────┴────────────┼────────────┴────────────┘               │
│                                     │                                         │
│  ┌──────────────────────────────────▼──────────────────────────────────────┐  │
│  │                         LAYER 1: FOUNDATION                              │  │
│  │                                                                          │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐   │  │
│  │   │                        teras-core                                │   │  │
│  │   │                                                                  │   │  │
│  │   │  • TerasError (all error types)                                  │   │  │
│  │   │  • TerasResult<T> (unified result type)                          │   │  │
│  │   │  • Common types (timestamps, IDs, formats)                       │   │  │
│  │   │  • Constants (magic numbers, versions)                           │   │  │
│  │   │  • Traits (interfaces for all components)                        │   │  │
│  │   │                                                                  │   │  │
│  │   └─────────────────────────────────────────────────────────────────┘   │  │
│  │                                                                          │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
                   DIAGRAM 3: COMPONENT DEPENDENCY GRAPH
═══════════════════════════════════════════════════════════════════════════════

Which crate depends on which:

                                ┌─────────────┐
                                │ teras-core  │
                                │ (Foundation)│
                                └──────┬──────┘
                                       │
           ┌───────────────┬───────────┼───────────┬───────────────┐
           │               │           │           │               │
           ▼               ▼           ▼           ▼               ▼
    ┌────────────┐  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
    │teras-kunci │  │teras-lindung│ │teras-jaring│ │teras-bentuk│ │teras-aliran│
    │  (Crypto)  │  │  (Memory)  │ │ (Network)  │ │  (Serial)  │ │ (Events)   │
    └──────┬─────┘  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘ └──────┬─────┘
           │               │              │              │              │
           └───────────────┴──────┬───────┴──────────────┴──────────────┘
                                  │
           ┌───────────────┬──────┴──────┬───────────────┐
           │               │             │               │
           ▼               ▼             ▼               ▼
    ┌────────────┐  ┌────────────┐ ┌────────────┐ ┌────────────┐
    │teras-saraf │  │teras-nadi  │ │teras-jejak │ │teras-undang│
    │  (Mesh)    │  │  (Pulse)   │ │  (Audit)   │ │  (Policy)  │
    └──────┬─────┘  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘
           │               │              │              │
           └───────────────┴──────┬───────┴──────────────┘
                                  │
    ┌─────────────┬───────────────┼───────────────┬─────────────┐
    │             │               │               │             │
    ▼             ▼               ▼               ▼             ▼
┌────────┐  ┌────────┐      ┌────────┐      ┌────────┐   ┌────────┐
│MENARA  │  │GAPURA  │      │ ZIRAH  │      │BENTENG │   │ SANDI  │
│(Mobile)│  │ (WAF)  │      │ (EDR)  │      │ (eKYC) │   │(DigiSig│
└────────┘  └────────┘      └────────┘      └────────┘   └────────┘


═══════════════════════════════════════════════════════════════════════════════
                   DIAGRAM 4: PRODUCT FEATURE MATRIX
═══════════════════════════════════════════════════════════════════════════════

What each product uses from TERAS core:

┌──────────────────┬────────┬────────┬────────┬────────┬────────┐
│     COMPONENT    │ MENARA │ GAPURA │ ZIRAH  │BENTENG │ SANDI  │
├──────────────────┼────────┼────────┼────────┼────────┼────────┤
│                  │        │        │        │        │        │
│ KUNCI (Crypto)   │        │        │        │        │        │
│ ├─ ML-KEM        │   ●    │   ●    │   ●    │   ●    │   ●    │
│ ├─ ML-DSA        │   ●    │   ●    │   ●    │   ●    │   ●    │
│ ├─ SLH-DSA       │   ○    │   ○    │   ○    │   ●    │   ●    │
│ ├─ Hybrid KEM    │   ●    │   ●    │   ●    │   ●    │   ●    │
│ └─ ZK Proofs     │   ●    │   ○    │   ○    │   ●    │   ●    │
│                  │        │        │        │        │        │
│ LINDUNG (Memory) │   ●    │   ●    │   ●    │   ●    │   ●    │
│ ├─ Secret<T>     │   ●    │   ●    │   ●    │   ●    │   ●    │
│ ├─ mlock         │   ●    │   ●    │   ●    │   ●    │   ●    │
│ └─ zeroize       │   ●    │   ●    │   ●    │   ●    │   ●    │
│                  │        │        │        │        │        │
│ JARING (Network) │        │        │        │        │        │
│ ├─ TLS 1.3 + PQ  │   ●    │   ●    │   ●    │   ●    │   ●    │
│ ├─ P2P Mesh      │   ●    │   ○    │   ●    │   ○    │   ○    │
│ └─ Cert Pinning  │   ●    │   ●    │   ●    │   ●    │   ●    │
│                  │        │        │        │        │        │
│ SARAF (Mesh)     │   ●    │   ●    │   ●    │   ●    │   ●    │
│ └─ ZK Threat     │   ●    │   ●    │   ●    │   ○    │   ○    │
│                  │        │        │        │        │        │
│ NADI (Pulse)     │   ●    │   ●    │   ●    │   ●    │   ●    │
│ └─ Health Check  │   ●    │   ●    │   ●    │   ●    │   ●    │
│                  │        │        │        │        │        │
│ JEJAK (Audit)    │   ●    │   ●    │   ●    │   ●    │   ●    │
│ └─ Hash Chain    │   ●    │   ●    │   ●    │   ●    │   ●    │
│                  │        │        │        │        │        │
│ UNDANG (Policy)  │   ●    │   ●    │   ●    │   ●    │   ●    │
│ └─ RBAC          │   ●    │   ●    │   ●    │   ●    │   ●    │
│                  │        │        │        │        │        │
│ PRODUCT-SPECIFIC │        │        │        │        │        │
│ ├─ Mobile Agent  │   ●    │   ○    │   ○    │   ○    │   ○    │
│ ├─ HTTP Parser   │   ○    │   ●    │   ○    │   ○    │   ○    │
│ ├─ eBPF Probes   │   ○    │   ○    │   ●    │   ○    │   ○    │
│ ├─ Face ML       │   ○    │   ○    │   ○    │   ●    │   ○    │
│ ├─ Deepfake Det  │   ○    │   ○    │   ○    │   ●    │   ○    │
│ ├─ Liveness      │   ○    │   ○    │   ○    │   ●    │   ○    │
│ ├─ PDF Parser    │   ○    │   ○    │   ○    │   ○    │   ●    │
│ └─ LTV Archive   │   ○    │   ○    │   ○    │   ○    │   ●    │
│                  │        │        │        │        │        │
└──────────────────┴────────┴────────┴────────┴────────┴────────┘

Legend: ● = Full use   ○ = Partial/Not used


═══════════════════════════════════════════════════════════════════════════════
             DIAGRAM 5: THE REVOLUTIONARY LIVING ORGANISM
═══════════════════════════════════════════════════════════════════════════════

TERAS is not 5 separate products. It's ONE organism with 5 faces.

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                         THE LIVING ORGANISM MODEL                               │
│                                                                                 │
│   Traditional Security:              TERAS Model:                               │
│   ┌────┐ ┌────┐ ┌────┐              ┌─────────────────────────────────────┐    │
│   │Prod│ │Prod│ │Prod│              │                                     │    │
│   │ A  │ │ B  │ │ C  │              │    ╭────╮   ╭────╮   ╭────╮        │    │
│   └──┬─┘ └──┬─┘ └──┬─┘              │   ╱      ╲ ╱      ╲ ╱      ╲       │    │
│      │      │      │                │  │ MENARA ├┤ GAPURA ├┤ ZIRAH │       │    │
│   ┌──▼──┐┌──▼──┐┌──▼──┐            │   ╲      ╱ ╲      ╱ ╲      ╱       │    │
│   │Data │││Data │││Data │           │    ╰──┬─╯   ╰──┬─╯   ╰──┬─╯        │    │
│   │Silo │││Silo │││Silo │           │       │        │        │          │    │
│   └─────┘└─────┘└─────┘            │       └────────┼────────┘          │    │
│                                     │                │                    │    │
│   (No sharing)                      │    ╭───────────┴───────────╮       │    │
│                                     │    │                       │       │    │
│                                     │    │    ░░░ SARAF ░░░      │       │    │
│                                     │    │   Neural Command      │       │    │
│                                     │    │        Mesh           │       │    │
│                                     │    │                       │       │    │
│                                     │    ╰───────────┬───────────╯       │    │
│                                     │                │                    │    │
│                                     │       ╭────────┼────────╮          │    │
│                                     │       │        │        │          │    │
│                                     │    ╭──┴─╮   ╭──┴─╮   ╭──┴─╮       │    │
│                                     │   ╱      ╲ ╱      ╲ ╱      ╲      │    │
│                                     │  │BENTENG ├┤ SANDI ├┤ NADI  │      │    │
│                                     │   ╲      ╱ ╲      ╱ ╲      ╱      │    │
│                                     │    ╰────╯   ╰────╯   ╰────╯       │    │
│                                     │                                     │    │
│                                     │       (ONE ORGANISM)               │    │
│                                     └─────────────────────────────────────┘    │
│                                                                                 │
│   RESULT:                                                                       │
│   • Threat detected by ZIRAH → instantly protects MENARA, GAPURA              │
│   • Attack blocked by GAPURA → instantly teaches ZIRAH, MENARA                │
│   • Fraud caught by BENTENG → instantly hardens SANDI                         │
│   • ALL WITHOUT SHARING ACTUAL DATA (Zero-Knowledge)                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
           DIAGRAM 6: SARAF - THE NEURAL COMMAND MESH
═══════════════════════════════════════════════════════════════════════════════

SARAF (Neural) - The distributed intelligence network:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                              SARAF ARCHITECTURE                                 │
│                         (Zero-Knowledge Threat Sharing)                         │
│                                                                                 │
│                                                                                 │
│     CUSTOMER A                    CUSTOMER B                    CUSTOMER C      │
│     (Bank)                        (Telco)                       (Retail)        │
│                                                                                 │
│  ┌─────────────┐              ┌─────────────┐              ┌─────────────┐     │
│  │   ZIRAH     │              │   GAPURA    │              │   MENARA    │     │
│  │   Agent     │              │   Gateway   │              │   Agent     │     │
│  │             │              │             │              │             │     │
│  │  Detects:   │              │  Detects:   │              │  Detects:   │     │
│  │  Ransomware │              │  SQLi Wave  │              │  Phishing   │     │
│  │  variant X  │              │  from IPs   │              │  campaign   │     │
│  └──────┬──────┘              └──────┬──────┘              └──────┬──────┘     │
│         │                            │                            │            │
│         │ Generate ZK Proof          │ Generate ZK Proof          │ Generate   │
│         │ "I saw threat matching     │ "I saw attack matching     │ ZK Proof   │
│         │  pattern P without         │  pattern Q without         │            │
│         │  revealing P"              │  revealing Q"              │            │
│         │                            │                            │            │
│         ▼                            ▼                            ▼            │
│  ╔══════════════════════════════════════════════════════════════════════╗      │
│  ║                                                                      ║      │
│  ║                         SARAF MESH NETWORK                           ║      │
│  ║                                                                      ║      │
│  ║   ┌────────────────────────────────────────────────────────────┐    ║      │
│  ║   │                                                            │    ║      │
│  ║   │     ZK Proof           ZK Proof           ZK Proof         │    ║      │
│  ║   │        │                  │                  │             │    ║      │
│  ║   │        ▼                  ▼                  ▼             │    ║      │
│  ║   │   ┌─────────┐        ┌─────────┐        ┌─────────┐       │    ║      │
│  ║   │   │Aggregate│───────▶│Aggregate│───────▶│Aggregate│       │    ║      │
│  ║   │   │ Node 1  │◀───────│ Node 2  │◀───────│ Node 3  │       │    ║      │
│  ║   │   └─────────┘        └─────────┘        └─────────┘       │    ║      │
│  ║   │        │                  │                  │             │    ║      │
│  ║   │        └──────────────────┼──────────────────┘             │    ║      │
│  ║   │                           │                                │    ║      │
│  ║   │                           ▼                                │    ║      │
│  ║   │                  ┌────────────────┐                        │    ║      │
│  ║   │                  │  COLLECTIVE    │                        │    ║      │
│  ║   │                  │  THREAT MODEL  │                        │    ║      │
│  ║   │                  │                │                        │    ║      │
│  ║   │                  │ "New patterns  │                        │    ║      │
│  ║   │                  │  emerging      │                        │    ║      │
│  ║   │                  │  globally"     │                        │    ║      │
│  ║   │                  └───────┬────────┘                        │    ║      │
│  ║   │                          │                                 │    ║      │
│  ║   └──────────────────────────┼─────────────────────────────────┘    ║      │
│  ║                              │                                      ║      │
│  ╚══════════════════════════════╪══════════════════════════════════════╝      │
│                                 │                                              │
│         ┌───────────────────────┼───────────────────────┐                      │
│         │                       │                       │                      │
│         ▼                       ▼                       ▼                      │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐              │
│  │  ALL ZIRAH  │         │ ALL GAPURA  │         │ ALL MENARA  │              │
│  │  Endpoints  │         │  Gateways   │         │   Devices   │              │
│  │             │         │             │         │             │              │
│  │  NOW KNOW:  │         │  NOW KNOW:  │         │  NOW KNOW:  │              │
│  │  "Pattern   │         │  "Pattern   │         │  "Pattern   │              │
│  │   exists"   │         │   exists"   │         │   exists"   │              │
│  │  without    │         │  without    │         │  without    │              │
│  │  knowing    │         │  knowing    │         │  knowing    │              │
│  │  details    │         │  details    │         │  details    │              │
│  └─────────────┘         └─────────────┘         └─────────────┘              │
│                                                                                 │
│   MAGIC: Customer A's ransomware → Customer B & C protected                    │
│          WITHOUT Customer A's data ever leaving their network                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
           DIAGRAM 7: NADI - THE PULSE NETWORK
═══════════════════════════════════════════════════════════════════════════════

NADI (Pulse) - Byzantine fault-tolerant health consensus:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                              NADI PULSE NETWORK                                 │
│                         (Distributed Health Monitoring)                         │
│                                                                                 │
│                                                                                 │
│   Every TERAS component sends a "heartbeat":                                   │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────┐      │
│   │                                                                     │      │
│   │    ZIRAH        GAPURA        MENARA       BENTENG       SANDI     │      │
│   │      │            │             │            │            │        │      │
│   │      │            │             │            │            │        │      │
│   │    ╔═╧═╗        ╔═╧═╗         ╔═╧═╗        ╔═╧═╗        ╔═╧═╗     │      │
│   │    ║ ♥ ║        ║ ♥ ║         ║ ♥ ║        ║ ♥ ║        ║ ♥ ║     │      │
│   │    ╚═╤═╝        ╚═╤═╝         ╚═╤═╝        ╚═╤═╝        ╚═╤═╝     │      │
│   │      │            │             │            │            │        │      │
│   │      │  Signed    │  Signed     │  Signed    │  Signed    │        │      │
│   │      │  Pulse     │  Pulse      │  Pulse     │  Pulse     │        │      │
│   │      │            │             │            │            │        │      │
│   └──────┼────────────┼─────────────┼────────────┼────────────┼────────┘      │
│          │            │             │            │            │                │
│          └────────────┴──────┬──────┴────────────┴────────────┘                │
│                              │                                                  │
│                              ▼                                                  │
│   ┌─────────────────────────────────────────────────────────────────────┐      │
│   │                                                                     │      │
│   │                      NADI CONSENSUS LAYER                           │      │
│   │                                                                     │      │
│   │   Each pulse contains:                                              │      │
│   │   ┌─────────────────────────────────────────────────────────┐      │      │
│   │   │ • Timestamp (signed)                                    │      │      │
│   │   │ • Component ID                                          │      │      │
│   │   │ • Health metrics (CPU, memory, threat level)            │      │      │
│   │   │ • Last N threats seen (ZK commitment)                   │      │      │
│   │   │ • Software version + attestation                        │      │      │
│   │   │ • ML-DSA-65 signature                                   │      │      │
│   │   └─────────────────────────────────────────────────────────┘      │      │
│   │                                                                     │      │
│   │   Byzantine Fault Tolerance:                                        │      │
│   │   ┌─────────────────────────────────────────────────────────┐      │      │
│   │   │                                                         │      │      │
│   │   │   If < 1/3 nodes compromised → System still works      │      │      │
│   │   │   If node stops responding → Marked unhealthy          │      │      │
│   │   │   If node sends bad data → Rejected + quarantined      │      │      │
│   │   │                                                         │      │      │
│   │   └─────────────────────────────────────────────────────────┘      │      │
│   │                                                                     │      │
│   └─────────────────────────────────────────────────────────────────────┘      │
│                                                                                 │
│   GLOBAL HEALTH VIEW:                                                          │
│   ┌─────────────────────────────────────────────────────────────────────┐      │
│   │                                                                     │      │
│   │   ┌─────────────────────────────────────────────────────────┐      │      │
│   │   │                                                         │      │      │
│   │   │   ZIRAH:   ████████████░░░░░░░░  85% healthy           │      │      │
│   │   │   GAPURA:  ██████████████████░░  98% healthy           │      │      │
│   │   │   MENARA:  █████████████████░░░  92% healthy           │      │      │
│   │   │   BENTENG: ████████████████████ 100% healthy           │      │      │
│   │   │   SANDI:   ████████████████████ 100% healthy           │      │      │
│   │   │                                                         │      │      │
│   │   │   GLOBAL:  ████████████████░░░░  95% healthy           │      │      │
│   │   │                                                         │      │      │
│   │   │   ⚠️  3 ZIRAH agents unresponsive (investigating)       │      │      │
│   │   │   ⚠️  1 MENARA device showing anomalous behavior        │      │      │
│   │   │                                                         │      │      │
│   │   └─────────────────────────────────────────────────────────┘      │      │
│   │                                                                     │      │
│   └─────────────────────────────────────────────────────────────────────┘      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
       DIAGRAM 8: DAILY OPERATIONS - THREAT UPDATE FLOW
═══════════════════════════════════════════════════════════════════════════════

How a new threat discovered at 9:00 AM protects ALL customers by 9:05 AM:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                    THREAT UPDATE FLOW (DAILY OPERATIONS)                        │
│                                                                                 │
│  TIME: 09:00:00 - Customer A's ZIRAH detects unknown ransomware                │
│  ════════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 1: DETECTION (T+0 seconds)                                         │   │
│  │                                                                          │   │
│  │   Customer A's Network                                                   │   │
│  │   ┌────────────────────────────────────────────────────────────┐        │   │
│  │   │                                                            │        │   │
│  │   │   ┌─────────┐     ┌─────────────────────────────────┐     │        │   │
│  │   │   │ Malware │────▶│         ZIRAH AGENT             │     │        │   │
│  │   │   │ Process │     │                                 │     │        │   │
│  │   │   └─────────┘     │  • eBPF detects anomaly         │     │        │   │
│  │   │                   │  • Behavior: encrypting files   │     │        │   │
│  │   │                   │  • Pattern: never seen before   │     │        │   │
│  │   │                   │  • Action: BLOCK + QUARANTINE   │     │        │   │
│  │   │                   │                                 │     │        │   │
│  │   │                   │  🔒 Extract behavioral pattern  │     │        │   │
│  │   │                   │  🔒 WITHOUT capturing malware   │     │        │   │
│  │   │                   └─────────────┬───────────────────┘     │        │   │
│  │   │                                 │                         │        │   │
│  │   └─────────────────────────────────┼─────────────────────────┘        │   │
│  │                                     │                                   │   │
│  └─────────────────────────────────────┼───────────────────────────────────┘   │
│                                        │                                       │
│  ┌─────────────────────────────────────▼───────────────────────────────────┐   │
│  │ STEP 2: ZK PROOF GENERATION (T+1 second)                                │   │
│  │                                                                          │   │
│  │   ┌────────────────────────────────────────────────────────────┐        │   │
│  │   │                                                            │        │   │
│  │   │   ZIRAH generates Zero-Knowledge Proof:                    │        │   │
│  │   │                                                            │        │   │
│  │   │   "I witnessed behavior pattern B that:                    │        │   │
│  │   │    - Accessed >100 files in 5 seconds                      │        │   │
│  │   │    - Encrypted file headers with pattern E                 │        │   │
│  │   │    - Attempted to delete shadow copies                     │        │   │
│  │   │    - Made network calls to suspicious endpoints            │        │   │
│  │   │                                                            │        │   │
│  │   │    WITHOUT revealing:                                      │        │   │
│  │   │    - Which files                                           │        │   │
│  │   │    - Customer's network topology                           │        │   │
│  │   │    - Actual malware binary                                 │        │   │
│  │   │    - Any customer data"                                    │        │   │
│  │   │                                                            │        │   │
│  │   │   Proof Size: ~700 bytes (Bulletproofs)                    │        │   │
│  │   │   Signed with: Device ML-DSA-65 key                        │        │   │
│  │   │                                                            │        │   │
│  │   └────────────────────────────────┬───────────────────────────┘        │   │
│  │                                    │                                     │   │
│  └────────────────────────────────────┼─────────────────────────────────────┘   │
│                                       │                                        │
│  ┌────────────────────────────────────▼─────────────────────────────────────┐  │
│  │ STEP 3: MESH PROPAGATION (T+5 seconds)                                   │  │
│  │                                                                           │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐    │  │
│  │   │                                                                 │    │  │
│  │   │                      SARAF MESH NETWORK                         │    │  │
│  │   │                                                                 │    │  │
│  │   │        ZK Proof                                                 │    │  │
│  │   │           │                                                     │    │  │
│  │   │           ▼                                                     │    │  │
│  │   │    ┌──────────────┐                                             │    │  │
│  │   │    │ Aggregation  │──────────────────────────────┐              │    │  │
│  │   │    │    Node      │                              │              │    │  │
│  │   │    └──────┬───────┘                              │              │    │  │
│  │   │           │                                      │              │    │  │
│  │   │           │ Verify proof cryptographically       │              │    │  │
│  │   │           │ (No access to original data)         │              │    │  │
│  │   │           │                                      │              │    │  │
│  │   │           ▼                                      ▼              │    │  │
│  │   │    ┌──────────────┐                       ┌──────────────┐     │    │  │
│  │   │    │   Pattern    │                       │   Pattern    │     │    │  │
│  │   │    │   Compiler   │                       │   Compiler   │     │    │  │
│  │   │    │              │                       │              │     │    │  │
│  │   │    │ Generates:   │                       │ Generates:   │     │    │  │
│  │   │    │ Behavioral   │                       │ Network      │     │    │  │
│  │   │    │ signature    │                       │ indicators   │     │    │  │
│  │   │    └──────┬───────┘                       └──────┬───────┘     │    │  │
│  │   │           │                                      │              │    │  │
│  │   │           └──────────────────┬───────────────────┘              │    │  │
│  │   │                              │                                  │    │  │
│  │   │                              ▼                                  │    │  │
│  │   │                   ┌───────────────────┐                         │    │  │
│  │   │                   │ UNIFIED PATTERN   │                         │    │  │
│  │   │                   │                   │                         │    │  │
│  │   │                   │ threat_id: T-2025 │                         │    │  │
│  │   │                   │ type: ransomware  │                         │    │  │
│  │   │                   │ severity: CRITICAL│                         │    │  │
│  │   │                   │ behavior_hash: H1 │                         │    │  │
│  │   │                   │ network_hash: H2  │                         │    │  │
│  │   │                   │ confidence: 99.7% │                         │    │  │
│  │   │                   │                   │                         │    │  │
│  │   │                   └─────────┬─────────┘                         │    │  │
│  │   │                             │                                   │    │  │
│  │   └─────────────────────────────┼───────────────────────────────────┘    │  │
│  │                                 │                                        │  │
│  └─────────────────────────────────┼────────────────────────────────────────┘  │
│                                    │                                           │
│  ┌─────────────────────────────────▼────────────────────────────────────────┐  │
│  │ STEP 4: PROOF-CARRYING UPDATE (T+30 seconds)                             │  │
│  │                                                                           │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐    │  │
│  │   │                                                                 │    │  │
│  │   │   UPDATE PACKAGE:                                               │    │  │
│  │   │   ┌──────────────────────────────────────────────────────┐     │    │  │
│  │   │   │                                                      │     │    │  │
│  │   │   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │     │    │  │
│  │   │   │  │   Pattern   │  │    Proof    │  │  Signature  │  │     │    │  │
│  │   │   │  │    Data     │  │   "This is  │  │  (ML-DSA +  │  │     │    │  │
│  │   │   │  │             │  │   safe to   │  │   Ed25519)  │  │     │    │  │
│  │   │   │  │  (200 bytes)│  │   deploy"   │  │             │  │     │    │  │
│  │   │   │  └─────────────┘  └─────────────┘  └─────────────┘  │     │    │  │
│  │   │   │                                                      │     │    │  │
│  │   │   └──────────────────────────────────────────────────────┘     │    │  │
│  │   │                                                                 │    │  │
│  │   │   Every endpoint verifies BEFORE applying:                      │    │  │
│  │   │   ✓ Signatures valid (cryptographic)                           │    │  │
│  │   │   ✓ Proof valid (mathematical)                                 │    │  │
│  │   │   ✓ Pattern well-formed (schema)                               │    │  │
│  │   │   ✓ Version newer than current (rollback protection)           │    │  │
│  │   │                                                                 │    │  │
│  │   └─────────────────────────────────────────────────────────────────┘    │  │
│  │                                                                           │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │ STEP 5: GLOBAL DEPLOYMENT (T+5 minutes)                                   │  │
│  │                                                                           │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐    │  │
│  │   │                                                                 │    │  │
│  │   │   WORLDWIDE PROTECTION STATUS:                                  │    │  │
│  │   │                                                                 │    │  │
│  │   │   ┌─────────────────────────────────────────────────────────┐  │    │  │
│  │   │   │                                                         │  │    │  │
│  │   │   │   ZIRAH (EDR)                                           │  │    │  │
│  │   │   │   ═══════════════════════════════════════               │  │    │  │
│  │   │   │   │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ 100% updated    │  │    │  │
│  │   │   │   50,000 endpoints protected                            │  │    │  │
│  │   │   │                                                         │  │    │  │
│  │   │   │   GAPURA (WAF)                                          │  │    │  │
│  │   │   │   ═══════════════════════════════════════               │  │    │  │
│  │   │   │   │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ 100% updated    │  │    │  │
│  │   │   │   10,000 gateways blocking C2 patterns                  │  │    │  │
│  │   │   │                                                         │  │    │  │
│  │   │   │   MENARA (Mobile)                                       │  │    │  │
│  │   │   │   ═══════════════════════════════════════               │  │    │  │
│  │   │   │   │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░│ 87% updated     │  │    │  │
│  │   │   │   2,000,000 devices (offline devices update on connect) │  │    │  │
│  │   │   │                                                         │  │    │  │
│  │   │   │   BENTENG (eKYC) - N/A for ransomware                   │  │    │  │
│  │   │   │   SANDI (DigiSig) - N/A for ransomware                  │  │    │  │
│  │   │   │                                                         │  │    │  │
│  │   │   └─────────────────────────────────────────────────────────┘  │    │  │
│  │   │                                                                 │    │  │
│  │   └─────────────────────────────────────────────────────────────────┘    │  │
│  │                                                                           │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  TIME: 09:05:00 - ALL TERAS CUSTOMERS PROTECTED                                │
│  ════════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│  SUMMARY:                                                                       │
│  • Detection at ONE customer → Protection for ALL customers                    │
│  • No customer data shared (Zero-Knowledge)                                    │
│  • No central server sees raw threats (distributed mesh)                       │
│  • Every update cryptographically verified (proof-carrying)                    │
│  • Cannot deploy bad update (client verifies independently)                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
       DIAGRAM 9: THREAT TYPE ROUTING
═══════════════════════════════════════════════════════════════════════════════

Not all threats are relevant to all products. SARAF routes intelligently:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                        THREAT ROUTING MATRIX                                    │
│                                                                                 │
│   ┌───────────────────────────────────────────────────────────────────────┐    │
│   │                                                                       │    │
│   │   THREAT TYPE          │ ZIRAH │GAPURA│MENARA│BENTENG│SANDI│         │    │
│   │   ═══════════════════════════════════════════════════════════         │    │
│   │                        │       │      │      │       │     │         │    │
│   │   Ransomware behavior  │   ●   │  ○   │  ●   │   ○   │  ○  │         │    │
│   │   SQLi patterns        │   ○   │  ●   │  ○   │   ○   │  ○  │         │    │
│   │   XSS payloads         │   ○   │  ●   │  ○   │   ○   │  ○  │         │    │
│   │   Phishing URLs        │   ○   │  ●   │  ●   │   ○   │  ○  │         │    │
│   │   Deepfake patterns    │   ○   │  ○   │  ○   │   ●   │  ○  │         │    │
│   │   Document fraud       │   ○   │  ○   │  ○   │   ●   │  ●  │         │    │
│   │   Malicious C2         │   ●   │  ●   │  ●   │   ○   │  ○  │         │    │
│   │   Crypto mining        │   ●   │  ○   │  ●   │   ○   │  ○  │         │    │
│   │   Privilege escalation │   ●   │  ○   │  ●   │   ○   │  ○  │         │    │
│   │   API abuse            │   ○   │  ●   │  ○   │   ●   │  ●  │         │    │
│   │   Bot networks         │   ○   │  ●   │  ○   │   ○   │  ○  │         │    │
│   │   Identity theft       │   ○   │  ○   │  ●   │   ●   │  ●  │         │    │
│   │   Signature tampering  │   ○   │  ○   │  ○   │   ○   │  ●  │         │    │
│   │                        │       │      │      │       │     │         │    │
│   │   ● = High relevance (immediate push)                                │    │
│   │   ○ = Low relevance (background sync)                                │    │
│   │                                                                       │    │
│   └───────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│   INTELLIGENT ROUTING:                                                          │
│                                                                                 │
│   ┌───────────────────────────────────────────────────────────────────────┐    │
│   │                                                                       │    │
│   │    ┌─────────────┐                                                   │    │
│   │    │   NEW       │                                                   │    │
│   │    │   THREAT    │                                                   │    │
│   │    └──────┬──────┘                                                   │    │
│   │           │                                                          │    │
│   │           ▼                                                          │    │
│   │    ┌─────────────┐                                                   │    │
│   │    │  CLASSIFY   │──────────────────────────────────────┐            │    │
│   │    │  (AI + Rule)│                                      │            │    │
│   │    └──────┬──────┘                                      │            │    │
│   │           │                                             │            │    │
│   │           ▼                                             ▼            │    │
│   │    ┌─────────────┐                               ┌─────────────┐    │    │
│   │    │ HIGH        │                               │ LOW         │    │    │
│   │    │ RELEVANCE   │                               │ RELEVANCE   │    │    │
│   │    └──────┬──────┘                               └──────┬──────┘    │    │
│   │           │                                             │            │    │
│   │           ▼                                             ▼            │    │
│   │    ┌─────────────┐                               ┌─────────────┐    │    │
│   │    │ IMMEDIATE   │                               │ BACKGROUND  │    │    │
│   │    │ PUSH        │                               │ SYNC        │    │    │
│   │    │ (< 1 min)   │                               │ (next hour) │    │    │
│   │    └─────────────┘                               └─────────────┘    │    │
│   │                                                                       │    │
│   └───────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
       DIAGRAM 10: PROOF-CARRYING CODE UPDATE DETAIL
═══════════════════════════════════════════════════════════════════════════════

Why TERAS can NEVER have a CrowdStrike-style outage:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                 PROOF-CARRYING CODE UPDATE (DETAIL)                             │
│                                                                                 │
│   TRADITIONAL UPDATE:                 TERAS UPDATE:                             │
│   ═══════════════════                 ═════════════                             │
│                                                                                 │
│   ┌─────────────────┐                 ┌─────────────────────────────────────┐  │
│   │                 │                 │                                     │  │
│   │   VENDOR        │                 │   VENDOR                            │  │
│   │   ┌─────────┐   │                 │   ┌─────────────────────────────┐   │  │
│   │   │ Write   │   │                 │   │ Write code                  │   │  │
│   │   │ code    │   │                 │   │         │                   │   │  │
│   │   └────┬────┘   │                 │   │         ▼                   │   │  │
│   │        │        │                 │   │ ┌─────────────────────────┐ │   │  │
│   │        │        │                 │   │ │ Write SPECIFICATION     │ │   │  │
│   │        │        │                 │   │ │ (What it SHOULD do)     │ │   │  │
│   │        │        │                 │   │ └───────────┬─────────────┘ │   │  │
│   │        │        │                 │   │             │               │   │  │
│   │        │        │                 │   │             ▼               │   │  │
│   │        │        │                 │   │ ┌─────────────────────────┐ │   │  │
│   │        │        │                 │   │ │ Generate PROOF          │ │   │  │
│   │        │        │                 │   │ │ (Code matches spec)     │ │   │  │
│   │        │        │                 │   │ └───────────┬─────────────┘ │   │  │
│   │        │        │                 │   │             │               │   │  │
│   │   ┌────▼────┐   │                 │   └─────────────┼───────────────┘   │  │
│   │   │  Test   │   │                 │                 │                   │  │
│   │   │ (maybe) │   │                 │                 │                   │  │
│   │   └────┬────┘   │                 │                 │                   │  │
│   │        │        │                 │                 │                   │  │
│   │   ┌────▼────┐   │                 │   ┌─────────────▼───────────────┐   │  │
│   │   │  Sign   │   │                 │   │                             │   │  │
│   │   │         │   │                 │   │  PACKAGE:                   │   │  │
│   │   └────┬────┘   │                 │   │  ┌───────┬───────┬───────┐  │   │  │
│   │        │        │                 │   │  │ Code  │ Spec  │ Proof │  │   │  │
│   │        │        │                 │   │  └───────┴───────┴───────┘  │   │  │
│   │        │        │                 │   │            │                │   │  │
│   │   ┌────▼────┐   │                 │   │      ┌─────▼─────┐          │   │  │
│   │   │  Push   │   │                 │   │      │   Sign    │          │   │  │
│   │   │ to all  │   │                 │   │      │ (2 keys)  │          │   │  │
│   │   └────┬────┘   │                 │   │      └─────┬─────┘          │   │  │
│   │        │        │                 │   │            │                │   │  │
│   └────────┼────────┘                 │   └────────────┼────────────────┘   │  │
│            │                          │                │                    │  │
│            │                          │                │                    │  │
│   ┌────────▼────────┐                 │   ┌────────────▼────────────────┐   │  │
│   │                 │                 │   │                             │   │  │
│   │   CLIENT        │                 │   │   CLIENT                    │   │  │
│   │                 │                 │   │                             │   │  │
│   │   ┌─────────┐   │                 │   │   ┌─────────────────────┐   │   │  │
│   │   │ Verify  │   │                 │   │   │ 1. Verify signature │   │   │  │
│   │   │ sig     │   │                 │   │   │    (cryptographic)  │   │   │  │
│   │   └────┬────┘   │                 │   │   └──────────┬──────────┘   │   │  │
│   │        │        │                 │   │              │              │   │  │
│   │   ┌────▼────┐   │                 │   │   ┌──────────▼──────────┐   │   │  │
│   │   │ INSTALL │   │                 │   │   │ 2. Verify PROOF     │   │   │  │
│   │   │ (blind  │   │                 │   │   │    (mathematical)   │   │   │  │
│   │   │ trust)  │   │                 │   │   │                     │   │   │  │
│   │   └────┬────┘   │                 │   │   │    "Does code       │   │   │  │
│   │        │        │                 │   │   │     actually match  │   │   │  │
│   │        │        │                 │   │   │     specification?" │   │   │  │
│   │        │        │                 │   │   │                     │   │   │  │
│   │        │        │                 │   │   └──────────┬──────────┘   │   │  │
│   │        │        │                 │   │              │              │   │  │
│   │   ┌────▼────┐   │                 │   │   ┌──────────▼──────────┐   │   │  │
│   │   │  💥     │   │                 │   │   │ 3. Check spec       │   │   │  │
│   │   │ CRASH   │   │                 │   │   │    (no backdoors)   │   │   │  │
│   │   │         │   │                 │   │   └──────────┬──────────┘   │   │  │
│   │   │ (If bad │   │                 │   │              │              │   │  │
│   │   │  code)  │   │                 │   │   ┌──────────▼──────────┐   │   │  │
│   │   └─────────┘   │                 │   │   │ 4. ALL PASS?        │   │   │  │
│   │                 │                 │   │   └──────────┬──────────┘   │   │  │
│   └─────────────────┘                 │   │              │              │   │  │
│                                       │   │         YES  │   NO         │   │  │
│                                       │   │              │              │   │  │
│                                       │   │   ┌──────────▼──┐  ┌───────▼───┐│  │
│                                       │   │   │  INSTALL    │  │  REJECT   ││  │
│                                       │   │   │  (safe)     │  │  + ALERT  ││  │
│                                       │   │   └─────────────┘  └───────────┘│  │
│                                       │   │                                 │   │
│                                       │   └─────────────────────────────────┘   │
│                                       │                                         │
│                                       └─────────────────────────────────────────┘
│                                                                                 │
│   RESULT:                                                                       │
│   • Bad code CANNOT be deployed (proof won't verify)                           │
│   • Backdoored code CANNOT be deployed (spec is visible)                       │
│   • Compromised vendor CANNOT push malware (clients verify independently)      │
│   • CrowdStrike-style outage IMPOSSIBLE (verification catches bad updates)     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
       DIAGRAM 11: COMPLETE ECOSYSTEM INTEGRATION
═══════════════════════════════════════════════════════════════════════════════

Everything working together:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                    THE COMPLETE TERAS ECOSYSTEM                                 │
│                                                                                 │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │                         CUSTOMER NETWORKS                                │  │
│   │                                                                          │  │
│   │     BANK A           TELCO B          RETAIL C         GOV D            │  │
│   │   ┌────────┐       ┌────────┐       ┌────────┐       ┌────────┐        │  │
│   │   │BENTENG │       │ ZIRAH  │       │MENARA  │       │ SANDI  │        │  │
│   │   │ SANDI  │       │ GAPURA │       │ GAPURA │       │BENTENG │        │  │
│   │   │ ZIRAH  │       │        │       │        │       │ ZIRAH  │        │  │
│   │   └───┬────┘       └───┬────┘       └───┬────┘       └───┬────┘        │  │
│   │       │                │                │                │              │  │
│   └───────┼────────────────┼────────────────┼────────────────┼──────────────┘  │
│           │                │                │                │                  │
│           │    Encrypted   │    Encrypted   │    Encrypted   │                  │
│           │    Channel     │    Channel     │    Channel     │                  │
│           │   (PQ-Hybrid)  │   (PQ-Hybrid)  │   (PQ-Hybrid)  │                  │
│           │                │                │                │                  │
│   ┌───────┴────────────────┴────────────────┴────────────────┴──────────────┐  │
│   │                                                                          │  │
│   │                          SARAF MESH LAYER                                │  │
│   │                                                                          │  │
│   │   ┌──────────────────────────────────────────────────────────────────┐  │  │
│   │   │                                                                  │  │  │
│   │   │     ○───────○───────○───────○───────○───────○                   │  │  │
│   │   │     │       │       │       │       │       │                   │  │  │
│   │   │     │   ┌───┴───┐   │   ┌───┴───┐   │   ┌───┴───┐              │  │  │
│   │   │     │   │Aggreg │   │   │Aggreg │   │   │Aggreg │              │  │  │
│   │   │     │   │ Node  │   │   │ Node  │   │   │ Node  │              │  │  │
│   │   │     │   └───────┘   │   └───────┘   │   └───────┘              │  │  │
│   │   │     │               │               │                          │  │  │
│   │   │     ○───────○───────○───────○───────○───────○                   │  │  │
│   │   │                                                                  │  │  │
│   │   │   (P2P mesh - no central point of failure)                      │  │  │
│   │   │   (Byzantine fault tolerant - survives 1/3 node compromise)     │  │  │
│   │   │                                                                  │  │  │
│   │   └──────────────────────────────────────────────────────────────────┘  │  │
│   │                                                                          │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                      │
│                                          │                                      │
│   ┌──────────────────────────────────────▼──────────────────────────────────┐  │
│   │                                                                          │  │
│   │                           NADI PULSE LAYER                               │  │
│   │                                                                          │  │
│   │   ┌──────────────────────────────────────────────────────────────────┐  │  │
│   │   │                                                                  │  │  │
│   │   │         ♥           ♥           ♥           ♥           ♥        │  │  │
│   │   │         │           │           │           │           │        │  │  │
│   │   │     ┌───┴───┐   ┌───┴───┐   ┌───┴───┐   ┌───┴───┐   ┌───┴───┐   │  │  │
│   │   │     │Health │   │Health │   │Health │   │Health │   │Health │   │  │  │
│   │   │     │Monitor│   │Monitor│   │Monitor│   │Monitor│   │Monitor│   │  │  │
│   │   │     └───────┘   └───────┘   └───────┘   └───────┘   └───────┘   │  │  │
│   │   │                                                                  │  │  │
│   │   │   (Every component heartbeats every 10 seconds)                 │  │  │
│   │   │   (Anomaly detection on heartbeat patterns)                     │  │  │
│   │   │   (Silent failure = immediate investigation)                    │  │  │
│   │   │                                                                  │  │  │
│   │   └──────────────────────────────────────────────────────────────────┘  │  │
│   │                                                                          │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                      │
│                                          │                                      │
│   ┌──────────────────────────────────────▼──────────────────────────────────┐  │
│   │                                                                          │  │
│   │                          JEJAK AUDIT LAYER                               │  │
│   │                                                                          │  │
│   │   ┌──────────────────────────────────────────────────────────────────┐  │  │
│   │   │                                                                  │  │  │
│   │   │  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐ │  │  │
│   │   │  │ E1  │ E2  │ E3  │ E4  │ E5  │ E6  │ E7  │ E8  │ E9  │ ... │ │  │  │
│   │   │  │     │     │     │     │     │     │     │     │     │     │ │  │  │
│   │   │  │ H1 ─┼─H2 ─┼─H3 ─┼─H4 ─┼─H5 ─┼─H6 ─┼─H7 ─┼─H8 ─┼─H9 ─┼─... │ │  │  │
│   │   │  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘ │  │  │
│   │   │                                                                  │  │  │
│   │   │   (Every event cryptographically chained)                       │  │  │
│   │   │   (Append-only - cannot modify history)                         │  │  │
│   │   │   (Replicated to 2+ locations)                                  │  │  │
│   │   │   (7-year retention for compliance)                             │  │  │
│   │   │                                                                  │  │  │
│   │   └──────────────────────────────────────────────────────────────────┘  │  │
│   │                                                                          │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   SECURITY GUARANTEES:                                                          │
│                                                                                 │
│   1. COLLECTIVE IMMUNITY                                                        │
│      → Threat at ONE customer protects ALL customers                           │
│      → Without sharing ANY customer data (Zero-Knowledge)                      │
│                                                                                 │
│   2. BYZANTINE FAULT TOLERANCE                                                  │
│      → System works even if 1/3 of nodes compromised                          │
│      → No single point of failure                                              │
│                                                                                 │
│   3. CRYPTOGRAPHIC INTEGRITY                                                    │
│      → Every update verified before deployment                                 │
│      → Bad updates mathematically impossible to deploy                         │
│                                                                                 │
│   4. POST-QUANTUM SECURITY                                                      │
│      → All communications use ML-KEM + X25519 hybrid                           │
│      → Quantum computers cannot break retroactively                            │
│                                                                                 │
│   5. COMPLETE AUDIT TRAIL                                                       │
│      → Every security event logged forever                                     │
│      → Cannot be modified (hash chain)                                         │
│      → Cannot be deleted (append-only)                                         │
│                                                                                 │
│   6. OFFLINE RESILIENCE                                                         │
│      → Core security works without network                                     │
│      → Mesh enhances but isn't required                                        │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
       DIAGRAM 12: DATA FLOW - WHAT STAYS WHERE
═══════════════════════════════════════════════════════════════════════════════

Privacy architecture - what data goes where:

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│                          DATA LOCALITY ARCHITECTURE                             │
│                                                                                 │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │                     CUSTOMER'S DEVICE/NETWORK                            │  │
│   │                                                                          │  │
│   │   DATA THAT NEVER LEAVES:                                                │  │
│   │   ═══════════════════════                                                │  │
│   │                                                                          │  │
│   │   ┌─────────────────────────────────────────────────────────────────┐   │  │
│   │   │                                                                 │   │  │
│   │   │   🔒 BIOMETRIC DATA                                            │   │  │
│   │   │      • Face images                                              │   │  │
│   │   │      • Face embeddings                                          │   │  │
│   │   │      • Fingerprint minutiae                                     │   │  │
│   │   │      • Voice prints                                             │   │  │
│   │   │                                                                 │   │  │
│   │   │   🔒 DOCUMENT IMAGES                                           │   │  │
│   │   │      • IC/Passport scans                                        │   │  │
│   │   │      • Supporting documents                                     │   │  │
│   │   │                                                                 │   │  │
│   │   │   🔒 PRIVATE KEYS                                              │   │  │
│   │   │      • Device signing keys                                      │   │  │
│   │   │      • User encryption keys                                     │   │  │
│   │   │                                                                 │   │  │
│   │   │   🔒 RAW THREAT DATA                                           │   │  │
│   │   │      • Actual malware binaries                                  │   │  │
│   │   │      • Attack source IPs                                        │   │  │
│   │   │      • Internal network topology                                │   │  │
│   │   │                                                                 │   │  │
│   │   └─────────────────────────────────────────────────────────────────┘   │  │
│   │                                                                          │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                          │                                      │
│                                          │ Only these leave:                    │
│                                          │                                      │
│                                          ▼                                      │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │                                                                          │  │
│   │   DATA THAT GOES TO SARAF MESH:                                          │  │
│   │   ═══════════════════════════════                                        │  │
│   │                                                                          │  │
│   │   ┌─────────────────────────────────────────────────────────────────┐   │  │
│   │   │                                                                 │   │  │
│   │   │   ✅ ZERO-KNOWLEDGE PROOFS                                     │   │  │
│   │   │      • "Face matches document" (not the face)                   │   │  │
│   │   │      • "Age ≥ 18" (not the birthdate)                          │   │  │
│   │   │      • "Threat matches pattern P" (not the threat)              │   │  │
│   │   │                                                                 │   │  │
│   │   │   ✅ BEHAVIORAL HASHES                                         │   │  │
│   │   │      • Hash of attack behavior (not actual attack)              │   │  │
│   │   │      • Hash of network patterns (not actual IPs)                │   │  │
│   │   │                                                                 │   │  │
│   │   │   ✅ SIGNED ATTESTATIONS                                       │   │  │
│   │   │      • "Device is healthy" (signed)                             │   │  │
│   │   │      • "Verification passed" (signed)                           │   │  │
│   │   │                                                                 │   │  │
│   │   │   ✅ HEALTH METRICS                                            │   │  │
│   │   │      • Component status                                         │   │  │
│   │   │      • Performance metrics (aggregated)                         │   │  │
│   │   │                                                                 │   │  │
│   │   └─────────────────────────────────────────────────────────────────┘   │  │
│   │                                                                          │  │
│   │   NOTHING in the mesh can be used to:                                    │  │
│   │   • Reconstruct faces                                                    │  │
│   │   • Identify individuals                                                 │  │
│   │   • Reconstruct attack details                                           │  │
│   │   • Identify customer networks                                           │  │
│   │                                                                          │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│   MATHEMATICAL GUARANTEE:                                                       │
│                                                                                 │
│   Zero-Knowledge proofs are information-theoretically secure.                  │
│   Even with infinite computing power, the original data cannot be              │
│   reconstructed from the proof.                                                │
│                                                                                 │
│   This is NOT encryption (which could be broken with enough compute).          │
│   This is mathematical impossibility.                                          │
│                                                                                 │
│   ═══════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
                           END OF DIAGRAMS
═══════════════════════════════════════════════════════════════════════════════

These diagrams represent the TERAS V3.1 architecture - a truly revolutionary
security platform that operates as a living organism rather than a collection
of separate tools.

Key innovations:
1. SARAF mesh - Zero-knowledge threat sharing across customers
2. NADI pulse - Byzantine fault-tolerant health monitoring
3. JEJAK chain - Tamper-evident cryptographic audit trail
4. Proof-carrying updates - Mathematically verified deployments
5. Hybrid PQ crypto - Quantum-resistant from day one

This is security as it should be: collective, intelligent, and private.

Document Version: 3.1.0
Date: 2025-12-30

# TERAS MASTER ARCHITECTURE v3.1 UPDATE SPECIFICATION

> **PURPOSE:** This document specifies ALL changes from v3.0 to v3.1
> **CHANGE TYPE:** ADDITIVE (no existing content modified, only additions)
> **PREVIOUS VERSION HASH:** [Compute SHA-256 of v3.0]

---

## CHANGE SUMMARY

| Section | Change Type | Description |
|---------|-------------|-------------|
| PART II | ADD | New REALITY 6: Threat Intelligence Bootstrap |
| PART IV | MODIFY | Add teras-suap crate to project structure |
| PART XI | ADD | New MODULE 5: Threat Feed Ingestion |
| NEW | ADD | PART XV: Threat Intelligence Bootstrap Strategy |
| Cargo.toml | MODIFY | Add teras-suap crate and dependencies |

---

## CHANGE 1: Add to PART II (Current Reality)

**Insert after REALITY 5 (What Can Be Built By Solo Developer):**

```
## REALITY 6: THREAT INTELLIGENCE BOOTSTRAP

╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   STATUS: Collective immunity requires SCALE. At early stage (0-100         ║
║           customers), external threat feeds are the primary source.         ║
║                                                                              ║
║   THE HONEST TIMELINE:                                                       ║
║   ┌────────────────────────────────────────────────────────────────────────┐ ║
║   │ Phase   │ Customers │ External │ Internal │ Value Proposition         │ ║
║   ├─────────┼───────────┼──────────┼──────────┼───────────────────────────│ ║
║   │ 0       │ 0         │ 100%     │ 0%       │ Curated aggregation       │ ║
║   │ 1       │ 1-10      │ 95%      │ 5%       │ Best-in-class delivery    │ ║
║   │ 2       │ 10-100    │ 60%      │ 40%      │ Peer threat visibility    │ ║
║   │ 3       │ 100+      │ 20%      │ 80%      │ TRUE collective immunity  │ ║
║   └────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
║   FREE THREAT INTELLIGENCE SOURCES:                                          ║
║   ┌────────────────────────────────────────────────────────────────────────┐ ║
║   │ Source              │ Data Type            │ Update     │ Cost         │ ║
║   ├─────────────────────┼──────────────────────┼────────────┼──────────────│ ║
║   │ abuse.ch            │ Malware URLs, C2, IOC│ Hourly     │ FREE         │ ║
║   │ AlienVault OTX      │ Community threat data│ Real-time  │ FREE         │ ║
║   │ Emerging Threats    │ Suricata/Snort rules │ Daily      │ FREE         │ ║
║   │ MISP (public)       │ Structured indicators│ Varies     │ FREE         │ ║
║   │ VirusTotal          │ Hash reputation      │ Real-time  │ FREE (500/d) │ ║
║   │ MyCERT              │ MY-specific threats  │ As needed  │ FREE (MY)    │ ║
║   │ OWASP ModSec CRS    │ WAF rules            │ Monthly    │ FREE         │ ║
║   │ MITRE ATT&CK        │ TTPs, techniques     │ Quarterly  │ FREE         │ ║
║   │ Custom Honeypots    │ Attack patterns      │ Continuous │ FREE*        │ ║
║   └────────────────────────────────────────────────────────────────────────┘ ║
║   * Oracle Cloud free tier: 4 ARM VMs                                        ║
║                                                                              ║
║   DAILY TIME COMMITMENT (Phase 0-1):                                         ║
║   • Automated overnight fetch: 0 minutes                                     ║
║   • Morning review of flagged items: 15-20 minutes                           ║
║   • Approval and deployment: 5-10 minutes                                    ║
║   • Total: 30 minutes/day                                                    ║
║                                                                              ║
║   ARCHITECTURE PROPERTY:                                                     ║
║   The proof-carrying update system is IDENTICAL at all phases.               ║
║   Only the SOURCE of threat data changes.                                    ║
║   Building for Phase 3 (collective immunity) from day 1.                     ║
║                                                                              ║
║   DO NOT:                                                                    ║
║   • Claim "collective immunity" until 50+ customers                          ║
║   • Skip external feeds at early stage                                       ║
║   • Promise 0-day detection without scale                                    ║
║                                                                              ║
║   DO:                                                                        ║
║   • Build teras-suap (feed ingestion) first                                  ║
║   • Automate feed fetching and normalization                                 ║
║   • Deploy honeypots on free infrastructure                                  ║
║   • Track MyCERT for Malaysia-specific threats                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## CHANGE 2: Modify PART IV SKELETON 1 (Project Structure)

**Add teras-suap to the crates directory:**

```
teras/
├── ...
├── crates/
│   ├── teras-core/              # Core types, no crypto
│   ├── teras-kunci/             # Cryptography
│   ├── teras-lindung/           # Memory protection
│   ├── teras-benteng/           # eKYC
│   │
│   └── teras-suap/              # Threat feed ingestion (NEW)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── types.rs         # ThreatIndicator, Confidence, etc.
│           ├── sources/         # Feed adapters
│           │   ├── mod.rs
│           │   ├── abuse_ch.rs  # abuse.ch (URLhaus, MalwareBazaar, etc.)
│           │   ├── alienvault.rs # AlienVault OTX
│           │   ├── emerging.rs  # Emerging Threats
│           │   ├── misp.rs      # MISP format
│           │   ├── mycert.rs    # MyCERT Malaysia
│           │   ├── owasp_crs.rs # ModSecurity CRS rules
│           │   └── custom.rs    # Custom/manual indicators
│           ├── normalize.rs     # Convert to common format
│           ├── dedupe.rs        # Deduplication
│           ├── validate.rs      # Indicator validation
│           ├── compile.rs       # Compile to product patterns
│           └── curator.rs       # Review queue management
│
├── tools/
│   ├── ...
│   └── teras-curator/           # CLI for threat review (NEW)
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
```

---

## CHANGE 3: Add to PART IV SKELETON 2 (Cargo.toml)

**Add to workspace members:**

```toml
[workspace]
members = [
    "crates/teras-core",
    "crates/teras-kunci",
    "crates/teras-lindung",
    "crates/teras-benteng",
    "crates/teras-suap",         # NEW
    "tools/teras-curator",        # NEW
]
```

**Add to workspace dependencies:**

```toml
[workspace.dependencies]
# ... existing deps ...

# Threat feed ingestion - EXACT VERSIONS
reqwest = { version = "=0.11.27", features = ["json", "rustls-tls"], default-features = false }
tokio = { version = "=1.36.0", features = ["rt-multi-thread", "macros", "time"] }
serde = { version = "=1.0.197", features = ["derive"] }
serde_json = "=1.0.114"
csv = "=1.3.0"
chrono = { version = "=0.4.35", features = ["serde"] }
url = "=2.5.0"
ipnetwork = "=0.20.0"

# Internal crates
teras-suap = { path = "crates/teras-suap" }
```

---

## CHANGE 4: Add PART XV (New Section)

**Insert after PART XIV:**

```
# PART XV: THREAT INTELLIGENCE BOOTSTRAP STRATEGY

This section defines how threat intelligence works at EARLY STAGE before
collective immunity reaches scale.

## XV.1: BOOTSTRAP PHASES

┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   PHASE 0: Solo Developer (0 customers)                                      │
│   ══════════════════════════════════════                                     │
│                                                                              │
│   ┌───────────────────┐                                                      │
│   │  EXTERNAL FEEDS   │─────────────────────────────────────────┐           │
│   │                   │                                         │           │
│   │  • abuse.ch       │                                         ▼           │
│   │  • AlienVault OTX │     ┌──────────────┐    ┌──────────────────────┐    │
│   │  • Emerging Thrt  │────▶│   CURATOR    │───▶│  PROOF-CARRYING      │    │
│   │  • MISP           │     │   (You)      │    │  UPDATE SYSTEM       │    │
│   │  • MyCERT         │     │  30 min/day  │    │  (Same as Phase 3)   │    │
│   │  • Honeypots      │     └──────────────┘    └──────────────────────┘    │
│   └───────────────────┘                                                      │
│                                                                              │
│   You ARE the threat intelligence. External feeds do 100% of detection.      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   PHASE 3: Scale (100+ customers) - TARGET STATE                             │
│   ══════════════════════════════════════════════                             │
│                                                                              │
│   ┌───────────────────┐     ┌───────────────────┐                           │
│   │  EXTERNAL FEEDS   │     │  CUSTOMER MESH    │                           │
│   │  (20% - validate) │     │  (80% - primary)  │                           │
│   └─────────┬─────────┘     └─────────┬─────────┘                           │
│             │                         │                                      │
│             └───────────┬─────────────┘                                      │
│                         │                                                    │
│                         ▼                                                    │
│               ┌──────────────────┐    ┌──────────────────────┐              │
│               │  ZK AGGREGATION  │───▶│  PROOF-CARRYING      │              │
│               │  (Automatic)     │    │  UPDATE SYSTEM       │              │
│               └──────────────────┘    └──────────────────────┘              │
│                                                                              │
│   Collective immunity: Detect 0-days before public disclosure.               │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

## XV.2: FEED SOURCE SPECIFICATIONS

### abuse.ch Suite (FREE)

┌──────────────────────────────────────────────────────────────────────────────┐
│ Feed           │ URL                                      │ Format │ Update │
├────────────────┼──────────────────────────────────────────┼────────┼────────┤
│ URLhaus        │ https://urlhaus.abuse.ch/downloads/csv/ │ CSV    │ 5 min  │
│ MalwareBazaar  │ https://bazaar.abuse.ch/export/csv/     │ CSV    │ Hourly │
│ ThreatFox      │ https://threatfox.abuse.ch/export/csv/  │ CSV    │ Hourly │
│ Feodo Tracker  │ https://feodotracker.abuse.ch/downloads/│ CSV    │ Hourly │
│ SSL Blacklist  │ https://sslbl.abuse.ch/blacklist/       │ CSV    │ Daily  │
└────────────────┴──────────────────────────────────────────┴────────┴────────┘

### AlienVault OTX (FREE with API key)

┌──────────────────────────────────────────────────────────────────────────────┐
│ Endpoint: https://otx.alienvault.com/api/v1/                                 │
│ Rate Limit: 10,000 requests/hour (free tier)                                 │
│ Data: Pulses (threat reports with IOCs)                                      │
│ Relevant APIs:                                                               │
│   • /pulses/subscribed - Subscribed pulse updates                            │
│   • /indicators/export - Bulk IOC export                                     │
└──────────────────────────────────────────────────────────────────────────────┘

### MyCERT (Malaysia - FREE for MY organizations)

┌──────────────────────────────────────────────────────────────────────────────┐
│ URL: https://www.mycert.org.my                                               │
│ Data: Malaysia-specific advisories, alerts, IOCs                             │
│ Relevance: HIGH for Malaysian customers                                      │
│ Format: RSS, manual parsing required                                         │
│ Contact: advisories@mycert.org.my for API access                             │
└──────────────────────────────────────────────────────────────────────────────┘

## XV.3: INDICATOR TYPES

┌──────────────────────────────────────────────────────────────────────────────┐
│ Type            │ Products          │ Example                                │
├─────────────────┼───────────────────┼────────────────────────────────────────┤
│ URL             │ GAPURA, MENARA    │ http://malware.example/payload.exe     │
│ Domain          │ GAPURA, MENARA    │ c2.malicious.com                       │
│ IP              │ GAPURA, ZIRAH     │ 192.168.1.100                          │
│ Hash (SHA-256)  │ ZIRAH, MENARA     │ a1b2c3d4...                            │
│ Email           │ BENTENG           │ phisher@scam.com                       │
│ Regex Pattern   │ GAPURA            │ /union\s+select/i                      │
│ YARA Rule       │ ZIRAH             │ rule Malware { ... }                   │
│ Suricata Rule   │ ZIRAH             │ alert tcp any any -> ...               │
│ TTP             │ All               │ T1566.001 (Spearphishing)              │
└─────────────────┴───────────────────┴────────────────────────────────────────┘

## XV.4: CONFIDENCE LEVELS

┌──────────────────────────────────────────────────────────────────────────────┐
│ Level    │ Threshold │ Auto-Approve │ Sources Required │ Action             │
├──────────┼───────────┼──────────────┼──────────────────┼────────────────────┤
│ HIGH     │ ≥ 90%     │ YES          │ 3+ independent   │ Deploy immediately │
│ MEDIUM   │ 50-89%    │ NO           │ 1-2 sources      │ Queue for review   │
│ LOW      │ < 50%     │ NO           │ 1 source only    │ Manual validation  │
└──────────┴───────────┴──────────────┴──────────────────┴────────────────────┘

Confidence calculation:
• Base: Source reputation (abuse.ch = HIGH, random Twitter = LOW)
• Boost: Multiple sources report same indicator (+20% per source)
• Boost: Matches honeypot observation (+30%)
• Decay: Age > 7 days (-10% per week)

## XV.5: DAILY WORKFLOW

┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   OVERNIGHT (Automated via cron)                                             │
│   ═══════════════════════════════                                            │
│                                                                              │
│   00:00  ┌─────────────────────────────────────────────────────────────┐    │
│          │ $ teras-suap fetch --all                                    │    │
│          │                                                             │    │
│          │ Fetching abuse.ch URLhaus...      [OK] 1,247 indicators     │    │
│          │ Fetching abuse.ch MalwareBazaar...  [OK] 523 indicators     │    │
│          │ Fetching AlienVault OTX...        [OK] 89 pulses            │    │
│          │ Fetching Emerging Threats...      [OK] 12 rule updates      │    │
│          │ Fetching MyCERT advisories...     [OK] 2 new advisories     │    │
│          │                                                             │    │
│          │ Normalizing...                    [OK]                      │    │
│          │ Deduplicating...                  [OK] 847 unique           │    │
│          │ Calculating confidence...         [OK]                      │    │
│          │                                                             │    │
│          │ Results:                                                    │    │
│          │   HIGH confidence:   612 (auto-approved)                    │    │
│          │   MEDIUM confidence: 189 (queued for review)                │    │
│          │   LOW confidence:     46 (queued for review)                │    │
│          │                                                             │    │
│          │ Email summary sent to: ikmal@teras.security                 │    │
│          └─────────────────────────────────────────────────────────────┘    │
│                                                                              │
│   MORNING (Manual, 15-20 minutes)                                            │
│   ═════════════════════════════════                                          │
│                                                                              │
│   09:00  ┌─────────────────────────────────────────────────────────────┐    │
│          │ $ teras-curator review --pending                            │    │
│          │                                                             │    │
│          │ Pending indicators: 235                                     │    │
│          │                                                             │    │
│          │ [1/235] MEDIUM CONFIDENCE                                   │    │
│          │ Type: URL                                                   │    │
│          │ Value: https://suspicious-domain.ru/download.exe            │    │
│          │ Source: AlienVault OTX (pulse: APT29-2024-Q4)               │    │
│          │ Products: GAPURA, MENARA                                    │    │
│          │                                                             │    │
│          │ [A]pprove  [R]eject  [S]kip  [I]nvestigate  [Q]uit          │    │
│          │ > A                                                         │    │
│          │                                                             │    │
│          │ Approved. [234 remaining]                                   │    │
│          └─────────────────────────────────────────────────────────────┘    │
│                                                                              │
│   DEPLOY (5 minutes)                                                         │
│   ═══════════════════                                                        │
│                                                                              │
│   09:20  ┌─────────────────────────────────────────────────────────────┐    │
│          │ $ teras-curator deploy --approved                           │    │
│          │                                                             │    │
│          │ Compiling patterns for GAPURA...  [OK]                      │    │
│          │ Compiling patterns for MENARA...  [OK]                      │    │
│          │ Compiling patterns for ZIRAH...   [OK]                      │    │
│          │                                                             │    │
│          │ Generating proof...               [OK]                      │    │
│          │ Signing update...                 [OK]                      │    │
│          │                                                             │    │
│          │ Deploying to production...        [OK]                      │    │
│          │                                                             │    │
│          │ Update v2024.12.30.001 deployed to 0 nodes                  │    │
│          │ (No customers yet - patterns ready for first deployment)    │    │
│          └─────────────────────────────────────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

## XV.6: HONEYPOT INFRASTRUCTURE

Deploy on Oracle Cloud Always Free Tier (4 ARM VMs):

┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   HONEYPOT DEPLOYMENT (FREE)                                                 │
│                                                                              │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐    │
│   │  HONEYPOT 1 │   │  HONEYPOT 2 │   │  HONEYPOT 3 │   │  HONEYPOT 4 │    │
│   │  Singapore  │   │  US West    │   │  EU Central │   │  Malaysia   │    │
│   │  SSH/HTTP   │   │  SSH/HTTP   │   │  SSH/HTTP   │   │  SSH/HTTP   │    │
│   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘    │
│          │                 │                 │                 │            │
│          └─────────────────┴────────┬────────┴─────────────────┘            │
│                                     │                                        │
│                                     ▼                                        │
│                          ┌──────────────────┐                               │
│                          │  teras-suap      │                               │
│                          │  (custom source) │                               │
│                          └──────────────────┘                               │
│                                                                              │
│   Software: Cowrie (SSH), Dionaea (HTTP), or similar                         │
│   Output: Attack IPs, credentials attempted, payloads                        │
│   Value: See attacks targeting YOUR infrastructure specifically              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

## XV.7: CRATE SPECIFICATION

### teras-suap Cargo.toml

```toml
[package]
name = "teras-suap"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
teras-core = { workspace = true }
teras-kunci = { workspace = true }

# Async runtime
tokio = { workspace = true }

# HTTP client
reqwest = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }
csv = { workspace = true }

# Date/time
chrono = { workspace = true }

# Network types
url = { workspace = true }
ipnetwork = { workspace = true }

[dev-dependencies]
tokio-test = "0.4"
```

### Core Types (types.rs)

```rust
// crates/teras-suap/src/types.rs
// EXACT IMPLEMENTATION

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Confidence level for threat indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,    // < 50%  - Single source, unverified
    Medium, // 50-89% - Some corroboration
    High,   // ≥ 90%  - Multiple sources, verified
}

impl Confidence {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=49 => Confidence::Low,
            50..=89 => Confidence::Medium,
            90..=100 => Confidence::High,
            _ => Confidence::High, // Clamp to 100
        }
    }
    
    pub fn auto_approve(&self) -> bool {
        matches!(self, Confidence::High)
    }
}

/// Which TERAS product this indicator applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Product {
    Gapura,  // WAF
    Menara,  // Mobile security
    Zirah,   // EDR
    Benteng, // eKYC
    Sandi,   // Digital signatures
}

/// Type of threat indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    Url(String),
    Domain(String),
    IpAddress(IpAddr),
    IpRange(ipnetwork::IpNetwork),
    Sha256(String),
    Sha1(String),
    Md5(String),
    Email(String),
    Regex(String),
    YaraRule(String),
    SuricataRule(String),
    MitreAttack(String), // T1566.001 format
}

/// Source of threat intelligence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    AbuseCh { feed: String },      // URLhaus, MalwareBazaar, etc.
    AlienVaultOtx { pulse_id: String },
    EmergingThreats,
    Misp { instance: String },
    MyCert { advisory_id: String },
    OwaspCrs { rule_id: String },
    MitreAttack,
    Honeypot { location: String },
    Manual { analyst: String },
}

/// A threat indicator with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// Unique identifier (SHA-256 of indicator value)
    pub id: String,
    
    /// The actual indicator
    pub indicator: IndicatorType,
    
    /// Confidence level
    pub confidence: Confidence,
    
    /// Raw confidence score (0-100)
    pub confidence_score: u8,
    
    /// Where this came from
    pub sources: Vec<Source>,
    
    /// Which products should use this
    pub products: Vec<Product>,
    
    /// When first seen
    pub first_seen: DateTime<Utc>,
    
    /// When last updated
    pub last_updated: DateTime<Utc>,
    
    /// Human-readable description
    pub description: Option<String>,
    
    /// Related MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    
    /// Tags for categorization
    pub tags: Vec<String>,
    
    /// Is this approved for production?
    pub approved: bool,
    
    /// Who approved it (if manual)
    pub approved_by: Option<String>,
}

impl ThreatIndicator {
    /// Calculate indicator ID from value.
    pub fn calculate_id(indicator: &IndicatorType) -> String {
        use teras_kunci::hash::sha256;
        let bytes = match indicator {
            IndicatorType::Url(s) => s.as_bytes(),
            IndicatorType::Domain(s) => s.as_bytes(),
            IndicatorType::IpAddress(ip) => return hex::encode(sha256(ip.to_string().as_bytes())),
            IndicatorType::IpRange(net) => return hex::encode(sha256(net.to_string().as_bytes())),
            IndicatorType::Sha256(s) => s.as_bytes(),
            IndicatorType::Sha1(s) => s.as_bytes(),
            IndicatorType::Md5(s) => s.as_bytes(),
            IndicatorType::Email(s) => s.as_bytes(),
            IndicatorType::Regex(s) => s.as_bytes(),
            IndicatorType::YaraRule(s) => s.as_bytes(),
            IndicatorType::SuricataRule(s) => s.as_bytes(),
            IndicatorType::MitreAttack(s) => s.as_bytes(),
        };
        hex::encode(sha256(bytes))
    }
}

/// Review status for curator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewStatus {
    Pending,
    Approved,
    Rejected,
    Skipped,
}
```
```

---

## CHANGE 5: Add to PART IX (Glossary)

**Add these terms:**

```
TERM                    DEFINITION
────                    ──────────
Bootstrap Phase         Period before collective immunity has scale (0-100 customers)
Confidence Score        0-100 rating of indicator reliability
Curator                 Tool/person reviewing threat indicators before deployment
Honeypot                Decoy system to attract and study attacks
IOC                     Indicator of Compromise (IP, hash, URL, etc.)
MyCERT                  Malaysia Computer Emergency Response Team
OTX                     Open Threat Exchange (AlienVault)
Pulse                   AlienVault OTX threat report package
TTP                     Tactics, Techniques, and Procedures (MITRE framework)
```

---

## CHANGE 6: Update Quick Reference Card

**Add to PART XIV:**

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  THREAT BOOTSTRAP (Early Stage):                                             ║
║  ├─ Daily time: 30 min/day                                                   ║
║  ├─ FREE sources: abuse.ch, OTX, MyCERT, ET                                  ║
║  ├─ Auto-approve: HIGH confidence only                                       ║
║  ├─ Manual review: MEDIUM/LOW confidence                                     ║
║  └─ Collective immunity: kicks in at ~50-100 customers                       ║
║                                                                              ║
║  CRON SETUP:                                                                 ║
║  0 0 * * * /usr/local/bin/teras-suap fetch --all                             ║
║                                                                              ║
║  DAILY COMMANDS:                                                             ║
║  $ teras-curator review --pending                                            ║
║  $ teras-curator deploy --approved                                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## VERSION UPDATE

```
Document version: 3.1.0
Previous version: 3.0.0
Previous version hash: [SHA-256 of v3.0]
This version hash: [Compute after finalization]

Changes in 3.1.0:
• Added REALITY 6: Threat Intelligence Bootstrap
• Added PART XV: Threat Intelligence Bootstrap Strategy  
• Added teras-suap crate specification
• Added teras-curator CLI tool
• Updated project structure
• Updated Cargo.toml workspace
• Added glossary terms
• Updated quick reference card
```

---

## HOW TO APPLY

1. Copy the master architecture v3.0 to v3.1
2. Insert REALITY 6 after REALITY 5 in PART II
3. Update project structure in SKELETON 1
4. Update Cargo.toml in SKELETON 2
5. Insert new PART XV after PART XIV
6. Add new MODULE 5 to PART XI
7. Add glossary terms to PART IX
8. Update quick reference in PART XIV
9. Update version information at document end
10. Compute SHA-256 hashes

---

## DOCUMENT END

This specification is ADDITIVE ONLY. No existing content from v3.0 is modified.
The bootstrap strategy acknowledges the honest reality: collective immunity
requires scale, and external feeds provide value until that scale is reached.