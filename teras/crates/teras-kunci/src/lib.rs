//! TERAS Kunci - Cryptographic Primitives
//!
//! This crate provides all cryptographic operations for TERAS:
//! - HYBRID Key Encapsulation (ML-KEM-768 + X25519)
//! - HYBRID Digital Signatures (ML-DSA-65 + Ed25519)
//! - Symmetric Encryption (AES-256-GCM, ChaCha20-Poly1305)
//! - Hashing (SHA-256, SHA3-256, BLAKE3)
//! - Key Derivation (HKDF, Argon2id)
//!
//! # Security Properties
//!
//! - ALL key material wrapped in `Secret<T>` (LAW 4)
//! - ALL secret operations are constant-time (LAW 3)
//! - HYBRID mode mandatory - both classical AND post-quantum (Decision 4)
//! - ONLY approved algorithms used (LAW 2)
//!
//! # Example
//!
//! ```
//! use teras_kunci::kem::HybridKem;
//!
//! // Generate hybrid keypair (ML-KEM-768 + X25519)
//! let (private, public) = HybridKem::generate().unwrap();
//!
//! // Encapsulate to create shared secret
//! let (ciphertext, shared_secret) = public.encapsulate().unwrap();
//!
//! // Decapsulate on the other side
//! let recovered = private.decapsulate(&ciphertext).unwrap();
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod ct;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod rand;
pub mod sign;
pub mod symmetric;

// Re-exports for convenience
pub use ct::{ct_copy_if, ct_eq, ct_is_zero, ct_select};
pub use hash::{blake3_hash, sha256, sha3_256, HashAlgorithm};
pub use kem::{HybridCiphertext, HybridEncapsulationKey, HybridKem};
pub use sign::{HybridSignature, HybridSigner, HybridVerifyingKey};
pub use symmetric::{Aes256GcmCipher, ChaCha20Poly1305Cipher, SymmetricCipher};
