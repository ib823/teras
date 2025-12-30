//! Digital Signatures.
//!
//! HYBRID mode is MANDATORY per Decision 4:
//! - Dilithium3 (ML-DSA-65 equivalent) + Ed25519 (both must verify)

mod ed25519_sign;
mod hybrid;
mod mldsa;

pub use ed25519_sign::{Ed25519Signature, Ed25519Signer, Ed25519VerifyingKey};
pub use hybrid::{HybridSignature, HybridSigner, HybridVerifyingKey};
pub use mldsa::{Dilithium3Signature, Dilithium3Signer, Dilithium3VerifyingKey};
