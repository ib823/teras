//! Key Encapsulation Mechanisms.
//!
//! HYBRID mode is MANDATORY per Decision 4:
//! - Kyber-768 (ML-KEM equivalent) + X25519 (both must succeed)

mod hybrid;
mod mlkem;
mod x25519_kem;

pub use hybrid::{HybridCiphertext, HybridEncapsulationKey, HybridKem};
pub use mlkem::{Kyber768, Kyber768Ciphertext, Kyber768EncapsulationKey};
pub use x25519_kem::{X25519Ciphertext, X25519Kem, X25519PublicKey};
