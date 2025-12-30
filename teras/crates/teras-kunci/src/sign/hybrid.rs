//! Hybrid Signatures: Dilithium3 (ML-DSA-65 equivalent) + Ed25519
//!
//! MANDATORY per Decision 4. Both signatures must verify.

use super::ed25519_sign::{Ed25519Signature, Ed25519Signer, Ed25519VerifyingKey};
use super::mldsa::{Dilithium3Signature, Dilithium3Signer, Dilithium3VerifyingKey};
use teras_core::error::{TerasError, TerasResult};

/// Hybrid signer combining Dilithium3 and Ed25519.
pub struct HybridSigner {
    dilithium: Dilithium3Signer,
    ed25519: Ed25519Signer,
}

/// Hybrid verifying key (public).
#[derive(Clone)]
pub struct HybridVerifyingKey {
    dilithium_vk: Dilithium3VerifyingKey,
    ed25519_vk: Ed25519VerifyingKey,
}

/// Hybrid signature containing both signatures.
#[derive(Clone)]
pub struct HybridSignature {
    dilithium_sig: Dilithium3Signature,
    ed25519_sig: Ed25519Signature,
}

impl HybridSigner {
    /// Generate new hybrid keypair.
    ///
    /// # Errors
    ///
    /// Returns error if either key generation fails.
    pub fn generate() -> TerasResult<(Self, HybridVerifyingKey)> {
        let (dilithium, dilithium_vk) = Dilithium3Signer::generate()?;
        let (ed25519, ed25519_vk) = Ed25519Signer::generate()?;

        Ok((
            Self { dilithium, ed25519 },
            HybridVerifyingKey {
                dilithium_vk,
                ed25519_vk,
            },
        ))
    }

    /// Sign a message with both algorithms.
    ///
    /// # Errors
    ///
    /// Returns `HybridCryptoFailed` if either signing fails.
    pub fn sign(&self, message: &[u8]) -> TerasResult<HybridSignature> {
        let dilithium_sig =
            self.dilithium
                .sign(message)
                .map_err(|_| TerasError::HybridCryptoFailed {
                    classical_ok: true,
                    pq_ok: false,
                })?;

        let ed25519_sig =
            self.ed25519
                .sign(message)
                .map_err(|_| TerasError::HybridCryptoFailed {
                    classical_ok: false,
                    pq_ok: true,
                })?;

        Ok(HybridSignature {
            dilithium_sig,
            ed25519_sig,
        })
    }
}

impl HybridVerifyingKey {
    /// Verify a hybrid signature.
    ///
    /// BOTH signatures must verify. If either fails, verification fails.
    ///
    /// # Errors
    ///
    /// Returns `HybridCryptoFailed` if either signature verification fails.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> TerasResult<()> {
        // Verify Dilithium3
        self.dilithium_vk
            .verify(message, &signature.dilithium_sig)
            .map_err(|_| TerasError::HybridCryptoFailed {
                classical_ok: true,
                pq_ok: false,
            })?;

        // Verify Ed25519
        self.ed25519_vk
            .verify(message, &signature.ed25519_sig)
            .map_err(|_| TerasError::HybridCryptoFailed {
                classical_ok: false,
                pq_ok: true,
            })?;

        Ok(())
    }

    /// Get the Dilithium3 verifying key.
    #[must_use]
    pub fn dilithium_vk(&self) -> &Dilithium3VerifyingKey {
        &self.dilithium_vk
    }

    /// Get the Ed25519 verifying key.
    #[must_use]
    pub fn ed25519_vk(&self) -> &Ed25519VerifyingKey {
        &self.ed25519_vk
    }
}

impl HybridSignature {
    /// Get the Dilithium3 signature component.
    #[must_use]
    pub fn dilithium_sig(&self) -> &Dilithium3Signature {
        &self.dilithium_sig
    }

    /// Get the Ed25519 signature component.
    #[must_use]
    pub fn ed25519_sig(&self) -> &Ed25519Signature {
        &self.ed25519_sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_verify() {
        let (signer, verifier) = HybridSigner::generate().unwrap();
        let message = b"Hello, World!";

        let sig = signer.sign(message).unwrap();
        assert!(verifier.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_hybrid_wrong_message_fails() {
        let (signer, verifier) = HybridSigner::generate().unwrap();

        let sig = signer.sign(b"message1").unwrap();
        assert!(verifier.verify(b"message2", &sig).is_err());
    }

    #[test]
    fn test_hybrid_wrong_key_fails() {
        let (signer1, _verifier1) = HybridSigner::generate().unwrap();
        let (_signer2, verifier2) = HybridSigner::generate().unwrap();

        let message = b"test";
        let sig = signer1.sign(message).unwrap();

        assert!(verifier2.verify(message, &sig).is_err());
    }

    #[test]
    fn test_hybrid_contains_both_signatures() {
        let (signer, verifier) = HybridSigner::generate().unwrap();
        let message = b"test";

        let sig = signer.sign(message).unwrap();

        // Both component signatures should individually verify
        assert!(verifier
            .dilithium_vk()
            .verify(message, sig.dilithium_sig())
            .is_ok());
        assert!(verifier
            .ed25519_vk()
            .verify(message, sig.ed25519_sig())
            .is_ok());
    }
}
