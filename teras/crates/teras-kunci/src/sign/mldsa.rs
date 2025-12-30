//! Dilithium3 Digital Signatures (ML-DSA-65 equivalent).
//!
//! NIST Level 3 post-quantum security.
//! Uses pqcrypto-dilithium which implements Dilithium (precursor to ML-DSA).

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PkTrait, SecretKey as SkTrait};
use teras_core::error::{TerasError, TerasResult};
use teras_lindung::Secret;

// Size constants - these are reference values for buffer sizing
// The actual sizes may vary slightly between implementations
#[allow(dead_code)]
const DILITHIUM3_SK_SIZE: usize = 4016;
#[allow(dead_code)]
const DILITHIUM3_VK_SIZE: usize = 1952;
#[allow(dead_code)]
const DILITHIUM3_SIG_SIZE: usize = 3293;

/// Dilithium3 signing key (private).
pub struct Dilithium3Signer {
    sk: Secret<Vec<u8>>,
}

/// Dilithium3 verifying key (public).
#[derive(Clone)]
pub struct Dilithium3VerifyingKey {
    vk: Vec<u8>,
}

/// Dilithium3 signature.
#[derive(Clone)]
pub struct Dilithium3Signature {
    sig: Vec<u8>,
}

impl Dilithium3Signer {
    /// Generate new Dilithium3 keypair.
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails.
    pub fn generate() -> TerasResult<(Self, Dilithium3VerifyingKey)> {
        let (pk, sk) = dilithium3::keypair();

        Ok((
            Self {
                sk: Secret::new(sk.as_bytes().to_vec()),
            },
            Dilithium3VerifyingKey {
                vk: pk.as_bytes().to_vec(),
            },
        ))
    }

    /// Sign a message.
    ///
    /// # Errors
    ///
    /// Returns error if signing fails.
    pub fn sign(&self, message: &[u8]) -> TerasResult<Dilithium3Signature> {
        let sk = dilithium3::SecretKey::from_bytes(self.sk.expose())
            .map_err(|_| TerasError::InvalidSignature)?;

        let sig = dilithium3::detached_sign(message, &sk);

        Ok(Dilithium3Signature {
            sig: sig.as_bytes().to_vec(),
        })
    }
}

impl Dilithium3VerifyingKey {
    /// Verify a signature.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if verification fails.
    pub fn verify(&self, message: &[u8], signature: &Dilithium3Signature) -> TerasResult<()> {
        let pk = dilithium3::PublicKey::from_bytes(&self.vk)
            .map_err(|_| TerasError::InvalidSignature)?;

        let sig = dilithium3::DetachedSignature::from_bytes(&signature.sig)
            .map_err(|_| TerasError::InvalidSignature)?;

        dilithium3::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| TerasError::InvalidSignature)
    }

    /// Get raw verifying key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.vk
    }
}

impl Dilithium3Signature {
    /// Get raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.sig
    }

    /// Create signature from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            sig: bytes.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium3_sign_verify() {
        let (signer, verifier) = Dilithium3Signer::generate().unwrap();
        let message = b"Hello, World!";

        let sig = signer.sign(message).unwrap();
        assert!(verifier.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_dilithium3_wrong_message_fails() {
        let (signer, verifier) = Dilithium3Signer::generate().unwrap();

        let sig = signer.sign(b"message1").unwrap();
        assert!(verifier.verify(b"message2", &sig).is_err());
    }

    #[test]
    fn test_dilithium3_wrong_key_fails() {
        let (signer1, _verifier1) = Dilithium3Signer::generate().unwrap();
        let (_signer2, verifier2) = Dilithium3Signer::generate().unwrap();

        let message = b"test";
        let sig = signer1.sign(message).unwrap();

        assert!(verifier2.verify(message, &sig).is_err());
    }
}
