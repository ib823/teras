//! Ed25519 Digital Signatures.
//!
//! Classical elliptic curve signatures.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use teras_core::error::{TerasError, TerasResult};
use teras_lindung::Secret;

/// Ed25519 secret key size.
pub const ED25519_SK_SIZE: usize = 32;
/// Ed25519 verifying key size.
pub const ED25519_VK_SIZE: usize = 32;
/// Ed25519 signature size.
pub const ED25519_SIG_SIZE: usize = 64;

/// Ed25519 signing key (private).
pub struct Ed25519Signer {
    sk: Secret<[u8; ED25519_SK_SIZE]>,
}

/// Ed25519 verifying key (public).
#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    vk: [u8; ED25519_VK_SIZE],
}

/// Ed25519 signature.
#[derive(Clone)]
pub struct Ed25519Signature {
    sig: [u8; ED25519_SIG_SIZE],
}

impl Ed25519Signer {
    /// Generate new Ed25519 keypair.
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails.
    pub fn generate() -> TerasResult<(Self, Ed25519VerifyingKey)> {
        // Generate 32 random bytes for the secret key
        let mut sk_bytes = [0u8; ED25519_SK_SIZE];
        OsRng.fill_bytes(&mut sk_bytes);

        let sk = SigningKey::from_bytes(&sk_bytes);
        let vk = sk.verifying_key();

        Ok((
            Self {
                sk: Secret::new(sk.to_bytes()),
            },
            Ed25519VerifyingKey { vk: vk.to_bytes() },
        ))
    }

    /// Sign a message.
    ///
    /// # Errors
    ///
    /// This function does not return errors for Ed25519.
    pub fn sign(&self, message: &[u8]) -> TerasResult<Ed25519Signature> {
        let sk = SigningKey::from_bytes(self.sk.expose());
        let sig = sk.sign(message);

        Ok(Ed25519Signature {
            sig: sig.to_bytes(),
        })
    }
}

impl Ed25519VerifyingKey {
    /// Verify a signature.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` if verification fails.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> TerasResult<()> {
        let vk = VerifyingKey::from_bytes(&self.vk).map_err(|_| TerasError::InvalidSignature)?;

        let sig = Signature::from_bytes(&signature.sig);

        vk.verify(message, &sig)
            .map_err(|_| TerasError::InvalidSignature)
    }

    /// Get raw verifying key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_VK_SIZE] {
        &self.vk
    }
}

impl Ed25519Signature {
    /// Get raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_SIG_SIZE] {
        &self.sig
    }

    /// Create signature from raw bytes.
    ///
    /// Returns None if the slice length doesn't match.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ED25519_SIG_SIZE {
            return None;
        }
        let mut sig = [0u8; ED25519_SIG_SIZE];
        sig.copy_from_slice(bytes);
        Some(Self { sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let (signer, verifier) = Ed25519Signer::generate().unwrap();
        let message = b"Hello, World!";

        let sig = signer.sign(message).unwrap();
        assert!(verifier.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_ed25519_wrong_message_fails() {
        let (signer, verifier) = Ed25519Signer::generate().unwrap();

        let sig = signer.sign(b"message1").unwrap();
        assert!(verifier.verify(b"message2", &sig).is_err());
    }

    #[test]
    fn test_ed25519_wrong_key_fails() {
        let (signer1, _verifier1) = Ed25519Signer::generate().unwrap();
        let (_signer2, verifier2) = Ed25519Signer::generate().unwrap();

        let message = b"test";
        let sig = signer1.sign(message).unwrap();

        assert!(verifier2.verify(message, &sig).is_err());
    }
}
