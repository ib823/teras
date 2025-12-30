//! X25519 Key Exchange (used as KEM).
//!
//! Classical elliptic curve Diffie-Hellman.

use rand::{rngs::OsRng, RngCore};
use teras_core::error::TerasResult;
use teras_lindung::Secret;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// X25519 secret key size.
pub const X25519_SK_SIZE: usize = 32;
/// X25519 public key size.
pub const X25519_PK_SIZE: usize = 32;
/// X25519 shared secret size.
pub const X25519_SS_SIZE: usize = 32;

/// X25519 static key (long-term private key).
pub struct X25519Kem {
    sk: Secret<[u8; X25519_SK_SIZE]>,
}

/// X25519 public key.
#[derive(Clone)]
pub struct X25519PublicKey {
    pk: [u8; X25519_PK_SIZE],
}

/// X25519 "ciphertext" (ephemeral public key).
#[derive(Clone)]
pub struct X25519Ciphertext {
    ephemeral_pk: [u8; X25519_PK_SIZE],
}

impl X25519Kem {
    /// Generate new X25519 keypair.
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails.
    pub fn generate() -> TerasResult<(Self, X25519PublicKey)> {
        // Generate random 32-byte secret key
        let mut sk_bytes = [0u8; X25519_SK_SIZE];
        OsRng.fill_bytes(&mut sk_bytes);

        // Compute public key: sk * basepoint
        let pk_bytes = x25519(sk_bytes, X25519_BASEPOINT_BYTES);

        Ok((
            Self {
                sk: Secret::new(sk_bytes),
            },
            X25519PublicKey { pk: pk_bytes },
        ))
    }

    /// Decapsulate (perform DH with ephemeral public key).
    ///
    /// # Errors
    ///
    /// This function does not return errors as X25519 DH always succeeds.
    pub fn decapsulate(&self, ct: &X25519Ciphertext) -> TerasResult<Secret<[u8; X25519_SS_SIZE]>> {
        // Compute shared secret: sk * their_pk
        let ss = x25519(*self.sk.expose(), ct.ephemeral_pk);
        Ok(Secret::new(ss))
    }
}

impl X25519PublicKey {
    /// Encapsulate (generate ephemeral key and perform DH).
    ///
    /// # Errors
    ///
    /// This function does not return errors as X25519 operations always succeed.
    #[allow(clippy::similar_names)]
    pub fn encapsulate(&self) -> TerasResult<(X25519Ciphertext, Secret<[u8; X25519_SS_SIZE]>)> {
        // Generate ephemeral secret key
        let mut eph_secret = [0u8; X25519_SK_SIZE];
        OsRng.fill_bytes(&mut eph_secret);

        // Compute ephemeral public key
        let eph_public = x25519(eph_secret, X25519_BASEPOINT_BYTES);

        // Compute shared secret: eph_secret * their_pk
        let ss = x25519(eph_secret, self.pk);

        Ok((
            X25519Ciphertext {
                ephemeral_pk: eph_public,
            },
            Secret::new(ss),
        ))
    }

    /// Get the raw public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_PK_SIZE] {
        &self.pk
    }
}

impl X25519Ciphertext {
    /// Get the raw ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_PK_SIZE] {
        &self.ephemeral_pk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_roundtrip() {
        let (sk, pk) = X25519Kem::generate().unwrap();
        let (ct, ss1) = pk.encapsulate().unwrap();
        let ss2 = sk.decapsulate(&ct).unwrap();

        assert_eq!(ss1.expose(), ss2.expose());
    }

    #[test]
    fn test_x25519_key_sizes() {
        let (sk, pk) = X25519Kem::generate().unwrap();

        assert_eq!(sk.sk.expose().len(), X25519_SK_SIZE);
        assert_eq!(pk.as_bytes().len(), X25519_PK_SIZE);
    }

    #[test]
    fn test_x25519_different_keypairs() {
        let (sk1, pk1) = X25519Kem::generate().unwrap();
        let (sk2, pk2) = X25519Kem::generate().unwrap();

        let (ct1, ss1_enc) = pk1.encapsulate().unwrap();
        let (ct2, ss2_enc) = pk2.encapsulate().unwrap();

        let ss1_dec = sk1.decapsulate(&ct1).unwrap();
        let ss2_dec = sk2.decapsulate(&ct2).unwrap();

        assert_eq!(ss1_enc.expose(), ss1_dec.expose());
        assert_eq!(ss2_enc.expose(), ss2_dec.expose());
        assert_ne!(ss1_enc.expose(), ss2_enc.expose());
    }
}
