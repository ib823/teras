//! Kyber-768 Key Encapsulation Mechanism (ML-KEM-768 equivalent).
//!
//! NIST Level 3 post-quantum security.
//! Uses pqcrypto-kyber which implements Kyber (precursor to ML-KEM).

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, PublicKey, SecretKey, SharedSecret};
use teras_core::error::{TerasError, TerasResult};
use teras_lindung::Secret;

/// Kyber-768 secret key size.
pub const KYBER768_SK_SIZE: usize = 2400;
/// Kyber-768 public key size.
pub const KYBER768_PK_SIZE: usize = 1184;
/// Kyber-768 ciphertext size.
pub const KYBER768_CT_SIZE: usize = 1088;
/// Kyber-768 shared secret size.
pub const KYBER768_SS_SIZE: usize = 32;

/// Kyber-768 decapsulation key (private).
pub struct Kyber768 {
    sk: Secret<[u8; KYBER768_SK_SIZE]>,
}

/// Kyber-768 encapsulation key (public).
#[derive(Clone)]
pub struct Kyber768EncapsulationKey {
    pk: [u8; KYBER768_PK_SIZE],
}

/// Kyber-768 ciphertext.
#[derive(Clone)]
pub struct Kyber768Ciphertext {
    ct: [u8; KYBER768_CT_SIZE],
}

impl Kyber768 {
    /// Generate new Kyber-768 keypair.
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails.
    pub fn generate() -> TerasResult<(Self, Kyber768EncapsulationKey)> {
        let (pk, sk) = kyber768::keypair();

        let sk_bytes: [u8; KYBER768_SK_SIZE] =
            sk.as_bytes()
                .try_into()
                .map_err(|_| TerasError::InvalidKeyLength {
                    expected: KYBER768_SK_SIZE,
                    actual: sk.as_bytes().len(),
                })?;

        let pk_bytes: [u8; KYBER768_PK_SIZE] =
            pk.as_bytes()
                .try_into()
                .map_err(|_| TerasError::InvalidKeyLength {
                    expected: KYBER768_PK_SIZE,
                    actual: pk.as_bytes().len(),
                })?;

        Ok((
            Self {
                sk: Secret::new(sk_bytes),
            },
            Kyber768EncapsulationKey { pk: pk_bytes },
        ))
    }

    /// Decapsulate to recover shared secret.
    ///
    /// # Errors
    ///
    /// Returns error if decapsulation fails.
    pub fn decapsulate(
        &self,
        ct: &Kyber768Ciphertext,
    ) -> TerasResult<Secret<[u8; KYBER768_SS_SIZE]>> {
        let sk = kyber768::SecretKey::from_bytes(self.sk.expose())
            .map_err(|_| TerasError::DecryptionFailed)?;
        let ciphertext =
            kyber768::Ciphertext::from_bytes(&ct.ct).map_err(|_| TerasError::DecryptionFailed)?;

        let ss = kyber768::decapsulate(&ciphertext, &sk);

        let ss_bytes: [u8; KYBER768_SS_SIZE] = ss
            .as_bytes()
            .try_into()
            .map_err(|_| TerasError::DecryptionFailed)?;

        Ok(Secret::new(ss_bytes))
    }
}

impl Kyber768EncapsulationKey {
    /// Encapsulate to create ciphertext and shared secret.
    ///
    /// # Errors
    ///
    /// Returns error if encapsulation fails.
    pub fn encapsulate(&self) -> TerasResult<(Kyber768Ciphertext, Secret<[u8; KYBER768_SS_SIZE]>)> {
        let pk = kyber768::PublicKey::from_bytes(&self.pk)
            .map_err(|_| TerasError::KeyDerivationFailed)?;

        let (ss, ct) = kyber768::encapsulate(&pk);

        let ct_bytes: [u8; KYBER768_CT_SIZE] = ct
            .as_bytes()
            .try_into()
            .map_err(|_| TerasError::KeyDerivationFailed)?;

        let ss_bytes: [u8; KYBER768_SS_SIZE] = ss
            .as_bytes()
            .try_into()
            .map_err(|_| TerasError::KeyDerivationFailed)?;

        Ok((Kyber768Ciphertext { ct: ct_bytes }, Secret::new(ss_bytes)))
    }

    /// Get the raw public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KYBER768_PK_SIZE] {
        &self.pk
    }
}

impl Kyber768Ciphertext {
    /// Get the raw ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KYBER768_CT_SIZE] {
        &self.ct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber768_roundtrip() {
        let (sk, pk) = Kyber768::generate().unwrap();
        let (ct, ss1) = pk.encapsulate().unwrap();
        let ss2 = sk.decapsulate(&ct).unwrap();

        assert_eq!(ss1.expose(), ss2.expose());
    }

    #[test]
    fn test_kyber768_key_sizes() {
        let (sk, pk) = Kyber768::generate().unwrap();

        assert_eq!(sk.sk.expose().len(), KYBER768_SK_SIZE);
        assert_eq!(pk.as_bytes().len(), KYBER768_PK_SIZE);
    }

    #[test]
    fn test_kyber768_ciphertext_size() {
        let (_, pk) = Kyber768::generate().unwrap();
        let (ct, _) = pk.encapsulate().unwrap();

        assert_eq!(ct.as_bytes().len(), KYBER768_CT_SIZE);
    }

    #[test]
    fn test_kyber768_different_keypairs_different_secrets() {
        let (sk1, pk1) = Kyber768::generate().unwrap();
        let (sk2, pk2) = Kyber768::generate().unwrap();

        let (ct1, ss1_enc) = pk1.encapsulate().unwrap();
        let (ct2, ss2_enc) = pk2.encapsulate().unwrap();

        let ss1_dec = sk1.decapsulate(&ct1).unwrap();
        let ss2_dec = sk2.decapsulate(&ct2).unwrap();

        // Each pair should work
        assert_eq!(ss1_enc.expose(), ss1_dec.expose());
        assert_eq!(ss2_enc.expose(), ss2_dec.expose());

        // But different pairs should have different secrets
        assert_ne!(ss1_enc.expose(), ss2_enc.expose());
    }
}
