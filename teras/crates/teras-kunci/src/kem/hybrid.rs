//! Hybrid KEM: Kyber-768 (ML-KEM equivalent) + X25519
//!
//! MANDATORY per Decision 4. Both algorithms must succeed.

use super::mlkem::{Kyber768, Kyber768Ciphertext, Kyber768EncapsulationKey, KYBER768_SS_SIZE};
use super::x25519_kem::{X25519Ciphertext, X25519Kem, X25519PublicKey, X25519_SS_SIZE};
use crate::kdf::hkdf_sha256_derive_key;
use teras_core::error::{TerasError, TerasResult};
use teras_lindung::Secret;

/// Combined shared secret size (before KDF).
pub const HYBRID_RAW_SS_SIZE: usize = KYBER768_SS_SIZE + X25519_SS_SIZE; // 64 bytes

/// Final derived key size.
pub const HYBRID_DERIVED_KEY_SIZE: usize = 32;

/// Hybrid KEM combining Kyber-768 (ML-KEM equivalent) and X25519.
///
/// Both algorithms must succeed for encapsulation/decapsulation.
/// If either fails, the operation fails.
///
/// This provides security if EITHER:
/// - Classical crypto (X25519) remains secure, OR
/// - Post-quantum crypto (Kyber) remains secure
pub struct HybridKem {
    kyber: Kyber768,
    x25519: X25519Kem,
}

/// Hybrid encapsulation key (public).
#[derive(Clone)]
pub struct HybridEncapsulationKey {
    kyber_ek: Kyber768EncapsulationKey,
    x25519_pk: X25519PublicKey,
}

/// Hybrid ciphertext.
#[derive(Clone)]
pub struct HybridCiphertext {
    kyber_ct: Kyber768Ciphertext,
    x25519_ct: X25519Ciphertext,
}

impl HybridKem {
    /// Generate new hybrid keypair.
    ///
    /// Generates both Kyber-768 and X25519 keypairs.
    ///
    /// # Errors
    ///
    /// Returns error if either key generation fails.
    pub fn generate() -> TerasResult<(Self, HybridEncapsulationKey)> {
        let (kyber, kyber_ek) = Kyber768::generate()?;
        let (x25519, x25519_pk) = X25519Kem::generate()?;

        Ok((
            Self { kyber, x25519 },
            HybridEncapsulationKey {
                kyber_ek,
                x25519_pk,
            },
        ))
    }

    /// Decapsulate to get shared secret.
    ///
    /// Both Kyber and X25519 must succeed. The shared secrets
    /// are concatenated and passed through HKDF.
    ///
    /// # Errors
    ///
    /// Returns `HybridCryptoFailed` if either decapsulation fails.
    pub fn decapsulate(
        &self,
        ct: &HybridCiphertext,
    ) -> TerasResult<Secret<[u8; HYBRID_DERIVED_KEY_SIZE]>> {
        // Decapsulate both
        let kyber_ss =
            self.kyber
                .decapsulate(&ct.kyber_ct)
                .map_err(|_| TerasError::HybridCryptoFailed {
                    classical_ok: true,
                    pq_ok: false,
                })?;

        let x25519_ss =
            self.x25519
                .decapsulate(&ct.x25519_ct)
                .map_err(|_| TerasError::HybridCryptoFailed {
                    classical_ok: false,
                    pq_ok: true,
                })?;

        // Combine shared secrets
        let mut combined = [0u8; HYBRID_RAW_SS_SIZE];
        combined[..KYBER768_SS_SIZE].copy_from_slice(kyber_ss.expose());
        combined[KYBER768_SS_SIZE..].copy_from_slice(x25519_ss.expose());

        // Derive final key using HKDF
        let derived = hkdf_sha256_derive_key(&combined, b"TERAS-HYBRID-KEM-v1", b"shared-secret")?;

        // Convert to fixed-size array
        let mut result = [0u8; HYBRID_DERIVED_KEY_SIZE];
        result.copy_from_slice(derived.expose());

        Ok(Secret::new(result))
    }
}

impl HybridEncapsulationKey {
    /// Encapsulate to create ciphertext and shared secret.
    ///
    /// Both Kyber and X25519 encapsulation must succeed.
    ///
    /// # Errors
    ///
    /// Returns `HybridCryptoFailed` if either encapsulation fails.
    pub fn encapsulate(
        &self,
    ) -> TerasResult<(HybridCiphertext, Secret<[u8; HYBRID_DERIVED_KEY_SIZE]>)> {
        // Encapsulate with both
        let (kyber_ct, kyber_ss) =
            self.kyber_ek
                .encapsulate()
                .map_err(|_| TerasError::HybridCryptoFailed {
                    classical_ok: true,
                    pq_ok: false,
                })?;

        let (x25519_ct, x25519_ss) =
            self.x25519_pk
                .encapsulate()
                .map_err(|_| TerasError::HybridCryptoFailed {
                    classical_ok: false,
                    pq_ok: true,
                })?;

        let ct = HybridCiphertext {
            kyber_ct,
            x25519_ct,
        };

        // Combine shared secrets
        let mut combined = [0u8; HYBRID_RAW_SS_SIZE];
        combined[..KYBER768_SS_SIZE].copy_from_slice(kyber_ss.expose());
        combined[KYBER768_SS_SIZE..].copy_from_slice(x25519_ss.expose());

        // Derive final key using HKDF
        let derived = hkdf_sha256_derive_key(&combined, b"TERAS-HYBRID-KEM-v1", b"shared-secret")?;

        // Convert to fixed-size array
        let mut result = [0u8; HYBRID_DERIVED_KEY_SIZE];
        result.copy_from_slice(derived.expose());

        Ok((ct, Secret::new(result)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let (dk, ek) = HybridKem::generate().unwrap();
        let (ct, ss1) = ek.encapsulate().unwrap();
        let ss2 = dk.decapsulate(&ct).unwrap();

        assert_eq!(ss1.expose(), ss2.expose());
    }

    #[test]
    fn test_hybrid_kem_derived_key_size() {
        let (_, ek) = HybridKem::generate().unwrap();
        let (_, ss) = ek.encapsulate().unwrap();

        assert_eq!(ss.expose().len(), HYBRID_DERIVED_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_kem_different_keypairs_different_secrets() {
        let (dk1, ek1) = HybridKem::generate().unwrap();
        let (dk2, ek2) = HybridKem::generate().unwrap();

        let (ct1, ss1_enc) = ek1.encapsulate().unwrap();
        let (ct2, ss2_enc) = ek2.encapsulate().unwrap();

        let ss1_dec = dk1.decapsulate(&ct1).unwrap();
        let ss2_dec = dk2.decapsulate(&ct2).unwrap();

        assert_eq!(ss1_enc.expose(), ss1_dec.expose());
        assert_eq!(ss2_enc.expose(), ss2_dec.expose());
        assert_ne!(ss1_enc.expose(), ss2_enc.expose());
    }

    #[test]
    fn test_hybrid_kem_cross_decapsulation_produces_different_result() {
        let (dk1, _ek1) = HybridKem::generate().unwrap();
        let (_dk2, ek2) = HybridKem::generate().unwrap();

        let (ct2, ss2) = ek2.encapsulate().unwrap();

        // Decapsulating with wrong key should produce different result
        // (Note: X25519 won't fail, just produce wrong result)
        let ss_wrong = dk1.decapsulate(&ct2).unwrap();

        // The secrets should be different
        assert_ne!(ss_wrong.expose(), ss2.expose());
    }
}
