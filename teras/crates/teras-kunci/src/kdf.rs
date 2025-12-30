//! Key derivation functions.
//!
//! Provides HKDF (for key derivation) and Argon2id (for passwords).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::Sha3_256;
use teras_core::error::{TerasError, TerasResult};
use teras_lindung::Secret;

/// HKDF algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfAlgorithm {
    /// HKDF with SHA-256
    Sha256,
    /// HKDF with SHA3-256
    Sha3_256,
}

/// Derive a key using HKDF.
///
/// # Arguments
///
/// * `algorithm` - Hash algorithm to use
/// * `ikm` - Input key material (the secret)
/// * `salt` - Optional salt (can be empty)
/// * `info` - Context/application-specific info
/// * `output_len` - Desired output length in bytes
///
/// # Errors
///
/// Returns `TerasError::KeyDerivationFailed` if derivation fails.
pub fn hkdf_derive(
    algorithm: HkdfAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> TerasResult<Vec<u8>> {
    let mut output = vec![0u8; output_len];

    match algorithm {
        HkdfAlgorithm::Sha256 => {
            let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
            hk.expand(info, &mut output)
                .map_err(|_| TerasError::KeyDerivationFailed)?;
        }
        HkdfAlgorithm::Sha3_256 => {
            let hk = Hkdf::<Sha3_256>::new(Some(salt), ikm);
            hk.expand(info, &mut output)
                .map_err(|_| TerasError::KeyDerivationFailed)?;
        }
    }

    Ok(output)
}

/// Derive a 256-bit key using HKDF-SHA256.
///
/// Convenience function for the most common case.
///
/// # Errors
///
/// Returns error if key derivation fails.
pub fn hkdf_sha256_derive_key(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> TerasResult<Secret<[u8; 32]>> {
    let output = hkdf_derive(HkdfAlgorithm::Sha256, ikm, salt, info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&output);
    Ok(Secret::new(key))
}

/// Argon2id parameters per architecture spec.
///
/// MINIMUM values from LAW 2:
/// - `time_cost`: 3
/// - `memory_cost`: 65536 (64 MB)
/// - `parallelism`: 4
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Memory cost in KB
    pub memory_cost: u32,
    /// Parallelism (threads)
    pub parallelism: u32,
    /// Output length in bytes
    pub output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            time_cost: 3,       // Minimum per spec
            memory_cost: 65536, // 64 MB, minimum per spec
            parallelism: 4,     // Minimum per spec
            output_len: 32,
        }
    }
}

/// Derive a key from a password using Argon2id.
///
/// This is for PASSWORD-BASED key derivation ONLY.
/// For non-password key derivation, use HKDF.
///
/// # Arguments
///
/// * `password` - The password bytes
/// * `salt` - Random salt (MUST be at least 16 bytes)
/// * `params` - Argon2 parameters
///
/// # Errors
///
/// Returns `TerasError::KeyDerivationFailed` if derivation fails.
///
/// # Panics
///
/// Panics if salt is less than 16 bytes or params don't meet minimums.
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> TerasResult<Secret<Vec<u8>>> {
    assert!(salt.len() >= 16, "Salt must be at least 16 bytes");
    assert!(
        params.time_cost >= 3,
        "time_cost must be at least 3 (LAW 2)"
    );
    assert!(
        params.memory_cost >= 65536,
        "memory_cost must be at least 65536 KB (LAW 2)"
    );
    assert!(
        params.parallelism >= 4,
        "parallelism must be at least 4 (LAW 2)"
    );

    let argon_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|_| TerasError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut output = vec![0u8; params.output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| TerasError::KeyDerivationFailed)?;

    Ok(Secret::new(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let key = hkdf_sha256_derive_key(ikm, salt, info).unwrap();
        assert_eq!(key.expose().len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"test";
        let salt = b"salt";
        let info = b"info";

        let key1 = hkdf_sha256_derive_key(ikm, salt, info).unwrap();
        let key2 = hkdf_sha256_derive_key(ikm, salt, info).unwrap();

        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_hkdf_different_info() {
        let ikm = b"test";
        let salt = b"salt";

        let key1 = hkdf_sha256_derive_key(ikm, salt, b"info1").unwrap();
        let key2 = hkdf_sha256_derive_key(ikm, salt, b"info2").unwrap();

        assert_ne!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_argon2id_basic() {
        let password = b"password123";
        let salt = b"1234567890123456"; // 16 bytes
        let params = Argon2Params::default();

        let key = argon2id_derive(password, salt, &params).unwrap();
        assert_eq!(key.expose().len(), 32);
    }

    #[test]
    fn test_argon2id_deterministic() {
        let password = b"password";
        let salt = b"1234567890123456";
        let params = Argon2Params::default();

        let key1 = argon2id_derive(password, salt, &params).unwrap();
        let key2 = argon2id_derive(password, salt, &params).unwrap();

        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    #[should_panic(expected = "Salt must be at least 16 bytes")]
    fn test_argon2id_short_salt_panics() {
        let password = b"password";
        let salt = b"short";
        let params = Argon2Params::default();

        let _ = argon2id_derive(password, salt, &params);
    }

    #[test]
    fn test_argon2_default_params_meet_minimum() {
        let params = Argon2Params::default();
        assert!(params.time_cost >= 3);
        assert!(params.memory_cost >= 65536);
        assert!(params.parallelism >= 4);
    }
}
