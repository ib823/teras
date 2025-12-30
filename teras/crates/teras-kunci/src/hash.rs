//! Cryptographic hash functions.
//!
//! Provides SHA-256, SHA3-256, and BLAKE3.

use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// Hash algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (FIPS 180-4)
    Sha256,
    /// SHA3-256 (FIPS 202)
    Sha3_256,
    /// BLAKE3
    Blake3,
}

/// Compute hash of data with specified algorithm.
#[must_use]
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(data);
            hasher.finalize().as_bytes().to_vec()
        }
    }
}

/// Compute SHA-256 hash (convenience function).
///
/// # Example
///
/// ```
/// use teras_kunci::sha256;
///
/// let hash = sha256(b"hello");
/// assert_eq!(hash.len(), 32);
/// ```
#[inline]
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA3-256 hash (convenience function).
///
/// # Example
///
/// ```
/// use teras_kunci::sha3_256;
///
/// let hash = sha3_256(b"hello");
/// assert_eq!(hash.len(), 32);
/// ```
#[inline]
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute BLAKE3 hash (convenience function).
///
/// # Example
///
/// ```
/// use teras_kunci::blake3_hash;
///
/// let hash = blake3_hash(b"hello");
/// assert_eq!(hash.len(), 32);
/// ```
#[inline]
#[must_use]
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // MANDATORY TEST VECTORS FROM PART X - BUILD FAILS IF THESE DON'T MATCH

    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha3_256_empty() {
        let result = sha3_256(b"");
        let expected =
            hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
                .unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha3_256_abc() {
        let result = sha3_256(b"abc");
        // SHA3-256("abc") from NIST examples
        let expected =
            hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
                .unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_blake3_empty() {
        let result = blake3_hash(b"");
        // BLAKE3 test vector
        let expected =
            hex::decode("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
                .unwrap();
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hash_algorithm_enum() {
        let data = b"test";

        let h1 = hash(HashAlgorithm::Sha256, data);
        let h2 = sha256(data);
        assert_eq!(h1, h2.to_vec());

        let h3 = hash(HashAlgorithm::Sha3_256, data);
        let h4 = sha3_256(data);
        assert_eq!(h3, h4.to_vec());

        let h5 = hash(HashAlgorithm::Blake3, data);
        let h6 = blake3_hash(data);
        assert_eq!(h5, h6.to_vec());
    }
}
