//! Secure random number generation.
//!
//! Uses OS-provided randomness only (`OsRng`).

use rand::{rngs::OsRng, RngCore};
use teras_core::error::{TerasError, TerasResult};
use teras_lindung::Secret;

/// Fill a buffer with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns `TerasError::RandomGenerationFailed` if the OS RNG fails.
pub fn fill_random(buffer: &mut [u8]) -> TerasResult<()> {
    OsRng
        .try_fill_bytes(buffer)
        .map_err(|_| TerasError::RandomGenerationFailed)
}

/// Generate a random byte array.
///
/// # Errors
///
/// Returns `TerasError::RandomGenerationFailed` if the OS RNG fails.
pub fn random_bytes<const N: usize>() -> TerasResult<[u8; N]> {
    let mut buffer = [0u8; N];
    fill_random(&mut buffer)?;
    Ok(buffer)
}

/// Generate a secret random byte array.
///
/// The result is wrapped in `Secret<T>` for automatic zeroization.
///
/// # Errors
///
/// Returns `TerasError::RandomGenerationFailed` if the OS RNG fails.
pub fn secret_random_bytes<const N: usize>() -> TerasResult<Secret<[u8; N]>> {
    let bytes = random_bytes::<N>()?;
    Ok(Secret::new(bytes))
}

/// Generate a random 256-bit key.
///
/// # Errors
///
/// Returns error if random generation fails.
pub fn random_key_256() -> TerasResult<Secret<[u8; 32]>> {
    secret_random_bytes::<32>()
}

/// Generate a random 128-bit nonce.
///
/// # Errors
///
/// Returns error if random generation fails.
pub fn random_nonce_128() -> TerasResult<[u8; 16]> {
    random_bytes::<16>()
}

/// Generate a random 96-bit nonce (for AES-GCM).
///
/// # Errors
///
/// Returns error if random generation fails.
pub fn random_nonce_96() -> TerasResult<[u8; 12]> {
    random_bytes::<12>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        fill_random(&mut buf1).unwrap();
        fill_random(&mut buf2).unwrap();

        // Extremely unlikely to be equal if random
        assert_ne!(buf1, buf2);

        // Extremely unlikely to be all zeros
        assert!(!buf1.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_bytes() {
        let bytes1: [u8; 32] = random_bytes().unwrap();
        let bytes2: [u8; 32] = random_bytes().unwrap();

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_secret_random_bytes() {
        let secret = secret_random_bytes::<32>().unwrap();
        let exposed = secret.expose();

        // Should be 32 bytes
        assert_eq!(exposed.len(), 32);

        // Extremely unlikely to be all zeros
        assert!(!exposed.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_nonce_sizes() {
        let nonce_96 = random_nonce_96().unwrap();
        assert_eq!(nonce_96.len(), 12);

        let nonce_128 = random_nonce_128().unwrap();
        assert_eq!(nonce_128.len(), 16);
    }
}
