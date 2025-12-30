//! Symmetric encryption: AES-256-GCM and ChaCha20-Poly1305.
//!
//! Both ciphers provide authenticated encryption (AEAD).

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use teras_core::error::{TerasError, TerasResult};
use teras_lindung::Secret;

/// Trait for symmetric AEAD ciphers.
pub trait SymmetricCipher {
    /// Encrypt plaintext with associated data.
    ///
    /// # Errors
    ///
    /// Returns error if encryption fails.
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> TerasResult<Vec<u8>>;

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns error if decryption fails (including auth failure).
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> TerasResult<Vec<u8>>;
}

/// AES-256-GCM cipher.
///
/// Requires:
/// - 256-bit key (32 bytes)
/// - 96-bit nonce (12 bytes)
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// Create new AES-256-GCM cipher from key.
    ///
    /// # Errors
    ///
    /// Returns error if key is not 32 bytes.
    pub fn new(key: &Secret<[u8; 32]>) -> TerasResult<Self> {
        let cipher =
            Aes256Gcm::new_from_slice(key.expose()).map_err(|_| TerasError::InvalidKeyLength {
                expected: 32,
                actual: 0,
            })?;
        Ok(Self { cipher })
    }
}

impl SymmetricCipher for Aes256GcmCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> TerasResult<Vec<u8>> {
        use aes_gcm::aead::Payload;

        if nonce.len() != 12 {
            return Err(TerasError::InvalidFormat(format!(
                "AES-GCM nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| TerasError::DecryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> TerasResult<Vec<u8>> {
        use aes_gcm::aead::Payload;

        if nonce.len() != 12 {
            return Err(TerasError::InvalidFormat(format!(
                "AES-GCM nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| TerasError::DecryptionFailed)
    }
}

/// ChaCha20-Poly1305 cipher.
///
/// Requires:
/// - 256-bit key (32 bytes)
/// - 96-bit nonce (12 bytes)
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create new ChaCha20-Poly1305 cipher from key.
    ///
    /// # Errors
    ///
    /// Returns error if key length is invalid.
    pub fn new(key: &Secret<[u8; 32]>) -> TerasResult<Self> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| {
            TerasError::InvalidKeyLength {
                expected: 32,
                actual: 0,
            }
        })?;
        Ok(Self { cipher })
    }
}

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> TerasResult<Vec<u8>> {
        use chacha20poly1305::aead::Payload;

        if nonce.len() != 12 {
            return Err(TerasError::InvalidFormat(format!(
                "ChaCha20-Poly1305 nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| TerasError::DecryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> TerasResult<Vec<u8>> {
        use chacha20poly1305::aead::Payload;

        if nonce.len() != 12 {
            return Err(TerasError::InvalidFormat(format!(
                "ChaCha20-Poly1305 nonce must be 12 bytes, got {}",
                nonce.len()
            )));
        }

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| TerasError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::random_nonce_96;

    fn test_key() -> Secret<[u8; 32]> {
        Secret::new([0x42u8; 32])
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = test_key();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce = random_nonce_96().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let key = test_key();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce = random_nonce_96().unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(&nonce, plaintext, b"aad1").unwrap();
        let result = cipher.decrypt(&nonce, &ciphertext, b"aad2");

        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_nonce_fails() {
        let key = test_key();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let nonce1 = random_nonce_96().unwrap();
        let nonce2 = random_nonce_96().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"aad";

        let ciphertext = cipher.encrypt(&nonce1, plaintext, aad).unwrap();
        let result = cipher.decrypt(&nonce2, &ciphertext, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = test_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let nonce = random_nonce_96().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_wrong_aad_fails() {
        let key = test_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let nonce = random_nonce_96().unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = cipher.encrypt(&nonce, plaintext, b"aad1").unwrap();
        let result = cipher.decrypt(&nonce, &ciphertext, b"aad2");

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = test_key();
        let cipher = Aes256GcmCipher::new(&key).unwrap();

        let bad_nonce = [0u8; 8]; // Wrong length
        let result = cipher.encrypt(&bad_nonce, b"test", b"");

        assert!(result.is_err());
    }
}
