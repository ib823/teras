//! AES-256-GCM encryption for at-rest data protection.
//!
//! Provides encryption/decryption of sensitive data stored on disk.
//! Keys are encrypted at rest and only decrypted in memory when needed.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use teras_core::error::{TerasError, TerasResult};
use zeroize::Zeroize;

/// AES-256-GCM key size in bytes.
pub const KEY_SIZE: usize = 32;

/// AES-256-GCM nonce size in bytes.
pub const NONCE_SIZE: usize = 12;

/// AES-256-GCM tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Magic bytes for encrypted file format.
const ENCRYPTED_MAGIC: &[u8] = b"TERASEN1";

/// Encrypted data format header.
#[derive(Debug)]
struct EncryptedHeader {
    /// Magic bytes.
    magic: [u8; 8],
    /// Nonce.
    nonce: [u8; NONCE_SIZE],
}

impl EncryptedHeader {
    const SIZE: usize = 8 + NONCE_SIZE;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..8].copy_from_slice(&self.magic);
        bytes[8..].copy_from_slice(&self.nonce);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> TerasResult<Self> {
        if bytes.len() < Self::SIZE {
            return Err(TerasError::InvalidFormat("Data too short".to_string()));
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[..8]);

        if magic != *ENCRYPTED_MAGIC {
            return Err(TerasError::InvalidFormat(
                "Invalid encrypted file magic".to_string(),
            ));
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[8..Self::SIZE]);

        Ok(Self { magic, nonce })
    }
}

/// Encrypt data using AES-256-GCM.
///
/// # Arguments
///
/// * `plaintext` - Data to encrypt
/// * `key` - 32-byte encryption key
///
/// # Returns
///
/// Encrypted data with format: MAGIC || NONCE || CIPHERTEXT
///
/// # Errors
///
/// Returns error if encryption fails.
pub fn encrypt(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> TerasResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| TerasError::InvalidKeyLength {
        expected: KEY_SIZE,
        actual: key.len(),
    })?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| TerasError::DecryptionFailed)?;

    // Build output: MAGIC || NONCE || CIPHERTEXT
    let header = EncryptedHeader {
        magic: ENCRYPTED_MAGIC.try_into().unwrap(),
        nonce: nonce_bytes,
    };

    let mut output = Vec::with_capacity(EncryptedHeader::SIZE + ciphertext.len());
    output.extend_from_slice(&header.to_bytes());
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt data using AES-256-GCM.
///
/// # Arguments
///
/// * `encrypted` - Encrypted data (MAGIC || NONCE || CIPHERTEXT)
/// * `key` - 32-byte encryption key
///
/// # Errors
///
/// Returns error if decryption fails or data is invalid.
pub fn decrypt(encrypted: &[u8], key: &[u8; KEY_SIZE]) -> TerasResult<Vec<u8>> {
    if encrypted.len() < EncryptedHeader::SIZE + TAG_SIZE {
        return Err(TerasError::InvalidFormat(
            "Encrypted data too short".to_string(),
        ));
    }

    let header = EncryptedHeader::from_bytes(encrypted)?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| TerasError::InvalidKeyLength {
        expected: KEY_SIZE,
        actual: key.len(),
    })?;

    let nonce = Nonce::from_slice(&header.nonce);
    let ciphertext = &encrypted[EncryptedHeader::SIZE..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| TerasError::DecryptionFailed)
}

/// Derive an encryption key from a password using Argon2.
///
/// # Arguments
///
/// * `password` - User password
/// * `salt` - Salt for key derivation (should be random and stored)
/// * `iterations` - Number of iterations (higher = more secure but slower)
///
/// # Errors
///
/// Returns error if key derivation fails.
pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> TerasResult<[u8; KEY_SIZE]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Argon2id with configurable iterations
    let params = Params::new(
        65536,          // 64 MB memory
        iterations,     // time cost
        4,              // parallelism
        Some(KEY_SIZE), // output length
    )
    .map_err(|_| TerasError::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| TerasError::KeyDerivationFailed)?;

    Ok(key)
}

/// Generate a random encryption key.
#[must_use]
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Generate a random salt for key derivation.
#[must_use]
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Securely zeroize a key.
pub fn zeroize_key(key: &mut [u8; KEY_SIZE]) {
    key.zeroize();
}

/// Encrypt and write a file.
///
/// # Errors
///
/// Returns error if encryption or file write fails.
pub fn encrypt_file(
    path: &std::path::Path,
    plaintext: &[u8],
    key: &[u8; KEY_SIZE],
) -> TerasResult<()> {
    let encrypted = encrypt(plaintext, key)?;
    crate::atomic::atomic_write(path, &encrypted)
}

/// Read and decrypt a file.
///
/// # Errors
///
/// Returns error if decryption or file read fails.
pub fn decrypt_file(path: &std::path::Path, key: &[u8; KEY_SIZE]) -> TerasResult<Vec<u8>> {
    let encrypted = std::fs::read(path).map_err(TerasError::IoError)?;
    decrypt(&encrypted, key)
}

/// Check if data appears to be encrypted (has correct magic).
#[must_use]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= ENCRYPTED_MAGIC.len() && &data[..ENCRYPTED_MAGIC.len()] == ENCRYPTED_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"secret message";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_has_magic() {
        let key = generate_key();
        let encrypted = encrypt(b"test", &key).unwrap();

        assert!(is_encrypted(&encrypted));
        assert!(&encrypted[..8] == ENCRYPTED_MAGIC);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();

        let encrypted = encrypt(b"secret", &key1).unwrap();
        let result = decrypt(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_fails() {
        let key = generate_key();
        let mut encrypted = encrypt(b"secret", &key).unwrap();

        // Corrupt a byte
        encrypted[20] ^= 0xFF;

        let result = decrypt(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated_fails() {
        let key = generate_key();
        let encrypted = encrypt(b"secret", &key).unwrap();

        // Truncate
        let truncated = &encrypted[..encrypted.len() - 10];
        let result = decrypt(truncated, &key);

        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key() {
        let password = b"my_password";
        let salt = generate_salt();

        let key = derive_key(password, &salt, 3).unwrap();
        assert_eq!(key.len(), KEY_SIZE);

        // Same password and salt should produce same key
        let key2 = derive_key(password, &salt, 3).unwrap();
        assert_eq!(key, key2);

        // Different password should produce different key
        let key3 = derive_key(b"different", &salt, 3).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_generate_key_random() {
        let key1 = generate_key();
        let key2 = generate_key();

        // Should be different (with overwhelming probability)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_zeroize_key() {
        let mut key = generate_key();
        let original = key;

        assert_ne!(key, [0u8; KEY_SIZE]);

        zeroize_key(&mut key);

        assert_eq!(key, [0u8; KEY_SIZE]);
        assert_ne!(original, key);
    }

    #[test]
    fn test_encrypt_decrypt_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("encrypted.dat");
        let key = generate_key();
        let plaintext = b"file contents";

        encrypt_file(&path, plaintext, &key).unwrap();
        assert!(path.exists());

        let decrypted = decrypt_file(&path, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_is_encrypted() {
        let key = generate_key();
        let encrypted = encrypt(b"test", &key).unwrap();

        assert!(is_encrypted(&encrypted));
        assert!(!is_encrypted(b"plain text"));
        assert!(!is_encrypted(b"TERAS")); // Too short
    }

    #[test]
    fn test_encrypt_empty() {
        let key = generate_key();
        let encrypted = encrypt(b"", &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_large() {
        let key = generate_key();
        let large = vec![0xAB; 1024 * 1024]; // 1 MB

        let encrypted = encrypt(&large, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, large);
    }
}
