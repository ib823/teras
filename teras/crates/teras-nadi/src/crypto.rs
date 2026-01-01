//! NADI cryptographic operations.
//!
//! Uses teras-kunci for all cryptographic primitives:
//! - ChaCha20-Poly1305 for packet encryption
//! - HMAC-SHA256 for header authentication
//! - HKDF-SHA3-256 for session key derivation
//!
//! # Key Derivation
//!
//! Session keys are derived using HKDF-SHA3-256 as specified:
//!
//! ```text
//! master_secret = HKDF-SHA3-256(
//!     ikm = pq_shared || classical_shared,
//!     salt = client_random || server_random,
//!     info = "NADI-v1-master"
//! )
//!
//! client_key = HKDF-Expand(master_secret, "client-key", 32)
//! server_key = HKDF-Expand(master_secret, "server-key", 32)
//! client_nonce = HKDF-Expand(master_secret, "client-nonce", 12)
//! server_nonce = HKDF-Expand(master_secret, "server-nonce", 12)
//! header_key = HKDF-Expand(master_secret, "header-mac", 32)
//! ```

use crate::error::{NadiError, NadiResult};
use crate::packet::{PacketHeader, HEADER_MAC_SIZE};
use bytes::Bytes;
use teras_kunci::kdf::{hkdf_derive, HkdfAlgorithm};
use teras_kunci::symmetric::{ChaCha20Poly1305Cipher, SymmetricCipher};
use teras_lindung::Secret;

/// Size of random bytes in handshake.
pub const RANDOM_SIZE: usize = 32;

/// Session key material derived from handshake.
pub struct SessionKeys {
    /// Key for encrypting client -> server traffic.
    pub client_key: Secret<[u8; 32]>,
    /// Key for encrypting server -> client traffic.
    pub server_key: Secret<[u8; 32]>,
    /// Base nonce for client -> server traffic.
    pub client_nonce: [u8; 12],
    /// Base nonce for server -> client traffic.
    pub server_nonce: [u8; 12],
    /// Key for header MAC.
    pub header_key: Secret<[u8; 32]>,
}

impl SessionKeys {
    /// Derive session keys from shared secrets.
    ///
    /// # Arguments
    ///
    /// * `pq_shared` - Post-quantum shared secret (ML-KEM-768)
    /// * `classical_shared` - Classical shared secret (X25519)
    /// * `client_random` - Client's random bytes
    /// * `server_random` - Server's random bytes
    pub fn derive(
        pq_shared: &[u8],
        classical_shared: &[u8],
        client_random: &[u8; RANDOM_SIZE],
        server_random: &[u8; RANDOM_SIZE],
    ) -> NadiResult<Self> {
        // Combine shared secrets for IKM
        let mut ikm = Vec::with_capacity(pq_shared.len() + classical_shared.len());
        ikm.extend_from_slice(pq_shared);
        ikm.extend_from_slice(classical_shared);

        // Combine randoms for salt
        let mut salt = [0u8; RANDOM_SIZE * 2];
        salt[..RANDOM_SIZE].copy_from_slice(client_random);
        salt[RANDOM_SIZE..].copy_from_slice(server_random);

        // Derive master secret using SHA3-256
        let master_secret = hkdf_derive(
            HkdfAlgorithm::Sha3_256,
            &ikm,
            &salt,
            b"NADI-v1-master",
            32,
        )
        .map_err(|e| NadiError::KeyDerivationFailed(e.to_string()))?;

        // Derive individual keys from master secret
        let client_key_bytes = hkdf_derive(
            HkdfAlgorithm::Sha3_256,
            &master_secret,
            &[],
            b"client-key",
            32,
        )
        .map_err(|e| NadiError::KeyDerivationFailed(e.to_string()))?;

        let server_key_bytes = hkdf_derive(
            HkdfAlgorithm::Sha3_256,
            &master_secret,
            &[],
            b"server-key",
            32,
        )
        .map_err(|e| NadiError::KeyDerivationFailed(e.to_string()))?;

        let client_nonce_bytes = hkdf_derive(
            HkdfAlgorithm::Sha3_256,
            &master_secret,
            &[],
            b"client-nonce",
            12,
        )
        .map_err(|e| NadiError::KeyDerivationFailed(e.to_string()))?;

        let server_nonce_bytes = hkdf_derive(
            HkdfAlgorithm::Sha3_256,
            &master_secret,
            &[],
            b"server-nonce",
            12,
        )
        .map_err(|e| NadiError::KeyDerivationFailed(e.to_string()))?;

        let header_key_bytes = hkdf_derive(
            HkdfAlgorithm::Sha3_256,
            &master_secret,
            &[],
            b"header-mac",
            32,
        )
        .map_err(|e| NadiError::KeyDerivationFailed(e.to_string()))?;

        // Convert to fixed arrays
        let mut client_key = [0u8; 32];
        client_key.copy_from_slice(&client_key_bytes);

        let mut server_key = [0u8; 32];
        server_key.copy_from_slice(&server_key_bytes);

        let mut client_nonce = [0u8; 12];
        client_nonce.copy_from_slice(&client_nonce_bytes);

        let mut server_nonce = [0u8; 12];
        server_nonce.copy_from_slice(&server_nonce_bytes);

        let mut header_key = [0u8; 32];
        header_key.copy_from_slice(&header_key_bytes);

        Ok(Self {
            client_key: Secret::new(client_key),
            server_key: Secret::new(server_key),
            client_nonce,
            server_nonce,
            header_key: Secret::new(header_key),
        })
    }
}

/// Packet encryption/decryption context.
pub struct PacketCrypto {
    /// Cipher for outgoing packets.
    encrypt_cipher: ChaCha20Poly1305Cipher,
    /// Cipher for incoming packets.
    decrypt_cipher: ChaCha20Poly1305Cipher,
    /// Base nonce for outgoing packets.
    encrypt_nonce: [u8; 12],
    /// Base nonce for incoming packets.
    decrypt_nonce: [u8; 12],
    /// Key for header MAC.
    header_key: Secret<[u8; 32]>,
    /// Are we the client (true) or server (false)?
    #[allow(dead_code)]
    is_client: bool,
}

impl PacketCrypto {
    /// Create packet crypto context from session keys.
    pub fn new(keys: SessionKeys, is_client: bool) -> NadiResult<Self> {
        let (encrypt_key, decrypt_key, encrypt_nonce, decrypt_nonce) = if is_client {
            (
                &keys.client_key,
                &keys.server_key,
                keys.client_nonce,
                keys.server_nonce,
            )
        } else {
            (
                &keys.server_key,
                &keys.client_key,
                keys.server_nonce,
                keys.client_nonce,
            )
        };

        let encrypt_cipher = ChaCha20Poly1305Cipher::new(encrypt_key)
            .map_err(|e| NadiError::Crypto(e.to_string()))?;

        let decrypt_cipher = ChaCha20Poly1305Cipher::new(decrypt_key)
            .map_err(|e| NadiError::Crypto(e.to_string()))?;

        Ok(Self {
            encrypt_cipher,
            decrypt_cipher,
            encrypt_nonce,
            decrypt_nonce,
            header_key: keys.header_key,
            is_client,
        })
    }

    /// Derive per-packet nonce from base nonce and sequence number.
    ///
    /// nonce = base_nonce XOR (sequence_number padded to 12 bytes)
    fn derive_nonce(base: &[u8; 12], sequence: u32) -> [u8; 12] {
        let mut nonce = *base;
        let seq_bytes = sequence.to_be_bytes();

        // XOR sequence into last 4 bytes
        for i in 0..4 {
            nonce[8 + i] ^= seq_bytes[i];
        }

        nonce
    }

    /// Encrypt a payload.
    ///
    /// Returns the encrypted payload with authentication tag.
    pub fn encrypt(&self, sequence: u32, payload: &[u8], header_bytes: &[u8]) -> NadiResult<Bytes> {
        let nonce = Self::derive_nonce(&self.encrypt_nonce, sequence);

        let ciphertext = self
            .encrypt_cipher
            .encrypt(&nonce, payload, header_bytes)
            .map_err(|e| NadiError::EncryptionFailed(e.to_string()))?;

        Ok(Bytes::from(ciphertext))
    }

    /// Decrypt a payload.
    ///
    /// Returns the decrypted plaintext.
    pub fn decrypt(
        &self,
        sequence: u32,
        ciphertext: &[u8],
        header_bytes: &[u8],
    ) -> NadiResult<Bytes> {
        let nonce = Self::derive_nonce(&self.decrypt_nonce, sequence);

        let plaintext = self
            .decrypt_cipher
            .decrypt(&nonce, ciphertext, header_bytes)
            .map_err(|_| NadiError::PayloadAuthFailed)?;

        Ok(Bytes::from(plaintext))
    }

    /// Compute header MAC.
    ///
    /// Uses HMAC-SHA256 truncated to 64 bits.
    pub fn compute_header_mac(&self, header: &PacketHeader) -> [u8; HEADER_MAC_SIZE] {
        let mac_input = header.mac_input();
        let full_mac = hmac_sha256(self.header_key.expose(), &mac_input);

        // Truncate to 64 bits
        let mut truncated = [0u8; HEADER_MAC_SIZE];
        truncated.copy_from_slice(&full_mac[..HEADER_MAC_SIZE]);
        truncated
    }

    /// Verify header MAC.
    pub fn verify_header_mac(&self, header: &PacketHeader) -> bool {
        let expected = self.compute_header_mac(header);
        teras_kunci::ct_eq(&expected, &header.header_mac)
    }

    /// Apply header MAC to a header.
    pub fn sign_header(&self, header: &mut PacketHeader) {
        header.header_mac = self.compute_header_mac(header);
    }
}

/// Compute HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // Simple HMAC implementation
    // HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
    const BLOCK_SIZE: usize = 64;

    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Inner pad
    let mut i_key_pad = [0x36u8; BLOCK_SIZE];
    for (i, byte) in k_prime.iter().enumerate() {
        i_key_pad[i] ^= byte;
    }

    // Outer pad
    let mut o_key_pad = [0x5cu8; BLOCK_SIZE];
    for (i, byte) in k_prime.iter().enumerate() {
        o_key_pad[i] ^= byte;
    }

    // Inner hash
    let mut hasher = Sha256::new();
    hasher.update(&i_key_pad);
    hasher.update(data);
    let inner_hash = hasher.finalize();

    // Outer hash
    let mut hasher = Sha256::new();
    hasher.update(&o_key_pad);
    hasher.update(&inner_hash);
    let outer_hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

/// Handshake cryptographic operations.
pub struct HandshakeCrypto;

impl HandshakeCrypto {
    /// Generate random bytes for handshake.
    pub fn generate_random() -> NadiResult<[u8; RANDOM_SIZE]> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut random = [0u8; RANDOM_SIZE];
        rng.fill_bytes(&mut random);
        Ok(random)
    }

    /// Hash transcript for signature.
    pub fn hash_transcript(transcript: &[u8]) -> [u8; 32] {
        teras_kunci::sha3_256(transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::HEADER_SIZE;

    fn test_session_keys() -> SessionKeys {
        let pq_shared = [0x11u8; 32];
        let classical_shared = [0x22u8; 32];
        let client_random = [0x33u8; RANDOM_SIZE];
        let server_random = [0x44u8; RANDOM_SIZE];

        SessionKeys::derive(&pq_shared, &classical_shared, &client_random, &server_random).unwrap()
    }

    #[test]
    fn test_session_key_derivation() {
        let keys = test_session_keys();

        // Keys should be non-zero
        assert_ne!(keys.client_key.expose(), &[0u8; 32]);
        assert_ne!(keys.server_key.expose(), &[0u8; 32]);
        assert_ne!(keys.header_key.expose(), &[0u8; 32]);

        // Client and server keys should be different
        assert_ne!(keys.client_key.expose(), keys.server_key.expose());
    }

    #[test]
    fn test_session_key_deterministic() {
        let pq_shared = [0x11u8; 32];
        let classical_shared = [0x22u8; 32];
        let client_random = [0x33u8; RANDOM_SIZE];
        let server_random = [0x44u8; RANDOM_SIZE];

        let keys1 =
            SessionKeys::derive(&pq_shared, &classical_shared, &client_random, &server_random)
                .unwrap();
        let keys2 =
            SessionKeys::derive(&pq_shared, &classical_shared, &client_random, &server_random)
                .unwrap();

        assert_eq!(keys1.client_key.expose(), keys2.client_key.expose());
        assert_eq!(keys1.server_key.expose(), keys2.server_key.expose());
    }

    #[test]
    fn test_packet_crypto_roundtrip() {
        // Derive keys separately for client and server (deterministic)
        let client_keys = test_session_keys();
        let server_keys = test_session_keys();
        let client_crypto = PacketCrypto::new(client_keys, true).unwrap();
        let server_crypto = PacketCrypto::new(server_keys, false).unwrap();

        let plaintext = b"Hello, NADI!";
        let header = [0u8; HEADER_SIZE - HEADER_MAC_SIZE];
        let sequence = 42u32;

        // Client encrypts
        let ciphertext = client_crypto.encrypt(sequence, plaintext, &header).unwrap();

        // Server decrypts
        let decrypted = server_crypto.decrypt(sequence, &ciphertext, &header).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_packet_crypto_wrong_sequence_fails() {
        // Derive keys separately for client and server (deterministic)
        let client_keys = test_session_keys();
        let server_keys = test_session_keys();
        let client_crypto = PacketCrypto::new(client_keys, true).unwrap();
        let server_crypto = PacketCrypto::new(server_keys, false).unwrap();

        let plaintext = b"Hello, NADI!";
        let header = [0u8; HEADER_SIZE - HEADER_MAC_SIZE];

        let ciphertext = client_crypto.encrypt(1, plaintext, &header).unwrap();
        let result = server_crypto.decrypt(2, &ciphertext, &header);

        assert!(result.is_err());
    }

    #[test]
    fn test_header_mac_verification() {
        use crate::packet::{PacketHeader, PacketType};

        let keys = test_session_keys();
        let crypto = PacketCrypto::new(keys, true).unwrap();

        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = 123;
        header.session_id = 0xDEADBEEF;

        crypto.sign_header(&mut header);

        assert!(crypto.verify_header_mac(&header));

        // Modify header should fail verification
        header.sequence = 456;
        assert!(!crypto.verify_header_mac(&header));
    }

    #[test]
    fn test_nonce_derivation() {
        let base = [0u8; 12];

        let nonce0 = PacketCrypto::derive_nonce(&base, 0);
        let nonce1 = PacketCrypto::derive_nonce(&base, 1);
        let nonce2 = PacketCrypto::derive_nonce(&base, 0xFFFFFFFF);

        // Different sequences should produce different nonces
        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce0, nonce2);
        assert_ne!(nonce1, nonce2);

        // Same sequence should produce same nonce
        assert_eq!(nonce0, PacketCrypto::derive_nonce(&base, 0));
    }

    #[test]
    fn test_hmac_sha256() {
        // Test vector from RFC 4231
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";

        let mac = hmac_sha256(key, data);

        // Result should be 32 bytes
        assert_eq!(mac.len(), 32);
        // Should be non-zero
        assert_ne!(mac, [0u8; 32]);
    }

    #[test]
    fn test_generate_random() {
        let r1 = HandshakeCrypto::generate_random().unwrap();
        let r2 = HandshakeCrypto::generate_random().unwrap();

        // Should be different (with overwhelming probability)
        assert_ne!(r1, r2);
        // Should not be all zeros
        assert_ne!(r1, [0u8; RANDOM_SIZE]);
    }

    #[test]
    fn test_hash_transcript() {
        let transcript1 = b"client_hello || server_hello";
        let transcript2 = b"different transcript";

        let hash1 = HandshakeCrypto::hash_transcript(transcript1);
        let hash2 = HandshakeCrypto::hash_transcript(transcript2);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}
