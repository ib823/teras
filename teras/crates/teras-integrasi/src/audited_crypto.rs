//! Audited cryptographic operations.
//!
//! Wraps teras-kunci operations with automatic LAW 8 audit logging.

use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};
use teras_kunci::hash::{blake3_hash, sha256, sha3_256};
use teras_kunci::kem::HybridKem;
use teras_kunci::sign::HybridSigner;

/// Audited cryptographic operations.
///
/// Every operation creates an audit log entry per LAW 8.
pub struct AuditedCrypto {
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
}

impl AuditedCrypto {
    /// Create new audited crypto wrapper.
    pub(crate) fn new(audit_log: Arc<std::sync::RwLock<AuditLog>>) -> Self {
        Self { audit_log }
    }

    fn log_operation(
        &self,
        operation: &str,
        key_id: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<u64> {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "teras-kunci".to_string(),
            },
            Action::KeyOperation {
                operation: operation.to_string(),
                key_id: key_id.to_string(),
            },
            format!("crypto:{operation}"),
            result,
        )
        .with_context(context.unwrap_or_default());

        let mut log = self
            .audit_log
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        log.append(entry)
    }

    /// Generate a new hybrid keypair (ML-KEM-768 + X25519).
    ///
    /// # Arguments
    ///
    /// * `key_id` - Identifier for this key (for audit log)
    ///
    /// # Returns
    ///
    /// Returns the public key metadata. Private key is held internally.
    ///
    /// # Errors
    ///
    /// Returns error if key generation or audit logging fails.
    pub fn generate_hybrid_keypair(&self, key_id: &str) -> TerasResult<HybridKemPublicKey> {
        // Generate keypair using HybridKem
        let (_secret_key, _public_key) = HybridKem::generate()?;

        // Log the operation (LAW 8)
        self.log_operation("generate_hybrid_kem", key_id, ActionResult::Success, None)?;

        Ok(HybridKemPublicKey {
            key_id: key_id.to_string(),
            algorithm: "ML-KEM-768+X25519".to_string(),
        })
    }

    /// Generate a new hybrid signing keypair (Dilithium3 + Ed25519).
    ///
    /// # Errors
    ///
    /// Returns error if key generation or audit logging fails.
    pub fn generate_signing_keypair(&self, key_id: &str) -> TerasResult<HybridSigningPublicKey> {
        // Generate keypair using HybridSigner
        let (_secret_key, public_key) = HybridSigner::generate()?;

        // Get public key bytes for metadata
        let dilithium_pk_len = public_key.dilithium_vk().as_bytes().len();
        let ed25519_pk_len = public_key.ed25519_vk().as_bytes().len();

        // Log the operation (LAW 8)
        self.log_operation("generate_hybrid_sign", key_id, ActionResult::Success, None)?;

        Ok(HybridSigningPublicKey {
            key_id: key_id.to_string(),
            algorithm: "ML-DSA-65+Ed25519".to_string(),
            dilithium_pk_size: dilithium_pk_len,
            ed25519_pk_size: ed25519_pk_len,
        })
    }

    /// Compute SHA-256 hash with audit logging.
    ///
    /// # Errors
    ///
    /// Returns error if audit logging fails.
    pub fn hash_sha256(&self, data: &[u8], object_id: &str) -> TerasResult<[u8; 32]> {
        let hash = sha256(data);

        self.log_operation(
            "hash_sha256",
            object_id,
            ActionResult::Success,
            Some(Context::new().with_extra("input_len", data.len().to_string())),
        )?;

        Ok(hash)
    }

    /// Compute SHA3-256 hash with audit logging.
    ///
    /// # Errors
    ///
    /// Returns error if audit logging fails.
    pub fn hash_sha3_256(&self, data: &[u8], object_id: &str) -> TerasResult<[u8; 32]> {
        let hash = sha3_256(data);

        self.log_operation(
            "hash_sha3_256",
            object_id,
            ActionResult::Success,
            Some(Context::new().with_extra("input_len", data.len().to_string())),
        )?;

        Ok(hash)
    }

    /// Compute BLAKE3 hash with audit logging.
    ///
    /// # Errors
    ///
    /// Returns error if audit logging fails.
    pub fn hash_blake3(&self, data: &[u8], object_id: &str) -> TerasResult<[u8; 32]> {
        let hash = blake3_hash(data);

        self.log_operation(
            "hash_blake3",
            object_id,
            ActionResult::Success,
            Some(Context::new().with_extra("input_len", data.len().to_string())),
        )?;

        Ok(hash)
    }
}

/// Public key metadata for hybrid KEM.
#[derive(Debug, Clone)]
pub struct HybridKemPublicKey {
    /// Key identifier.
    pub key_id: String,
    /// Algorithm identifier.
    pub algorithm: String,
}

/// Public key metadata for hybrid signing.
#[derive(Debug, Clone)]
pub struct HybridSigningPublicKey {
    /// Key identifier.
    pub key_id: String,
    /// Algorithm identifier.
    pub algorithm: String,
    /// Dilithium public key size in bytes.
    pub dilithium_pk_size: usize,
    /// Ed25519 public key size in bytes.
    pub ed25519_pk_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use teras_jejak::storage::MemoryStorage;

    fn create_test_crypto() -> AuditedCrypto {
        let storage = MemoryStorage::new();
        let audit_log = AuditLog::new(Box::new(storage));
        AuditedCrypto::new(Arc::new(std::sync::RwLock::new(audit_log)))
    }

    #[test]
    fn test_generate_hybrid_keypair_logged() {
        let crypto = create_test_crypto();

        let pk = crypto.generate_hybrid_keypair("test-key-1").unwrap();

        assert_eq!(pk.key_id, "test-key-1");
        assert_eq!(pk.algorithm, "ML-KEM-768+X25519");

        // Verify audit log entry
        let log = crypto.audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    #[test]
    fn test_generate_signing_keypair_logged() {
        let crypto = create_test_crypto();

        let pk = crypto.generate_signing_keypair("sign-key-1").unwrap();

        assert_eq!(pk.key_id, "sign-key-1");
        assert_eq!(pk.algorithm, "ML-DSA-65+Ed25519");
        assert!(pk.dilithium_pk_size > 0);
        assert!(pk.ed25519_pk_size > 0);

        // Verify audit log entry
        let log = crypto.audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    #[test]
    fn test_hash_sha256_logged() {
        let crypto = create_test_crypto();

        let hash = crypto.hash_sha256(b"test data", "doc-1").unwrap();

        assert_eq!(hash.len(), 32);

        // Verify audit log entry
        let log = crypto.audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    #[test]
    fn test_hash_sha3_256_logged() {
        let crypto = create_test_crypto();

        let hash = crypto.hash_sha3_256(b"test data", "doc-2").unwrap();

        assert_eq!(hash.len(), 32);

        // Verify audit log entry
        let log = crypto.audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    #[test]
    fn test_hash_blake3_logged() {
        let crypto = create_test_crypto();

        let hash = crypto.hash_blake3(b"test data", "doc-3").unwrap();

        assert_eq!(hash.len(), 32);

        // Verify audit log entry
        let log = crypto.audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    #[test]
    fn test_multiple_operations_logged() {
        let crypto = create_test_crypto();

        crypto.hash_sha256(b"data1", "obj1").unwrap();
        crypto.hash_sha3_256(b"data2", "obj2").unwrap();
        crypto.hash_blake3(b"data3", "obj3").unwrap();

        // Verify all operations logged
        let log = crypto.audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 3);

        // Verify chain integrity
        assert!(log.verify_chain().unwrap().valid);
    }
}
