//! Key storage abstraction for signing keys.
//!
//! LAW 4: All secrets use Secret<T> and are zeroized.
//! LAW 8: All key operations are logged.

use crate::types::{SignatureAlgorithm, SigningKeyInfo};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};
use teras_kunci::sign::{HybridSigner, HybridVerifyingKey};

/// Trait for key storage backends.
pub trait KeyStore: Send + Sync {
    /// Store a keypair.
    fn store(
        &mut self,
        key_id: &str,
        signer: HybridSigner,
        vk: HybridVerifyingKey,
    ) -> TerasResult<()>;

    /// Get a signer by key ID.
    fn get_signer(&self, key_id: &str) -> TerasResult<Option<&HybridSigner>>;

    /// Get a verifying key by key ID.
    fn get_verifying_key(&self, key_id: &str) -> TerasResult<Option<&HybridVerifyingKey>>;

    /// List all key IDs.
    fn list_keys(&self) -> TerasResult<Vec<String>>;

    /// Remove a key by ID.
    fn remove(&mut self, key_id: &str) -> TerasResult<bool>;

    /// Check if a key exists.
    fn contains(&self, key_id: &str) -> bool;

    /// Get key count.
    fn count(&self) -> usize;
}

/// In-memory key storage.
///
/// Keys are stored in memory and lost when the process exits.
/// Suitable for testing and short-lived operations.
pub struct MemoryKeyStore {
    signers: HashMap<String, HybridSigner>,
    verifying_keys: HashMap<String, HybridVerifyingKey>,
    metadata: HashMap<String, SigningKeyInfo>,
}

impl MemoryKeyStore {
    /// Create a new empty memory key store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signers: HashMap::new(),
            verifying_keys: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Get key metadata.
    #[must_use]
    pub fn get_info(&self, key_id: &str) -> Option<&SigningKeyInfo> {
        self.metadata.get(key_id)
    }
}

impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for MemoryKeyStore {
    fn store(
        &mut self,
        key_id: &str,
        signer: HybridSigner,
        vk: HybridVerifyingKey,
    ) -> TerasResult<()> {
        // Create metadata
        let info = SigningKeyInfo {
            key_id: key_id.to_string(),
            algorithm: SignatureAlgorithm::HybridDilithiumEd25519,
            created_at: Utc::now(),
            expires_at: None,
            subject: None,
            dilithium_pk_size: vk.dilithium_vk().as_bytes().len(),
            ed25519_pk_size: vk.ed25519_vk().as_bytes().len(),
        };

        self.signers.insert(key_id.to_string(), signer);
        self.verifying_keys.insert(key_id.to_string(), vk);
        self.metadata.insert(key_id.to_string(), info);

        Ok(())
    }

    fn get_signer(&self, key_id: &str) -> TerasResult<Option<&HybridSigner>> {
        Ok(self.signers.get(key_id))
    }

    fn get_verifying_key(&self, key_id: &str) -> TerasResult<Option<&HybridVerifyingKey>> {
        Ok(self.verifying_keys.get(key_id))
    }

    fn list_keys(&self) -> TerasResult<Vec<String>> {
        Ok(self.signers.keys().cloned().collect())
    }

    fn remove(&mut self, key_id: &str) -> TerasResult<bool> {
        let removed = self.signers.remove(key_id).is_some();
        self.verifying_keys.remove(key_id);
        self.metadata.remove(key_id);
        Ok(removed)
    }

    fn contains(&self, key_id: &str) -> bool {
        self.signers.contains_key(key_id)
    }

    fn count(&self) -> usize {
        self.signers.len()
    }
}

/// Audited key store wrapper.
///
/// Wraps any KeyStore implementation with LAW 8 audit logging.
pub struct AuditedKeyStore<S: KeyStore> {
    inner: S,
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
}

impl<S: KeyStore> AuditedKeyStore<S> {
    /// Create a new audited key store.
    pub fn new(store: S, audit_log: Arc<std::sync::RwLock<AuditLog>>) -> Self {
        Self {
            inner: store,
            audit_log,
        }
    }

    /// Generate and store a new keypair.
    ///
    /// # Errors
    ///
    /// Returns error if key generation or storage fails.
    pub fn generate(&mut self, key_id: &str) -> TerasResult<SigningKeyInfo> {
        let (signer, vk) = HybridSigner::generate()?;

        let info = SigningKeyInfo {
            key_id: key_id.to_string(),
            algorithm: SignatureAlgorithm::HybridDilithiumEd25519,
            created_at: Utc::now(),
            expires_at: None,
            subject: None,
            dilithium_pk_size: vk.dilithium_vk().as_bytes().len(),
            ed25519_pk_size: vk.ed25519_vk().as_bytes().len(),
        };

        self.inner.store(key_id, signer, vk)?;

        // Log key generation (LAW 8)
        self.log_operation(
            "generate",
            key_id,
            ActionResult::Success,
            Some(Context::new().with_extra("algorithm", info.algorithm.to_string())),
        )?;

        Ok(info)
    }

    /// Store a keypair.
    ///
    /// # Errors
    ///
    /// Returns error if storage or logging fails.
    pub fn store(
        &mut self,
        key_id: &str,
        signer: HybridSigner,
        vk: HybridVerifyingKey,
    ) -> TerasResult<()> {
        self.inner.store(key_id, signer, vk)?;

        self.log_operation("store", key_id, ActionResult::Success, None)?;

        Ok(())
    }

    /// Get a signer by key ID.
    ///
    /// # Errors
    ///
    /// Returns error if key not found.
    pub fn get_signer(&self, key_id: &str) -> TerasResult<&HybridSigner> {
        self.inner
            .get_signer(key_id)?
            .ok_or_else(|| TerasError::KeyNotFound {
                key_id: key_id.to_string(),
            })
    }

    /// Get a verifying key by key ID.
    ///
    /// # Errors
    ///
    /// Returns error if key not found.
    pub fn get_verifying_key(&self, key_id: &str) -> TerasResult<&HybridVerifyingKey> {
        self.inner
            .get_verifying_key(key_id)?
            .ok_or_else(|| TerasError::KeyNotFound {
                key_id: key_id.to_string(),
            })
    }

    /// List all key IDs.
    ///
    /// # Errors
    ///
    /// Returns error if listing fails.
    pub fn list_keys(&self) -> TerasResult<Vec<String>> {
        self.inner.list_keys()
    }

    /// Remove a key.
    ///
    /// # Errors
    ///
    /// Returns error if removal or logging fails.
    pub fn remove(&mut self, key_id: &str) -> TerasResult<bool> {
        let removed = self.inner.remove(key_id)?;

        if removed {
            self.log_operation("remove", key_id, ActionResult::Success, None)?;
        } else {
            self.log_operation(
                "remove",
                key_id,
                ActionResult::Failure {
                    reason: "Key not found".to_string(),
                    code: None,
                },
                None,
            )?;
        }

        Ok(removed)
    }

    /// Check if a key exists.
    #[must_use]
    pub fn contains(&self, key_id: &str) -> bool {
        self.inner.contains(key_id)
    }

    /// Get key count.
    #[must_use]
    pub fn count(&self) -> usize {
        self.inner.count()
    }

    /// Get underlying store (for reading metadata).
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
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
                component: "teras-sandi-keystore".to_string(),
            },
            Action::KeyOperation {
                operation: format!("keystore:{operation}"),
                key_id: key_id.to_string(),
            },
            format!("keystore:{key_id}"),
            result,
        )
        .with_context(context.unwrap_or_default());

        let mut log = self
            .audit_log
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        log.append(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use teras_jejak::storage::MemoryStorage;

    fn create_audit_log() -> Arc<std::sync::RwLock<AuditLog>> {
        let storage = MemoryStorage::new();
        Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))))
    }

    #[test]
    fn test_memory_keystore_basic() {
        let mut store = MemoryKeyStore::new();
        let (signer, vk) = HybridSigner::generate().unwrap();

        store.store("key-1", signer, vk).unwrap();

        assert!(store.contains("key-1"));
        assert!(!store.contains("key-2"));
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_memory_keystore_list() {
        let mut store = MemoryKeyStore::new();

        for i in 0..3 {
            let (signer, vk) = HybridSigner::generate().unwrap();
            store.store(&format!("key-{i}"), signer, vk).unwrap();
        }

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_memory_keystore_remove() {
        let mut store = MemoryKeyStore::new();
        let (signer, vk) = HybridSigner::generate().unwrap();

        store.store("remove-key", signer, vk).unwrap();
        assert!(store.contains("remove-key"));

        let removed = store.remove("remove-key").unwrap();
        assert!(removed);
        assert!(!store.contains("remove-key"));

        let removed_again = store.remove("remove-key").unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_audited_keystore_generate() {
        let audit_log = create_audit_log();
        let store = MemoryKeyStore::new();
        let mut audited = AuditedKeyStore::new(store, audit_log.clone());

        let info = audited.generate("gen-key").unwrap();

        assert_eq!(info.key_id, "gen-key");
        assert_eq!(info.algorithm, SignatureAlgorithm::HybridDilithiumEd25519);
        assert!(audited.contains("gen-key"));

        // Verify operation was logged
        let log = audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    #[test]
    fn test_audited_keystore_get_signer() {
        let audit_log = create_audit_log();
        let store = MemoryKeyStore::new();
        let mut audited = AuditedKeyStore::new(store, audit_log);

        audited.generate("get-key").unwrap();

        let signer = audited.get_signer("get-key");
        assert!(signer.is_ok());

        let missing = audited.get_signer("missing-key");
        assert!(missing.is_err());
    }

    #[test]
    fn test_audited_keystore_get_verifying_key() {
        let audit_log = create_audit_log();
        let store = MemoryKeyStore::new();
        let mut audited = AuditedKeyStore::new(store, audit_log);

        audited.generate("vk-key").unwrap();

        let vk = audited.get_verifying_key("vk-key");
        assert!(vk.is_ok());
    }

    #[test]
    fn test_audited_keystore_remove_logged() {
        let audit_log = create_audit_log();
        let store = MemoryKeyStore::new();
        let mut audited = AuditedKeyStore::new(store, audit_log.clone());

        audited.generate("rm-key").unwrap();
        audited.remove("rm-key").unwrap();

        // Verify both operations logged (generate + remove)
        let log = audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 2);
    }
}
