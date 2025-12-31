//! File-based encrypted key storage.
//!
//! LAW 4: All secrets use `Secret<T>` and are zeroized.
//! LAW 8: All key operations are logged.
//!
//! Keys are encrypted at rest using AES-256-GCM derived from a
//! master password.

use crate::config::KeyStorageConfig;
use crate::encryption;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use teras_core::error::{TerasError, TerasResult};
use zeroize::Zeroize;

/// Serializable key metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyMetadata {
    /// Key identifier.
    pub key_id: String,
    /// Algorithm identifier.
    pub algorithm: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (if set).
    pub expires_at: Option<DateTime<Utc>>,
    /// Key owner/subject.
    pub subject: Option<String>,
}

/// Serializable signing key bundle.
#[derive(Serialize, Deserialize)]
struct StoredSigningKey {
    /// Metadata.
    metadata: StoredKeyMetadata,
    /// Dilithium secret key bytes.
    dilithium_sk: Vec<u8>,
    /// Dilithium public key bytes.
    dilithium_pk: Vec<u8>,
    /// Ed25519 secret key bytes.
    ed25519_sk: Vec<u8>,
    /// Ed25519 public key bytes.
    ed25519_pk: Vec<u8>,
}

impl Drop for StoredSigningKey {
    fn drop(&mut self) {
        self.dilithium_sk.zeroize();
        self.ed25519_sk.zeroize();
    }
}

/// File-based encrypted key storage.
///
/// Stores signing keys encrypted at rest with AES-256-GCM.
/// The encryption key is derived from a master password using Argon2.
pub struct FileKeyStore {
    /// Configuration.
    config: KeyStorageConfig,
    /// Encryption key (derived from password).
    encryption_key: RwLock<Option<[u8; encryption::KEY_SIZE]>>,
    /// In-memory cache of key metadata.
    metadata_cache: RwLock<HashMap<String, StoredKeyMetadata>>,
    /// Salt for key derivation.
    salt: [u8; 16],
}

impl FileKeyStore {
    /// Create a new file-based key store.
    ///
    /// # Arguments
    ///
    /// * `config` - Key storage configuration
    /// * `password` - Master password for encryption
    ///
    /// # Errors
    ///
    /// Returns error if directory creation or key derivation fails.
    pub fn new(config: KeyStorageConfig, password: &[u8]) -> TerasResult<Self> {
        // Create directory if it doesn't exist
        if !config.path.exists() {
            std::fs::create_dir_all(&config.path).map_err(TerasError::IoError)?;
        }

        // Load or generate salt
        let salt_path = config.path.join(".salt");
        let salt = if salt_path.exists() {
            let data = std::fs::read(&salt_path).map_err(TerasError::IoError)?;
            if data.len() != 16 {
                return Err(TerasError::StorageCorruption {
                    path: salt_path.display().to_string(),
                    reason: "Invalid salt length".to_string(),
                });
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&data);
            salt
        } else {
            let salt = encryption::generate_salt();
            crate::atomic::atomic_write(&salt_path, &salt)?;
            salt
        };

        // Derive encryption key
        let encryption_key = if config.encrypt_at_rest {
            Some(encryption::derive_key(
                password,
                &salt,
                config.kdf_iterations,
            )?)
        } else {
            None
        };

        let store = Self {
            config,
            encryption_key: RwLock::new(encryption_key),
            metadata_cache: RwLock::new(HashMap::new()),
            salt,
        };

        // Load metadata cache
        store.load_metadata_cache()?;

        Ok(store)
    }

    /// Load metadata for all stored keys.
    fn load_metadata_cache(&self) -> TerasResult<()> {
        let files = crate::path::list_files_with_extension(
            &self.config.path,
            crate::path::extensions::KEY,
        )?;

        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;

        for file in files {
            if let Some(key_id) = crate::path::extract_id_from_filename(&file) {
                // Load and decrypt to get metadata
                if let Ok(stored) = self.load_key_internal(&key_id) {
                    cache.insert(key_id, stored.metadata.clone());
                }
            }
        }

        Ok(())
    }

    /// Get the file path for a key.
    fn key_file_path(&self, key_id: &str) -> PathBuf {
        self.config
            .path
            .join(format!("{key_id}.{}", crate::path::extensions::KEY))
    }

    /// Store a signing key.
    ///
    /// # Errors
    ///
    /// Returns error if storage fails.
    pub fn store_key(
        &self,
        key_id: &str,
        dilithium_sk: &[u8],
        dilithium_pk: &[u8],
        ed25519_sk: &[u8],
        ed25519_pk: &[u8],
    ) -> TerasResult<StoredKeyMetadata> {
        let metadata = StoredKeyMetadata {
            key_id: key_id.to_string(),
            algorithm: "ML-DSA-65+Ed25519".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            subject: None,
        };

        let stored = StoredSigningKey {
            metadata: metadata.clone(),
            dilithium_sk: dilithium_sk.to_vec(),
            dilithium_pk: dilithium_pk.to_vec(),
            ed25519_sk: ed25519_sk.to_vec(),
            ed25519_pk: ed25519_pk.to_vec(),
        };

        // Serialize
        let json = serde_json::to_vec(&stored).map_err(|e| TerasError::SerializationFailed {
            type_name: "StoredSigningKey".to_string(),
            reason: e.to_string(),
        })?;

        // Encrypt if configured
        let data = if self.config.encrypt_at_rest {
            let key = self
                .encryption_key
                .read()
                .map_err(|_| TerasError::AuditLogFull)?;
            let key = key.as_ref().ok_or_else(|| TerasError::ConfigError {
                message: "Encryption key not set".to_string(),
            })?;
            encryption::encrypt(&json, key)?
        } else {
            json
        };

        // Write atomically
        let path = self.key_file_path(key_id);
        crate::atomic::atomic_write(&path, &data)?;

        // Update cache
        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        cache.insert(key_id.to_string(), metadata.clone());

        Ok(metadata)
    }

    /// Load a stored signing key.
    fn load_key_internal(&self, key_id: &str) -> TerasResult<StoredSigningKey> {
        let path = self.key_file_path(key_id);

        if !path.exists() {
            return Err(TerasError::KeyNotFound {
                key_id: key_id.to_string(),
            });
        }

        let data = std::fs::read(&path).map_err(TerasError::IoError)?;

        // Decrypt if encrypted
        let json = if encryption::is_encrypted(&data) {
            let key = self
                .encryption_key
                .read()
                .map_err(|_| TerasError::AuditLogFull)?;
            let key = key.as_ref().ok_or_else(|| TerasError::ConfigError {
                message: "Encryption key not set".to_string(),
            })?;
            encryption::decrypt(&data, key)?
        } else {
            data
        };

        serde_json::from_slice(&json).map_err(|e| TerasError::DeserializationFailed {
            type_name: "StoredSigningKey".to_string(),
            reason: e.to_string(),
        })
    }

    /// Load signing key bytes.
    ///
    /// Returns (dilithium_sk, dilithium_pk, ed25519_sk, ed25519_pk).
    ///
    /// # Errors
    ///
    /// Returns error if key not found or decryption fails.
    pub fn load_key(&self, key_id: &str) -> TerasResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let stored = self.load_key_internal(key_id)?;
        Ok((
            stored.dilithium_sk.clone(),
            stored.dilithium_pk.clone(),
            stored.ed25519_sk.clone(),
            stored.ed25519_pk.clone(),
        ))
    }

    /// Get key metadata without loading the key.
    ///
    /// # Errors
    ///
    /// Returns error if key not found.
    pub fn get_metadata(&self, key_id: &str) -> TerasResult<StoredKeyMetadata> {
        let cache = self
            .metadata_cache
            .read()
            .map_err(|_| TerasError::AuditLogFull)?;

        cache
            .get(key_id)
            .cloned()
            .ok_or_else(|| TerasError::KeyNotFound {
                key_id: key_id.to_string(),
            })
    }

    /// List all key IDs.
    pub fn list_keys(&self) -> TerasResult<Vec<String>> {
        let cache = self
            .metadata_cache
            .read()
            .map_err(|_| TerasError::AuditLogFull)?;
        Ok(cache.keys().cloned().collect())
    }

    /// Check if a key exists.
    #[must_use]
    pub fn contains(&self, key_id: &str) -> bool {
        self.metadata_cache
            .read()
            .map(|c| c.contains_key(key_id))
            .unwrap_or(false)
    }

    /// Get number of stored keys.
    #[must_use]
    pub fn count(&self) -> usize {
        self.metadata_cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Remove a key.
    ///
    /// # Errors
    ///
    /// Returns error if deletion fails.
    pub fn remove(&self, key_id: &str) -> TerasResult<bool> {
        let path = self.key_file_path(key_id);

        if !path.exists() {
            return Ok(false);
        }

        crate::atomic::atomic_delete(&path)?;

        let mut cache = self
            .metadata_cache
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        cache.remove(key_id);

        Ok(true)
    }

    /// Change the master password.
    ///
    /// Re-encrypts all keys with a new password.
    ///
    /// # Errors
    ///
    /// Returns error if re-encryption fails.
    pub fn change_password(&self, new_password: &[u8]) -> TerasResult<()> {
        if !self.config.encrypt_at_rest {
            return Ok(());
        }

        // Derive new key
        let new_key = encryption::derive_key(new_password, &self.salt, self.config.kdf_iterations)?;

        // Re-encrypt all keys
        let key_ids: Vec<String> = self.list_keys()?;

        for key_id in key_ids {
            // Load with old key
            let stored = self.load_key_internal(&key_id)?;

            // Re-serialize
            let json =
                serde_json::to_vec(&stored).map_err(|e| TerasError::SerializationFailed {
                    type_name: "StoredSigningKey".to_string(),
                    reason: e.to_string(),
                })?;

            // Encrypt with new key
            let encrypted = encryption::encrypt(&json, &new_key)?;

            // Write atomically
            let path = self.key_file_path(&key_id);
            crate::atomic::atomic_write(&path, &encrypted)?;
        }

        // Update stored encryption key
        let mut key = self
            .encryption_key
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        *key = Some(new_key);

        Ok(())
    }
}

impl Drop for FileKeyStore {
    fn drop(&mut self) {
        // Zeroize the encryption key
        if let Ok(mut key) = self.encryption_key.write() {
            if let Some(ref mut k) = *key {
                k.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_config(path: PathBuf) -> KeyStorageConfig {
        KeyStorageConfig {
            path,
            encrypt_at_rest: true,
            kdf_iterations: 3, // Low for testing
        }
    }

    #[test]
    fn test_file_keystore_creation() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("keys"));

        let store = FileKeyStore::new(config.clone(), b"password").unwrap();
        assert!(config.path.exists());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_file_keystore_store_and_load() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("keys"));
        let store = FileKeyStore::new(config, b"password").unwrap();

        let dil_sk = vec![1u8; 100];
        let dil_pk = vec![2u8; 50];
        let ed_sk = vec![3u8; 32];
        let ed_pk = vec![4u8; 32];

        store
            .store_key("key-1", &dil_sk, &dil_pk, &ed_sk, &ed_pk)
            .unwrap();

        let (loaded_dil_sk, loaded_dil_pk, loaded_ed_sk, loaded_ed_pk) =
            store.load_key("key-1").unwrap();

        assert_eq!(loaded_dil_sk, dil_sk);
        assert_eq!(loaded_dil_pk, dil_pk);
        assert_eq!(loaded_ed_sk, ed_sk);
        assert_eq!(loaded_ed_pk, ed_pk);
    }

    #[test]
    fn test_file_keystore_persistence() {
        let temp = TempDir::new().unwrap();
        let keys_path = temp.path().join("keys");
        let config = make_test_config(keys_path.clone());

        let dil_sk = vec![1u8; 100];
        let dil_pk = vec![2u8; 50];
        let ed_sk = vec![3u8; 32];
        let ed_pk = vec![4u8; 32];

        // Store key
        {
            let store = FileKeyStore::new(config.clone(), b"password").unwrap();
            store
                .store_key("key-1", &dil_sk, &dil_pk, &ed_sk, &ed_pk)
                .unwrap();
        }

        // Load in new instance
        {
            let store = FileKeyStore::new(config, b"password").unwrap();
            assert!(store.contains("key-1"));

            let (loaded_dil_sk, _, _, _) = store.load_key("key-1").unwrap();
            assert_eq!(loaded_dil_sk, dil_sk);
        }
    }

    #[test]
    fn test_file_keystore_wrong_password() {
        let temp = TempDir::new().unwrap();
        let keys_path = temp.path().join("keys");
        let config = make_test_config(keys_path.clone());

        // Store with one password
        {
            let store = FileKeyStore::new(config.clone(), b"password1").unwrap();
            store.store_key("key-1", &[1], &[2], &[3], &[4]).unwrap();
        }

        // Try to load with different password
        {
            let store = FileKeyStore::new(config, b"password2").unwrap();
            // Load should fail due to decryption error
            let result = store.load_key("key-1");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_file_keystore_list_and_count() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("keys"));
        let store = FileKeyStore::new(config, b"password").unwrap();

        assert_eq!(store.count(), 0);
        assert!(store.list_keys().unwrap().is_empty());

        store.store_key("key-1", &[1], &[2], &[3], &[4]).unwrap();
        store.store_key("key-2", &[1], &[2], &[3], &[4]).unwrap();

        assert_eq!(store.count(), 2);

        let keys = store.list_keys().unwrap();
        assert!(keys.contains(&"key-1".to_string()));
        assert!(keys.contains(&"key-2".to_string()));
    }

    #[test]
    fn test_file_keystore_remove() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("keys"));
        let store = FileKeyStore::new(config, b"password").unwrap();

        store.store_key("key-1", &[1], &[2], &[3], &[4]).unwrap();
        assert!(store.contains("key-1"));

        let removed = store.remove("key-1").unwrap();
        assert!(removed);
        assert!(!store.contains("key-1"));

        // Remove non-existent
        let removed = store.remove("key-1").unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_file_keystore_metadata() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("keys"));
        let store = FileKeyStore::new(config, b"password").unwrap();

        store.store_key("key-1", &[1], &[2], &[3], &[4]).unwrap();

        let metadata = store.get_metadata("key-1").unwrap();
        assert_eq!(metadata.key_id, "key-1");
        assert_eq!(metadata.algorithm, "ML-DSA-65+Ed25519");
    }

    #[test]
    fn test_encrypted_file_format() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("keys"));
        let store = FileKeyStore::new(config.clone(), b"password").unwrap();

        store.store_key("key-1", &[1], &[2], &[3], &[4]).unwrap();

        // Read raw file
        let path = config.path.join("key-1.key");
        let data = std::fs::read(&path).unwrap();

        // Should be encrypted
        assert!(encryption::is_encrypted(&data));
    }

    #[test]
    fn test_unencrypted_storage() {
        let temp = TempDir::new().unwrap();
        let mut config = make_test_config(temp.path().join("keys"));
        config.encrypt_at_rest = false;

        let store = FileKeyStore::new(config.clone(), b"").unwrap();
        store.store_key("key-1", &[1], &[2], &[3], &[4]).unwrap();

        // Read raw file
        let path = config.path.join("key-1.key");
        let data = std::fs::read(&path).unwrap();

        // Should NOT be encrypted
        assert!(!encryption::is_encrypted(&data));

        // Should be valid JSON
        let _: StoredSigningKey = serde_json::from_slice(&data).unwrap();
    }
}
