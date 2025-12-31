//! File-based identity storage with checksum verification.
//!
//! LAW 1: Biometrics never leave device - only stores hashes.
//! LAW 8: All operations are logged via audit integration.
//!
//! Each identity is stored as a separate file with a companion checksum.

use crate::config::IdentityStorageConfig;
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use teras_benteng::{IdentityId, IdentityRecord, IdentityStatus, IdentityStorage};
use teras_core::error::{TerasError, TerasResult};

/// File-based identity storage.
///
/// Stores each identity record as a JSON file with BLAKE3 checksum.
///
/// Directory structure:
/// ```text
/// identities/
///   {identity-id}.identity
///   {identity-id}.identity.blake3
///   ...
/// ```
pub struct FileIdentityStorage {
    /// Configuration.
    config: IdentityStorageConfig,
    /// In-memory cache for fast lookups.
    cache: RwLock<HashMap<String, IdentityRecord>>,
}

impl FileIdentityStorage {
    /// Create a new file-based identity storage.
    ///
    /// # Errors
    ///
    /// Returns error if directory creation fails.
    pub fn new(config: IdentityStorageConfig) -> TerasResult<Self> {
        // Create directory if it doesn't exist
        if !config.path.exists() {
            std::fs::create_dir_all(&config.path).map_err(TerasError::IoError)?;
        }

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&config.path, perms).map_err(TerasError::IoError)?;
        }

        let storage = Self {
            config,
            cache: RwLock::new(HashMap::new()),
        };

        // Load existing records into cache
        storage.load_cache()?;

        Ok(storage)
    }

    /// Load all identity records into cache.
    fn load_cache(&self) -> TerasResult<()> {
        let files = crate::path::list_files_with_extension(
            &self.config.path,
            crate::path::extensions::IDENTITY,
        )?;

        let mut cache = self
            .cache
            .write()
            .map_err(|_| TerasError::BiometricEnrollmentFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        for file in files {
            if let Ok(record) = self.load_record_from_file(&file) {
                cache.insert(record.id.as_str().to_string(), record);
            }
        }

        Ok(())
    }

    /// Load a single record from file.
    fn load_record_from_file(&self, path: &std::path::Path) -> TerasResult<IdentityRecord> {
        // Verify checksum if configured
        if self.config.verify_checksums {
            crate::checksum::verify_checksum_file(path)?;
        }

        let data = std::fs::read(path).map_err(TerasError::IoError)?;

        serde_json::from_slice(&data).map_err(|e| TerasError::DeserializationFailed {
            type_name: "IdentityRecord".to_string(),
            reason: e.to_string(),
        })
    }

    /// Get the file path for an identity.
    fn identity_file_path(&self, id: &IdentityId) -> PathBuf {
        self.config.path.join(format!(
            "{}.{}",
            id.as_str(),
            crate::path::extensions::IDENTITY
        ))
    }

    /// Write a record to file with checksum.
    fn write_record(&self, record: &IdentityRecord) -> TerasResult<()> {
        let path = self.identity_file_path(&record.id);

        let json =
            serde_json::to_vec_pretty(record).map_err(|e| TerasError::SerializationFailed {
                type_name: "IdentityRecord".to_string(),
                reason: e.to_string(),
            })?;

        if self.config.verify_checksums {
            crate::atomic::atomic_write_with_checksum(&path, &json)
        } else {
            crate::atomic::atomic_write(&path, &json)
        }
    }

    /// Delete a record file and its checksum.
    fn delete_record_file(&self, id: &IdentityId) -> TerasResult<bool> {
        let path = self.identity_file_path(id);

        if !path.exists() {
            return Ok(false);
        }

        if self.config.verify_checksums {
            crate::atomic::atomic_delete_with_checksum(&path)
        } else {
            crate::atomic::atomic_delete(&path)
        }?;

        Ok(true)
    }

    /// Verify integrity of all stored identities.
    ///
    /// # Errors
    ///
    /// Returns error if any identity file is corrupted.
    pub fn verify_integrity(&self) -> TerasResult<VerificationReport> {
        let files = crate::path::list_files_with_extension(
            &self.config.path,
            crate::path::extensions::IDENTITY,
        )?;

        let mut report = VerificationReport {
            total: files.len(),
            valid: 0,
            corrupted: Vec::new(),
        };

        for file in files {
            match crate::checksum::verify_checksum_file(&file) {
                Ok(()) => report.valid += 1,
                Err(_) => {
                    report.corrupted.push(file.display().to_string());
                }
            }
        }

        Ok(report)
    }

    /// Get storage statistics.
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        let file_count = crate::path::list_files_with_extension(
            &self.config.path,
            crate::path::extensions::IDENTITY,
        )
        .map(|f| f.len())
        .unwrap_or(0);

        let total_size: u64 = std::fs::read_dir(&self.config.path)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0);

        StorageStats {
            record_count: self.cache.read().map(|c| c.len()).unwrap_or(0),
            file_count,
            total_size_bytes: total_size,
        }
    }
}

impl IdentityStorage for FileIdentityStorage {
    fn store(&self, record: IdentityRecord) -> TerasResult<()> {
        // Write to file first (durability)
        self.write_record(&record)?;

        // Update cache
        let mut cache = self
            .cache
            .write()
            .map_err(|_| TerasError::BiometricEnrollmentFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        cache.insert(record.id.as_str().to_string(), record);

        Ok(())
    }

    fn get(&self, id: &IdentityId) -> TerasResult<Option<IdentityRecord>> {
        let cache = self
            .cache
            .read()
            .map_err(|_| TerasError::BiometricVerificationFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        Ok(cache.get(id.as_str()).cloned())
    }

    fn get_by_user(&self, user_id: &str) -> TerasResult<Vec<IdentityRecord>> {
        let cache = self
            .cache
            .read()
            .map_err(|_| TerasError::BiometricVerificationFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        Ok(cache
            .values()
            .filter(|r| r.user_id == user_id)
            .cloned()
            .collect())
    }

    fn update_status(&self, id: &IdentityId, status: IdentityStatus) -> TerasResult<bool> {
        let mut cache =
            self.cache
                .write()
                .map_err(|_| TerasError::BiometricVerificationFailed {
                    reason: "Storage lock failed".to_string(),
                })?;

        if let Some(record) = cache.get_mut(id.as_str()) {
            record.status = status;

            // Write to file
            self.write_record(record)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn update_verified(&self, id: &IdentityId) -> TerasResult<bool> {
        let mut cache =
            self.cache
                .write()
                .map_err(|_| TerasError::BiometricVerificationFailed {
                    reason: "Storage lock failed".to_string(),
                })?;

        if let Some(record) = cache.get_mut(id.as_str()) {
            record.last_verified_at = Some(Utc::now());
            record.verification_count += 1;

            // Write to file
            self.write_record(record)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn delete(&self, id: &IdentityId) -> TerasResult<bool> {
        // Delete file first
        let deleted = self.delete_record_file(id)?;

        if deleted {
            // Update cache
            let mut cache =
                self.cache
                    .write()
                    .map_err(|_| TerasError::BiometricVerificationFailed {
                        reason: "Storage lock failed".to_string(),
                    })?;
            cache.remove(id.as_str());
        }

        Ok(deleted)
    }

    fn exists(&self, id: &IdentityId) -> bool {
        self.cache
            .read()
            .map(|c| c.contains_key(id.as_str()))
            .unwrap_or(false)
    }

    fn count(&self) -> TerasResult<usize> {
        let cache = self
            .cache
            .read()
            .map_err(|_| TerasError::BiometricVerificationFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        Ok(cache.len())
    }
}

/// Report from integrity verification.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Total files checked.
    pub total: usize,
    /// Valid files.
    pub valid: usize,
    /// Corrupted file paths.
    pub corrupted: Vec<String>,
}

impl VerificationReport {
    /// Check if all files are valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.corrupted.is_empty()
    }
}

/// Storage statistics.
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Number of identity records.
    pub record_count: usize,
    /// Number of files (including checksums).
    pub file_count: usize,
    /// Total size on disk in bytes.
    pub total_size_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use teras_benteng::BiometricType;

    fn make_test_config(path: PathBuf) -> IdentityStorageConfig {
        IdentityStorageConfig {
            path,
            verify_checksums: true,
        }
    }

    fn create_test_record(id: &str) -> IdentityRecord {
        IdentityRecord {
            id: IdentityId::new(id),
            user_id: "user-1".to_string(),
            biometric_type: BiometricType::Face,
            template_hash: [0u8; 32],
            device_id: "device-1".to_string(),
            device_public_key: [0u8; 32],
            status: IdentityStatus::Active,
            enrolled_at: Utc::now(),
            last_verified_at: None,
            verification_count: 0,
        }
    }

    #[test]
    fn test_file_storage_creation() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));

        let storage = FileIdentityStorage::new(config.clone()).unwrap();
        assert!(config.path.exists());
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn test_file_storage_store_and_get() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        let record = create_test_record("id-1");
        storage.store(record).unwrap();

        let retrieved = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
        assert_eq!(retrieved.user_id, "user-1");
    }

    #[test]
    fn test_file_storage_persistence() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("identities");
        let config = make_test_config(path.clone());

        // Store record
        {
            let storage = FileIdentityStorage::new(config.clone()).unwrap();
            storage.store(create_test_record("id-1")).unwrap();
        }

        // Load in new instance
        {
            let storage = FileIdentityStorage::new(config).unwrap();
            assert!(storage.exists(&IdentityId::new("id-1")));

            let record = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
            assert_eq!(record.user_id, "user-1");
        }
    }

    #[test]
    fn test_file_storage_get_by_user() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        let mut record1 = create_test_record("id-1");
        record1.user_id = "user-A".to_string();

        let mut record2 = create_test_record("id-2");
        record2.user_id = "user-A".to_string();

        let mut record3 = create_test_record("id-3");
        record3.user_id = "user-B".to_string();

        storage.store(record1).unwrap();
        storage.store(record2).unwrap();
        storage.store(record3).unwrap();

        let user_a = storage.get_by_user("user-A").unwrap();
        assert_eq!(user_a.len(), 2);
    }

    #[test]
    fn test_file_storage_update_status() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        storage.store(create_test_record("id-1")).unwrap();

        let updated = storage
            .update_status(&IdentityId::new("id-1"), IdentityStatus::Suspended)
            .unwrap();
        assert!(updated);

        let record = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
        assert_eq!(record.status, IdentityStatus::Suspended);
    }

    #[test]
    fn test_file_storage_update_verified() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        storage.store(create_test_record("id-1")).unwrap();

        storage.update_verified(&IdentityId::new("id-1")).unwrap();
        storage.update_verified(&IdentityId::new("id-1")).unwrap();

        let record = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
        assert!(record.last_verified_at.is_some());
        assert_eq!(record.verification_count, 2);
    }

    #[test]
    fn test_file_storage_delete() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        storage.store(create_test_record("id-1")).unwrap();
        assert!(storage.exists(&IdentityId::new("id-1")));

        let deleted = storage.delete(&IdentityId::new("id-1")).unwrap();
        assert!(deleted);
        assert!(!storage.exists(&IdentityId::new("id-1")));
    }

    #[test]
    fn test_file_storage_count() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        assert_eq!(storage.count().unwrap(), 0);

        storage.store(create_test_record("id-1")).unwrap();
        storage.store(create_test_record("id-2")).unwrap();

        assert_eq!(storage.count().unwrap(), 2);
    }

    #[test]
    fn test_checksum_files_created() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config.clone()).unwrap();

        storage.store(create_test_record("id-1")).unwrap();

        // Checksum file should exist
        let checksum_path = config.path.join("id-1.identity.blake3");
        assert!(checksum_path.exists());
    }

    #[test]
    fn test_verify_integrity() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        storage.store(create_test_record("id-1")).unwrap();
        storage.store(create_test_record("id-2")).unwrap();

        let report = storage.verify_integrity().unwrap();
        assert!(report.is_valid());
        assert_eq!(report.total, 2);
        assert_eq!(report.valid, 2);
    }

    #[test]
    fn test_verify_integrity_detects_corruption() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config.clone()).unwrap();

        storage.store(create_test_record("id-1")).unwrap();

        // Corrupt the file
        let file_path = config.path.join("id-1.identity");
        std::fs::write(&file_path, b"corrupted").unwrap();

        let report = storage.verify_integrity().unwrap();
        assert!(!report.is_valid());
        assert_eq!(report.corrupted.len(), 1);
    }

    #[test]
    fn test_stats() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("identities"));
        let storage = FileIdentityStorage::new(config).unwrap();

        storage.store(create_test_record("id-1")).unwrap();

        let stats = storage.stats();
        assert_eq!(stats.record_count, 1);
        assert!(stats.total_size_bytes > 0);
    }
}
