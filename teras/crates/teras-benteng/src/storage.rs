//! Identity storage trait and implementations.

use crate::types::{IdentityId, IdentityRecord, IdentityStatus};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use teras_core::error::{TerasError, TerasResult};

/// Trait for identity storage backends.
pub trait IdentityStorage: Send + Sync {
    /// Store an identity record.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn store(&self, record: IdentityRecord) -> TerasResult<()>;

    /// Get an identity by ID.
    ///
    /// # Errors
    ///
    /// Returns error if retrieval fails.
    fn get(&self, id: &IdentityId) -> TerasResult<Option<IdentityRecord>>;

    /// Get identities by user ID.
    ///
    /// # Errors
    ///
    /// Returns error if retrieval fails.
    fn get_by_user(&self, user_id: &str) -> TerasResult<Vec<IdentityRecord>>;

    /// Update identity status.
    ///
    /// # Errors
    ///
    /// Returns error if update fails.
    fn update_status(&self, id: &IdentityId, status: IdentityStatus) -> TerasResult<bool>;

    /// Update last verified time.
    ///
    /// # Errors
    ///
    /// Returns error if update fails.
    fn update_verified(&self, id: &IdentityId) -> TerasResult<bool>;

    /// Delete an identity.
    ///
    /// # Errors
    ///
    /// Returns error if deletion fails.
    fn delete(&self, id: &IdentityId) -> TerasResult<bool>;

    /// Check if identity exists.
    fn exists(&self, id: &IdentityId) -> bool;

    /// Count total identities.
    ///
    /// # Errors
    ///
    /// Returns error if count operation fails.
    fn count(&self) -> TerasResult<usize>;
}

/// In-memory identity storage.
///
/// **WARNING:** Not for production - no persistence.
#[derive(Clone)]
pub struct MemoryIdentityStorage {
    records: Arc<RwLock<HashMap<String, IdentityRecord>>>,
}

impl MemoryIdentityStorage {
    /// Create new in-memory storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryIdentityStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityStorage for MemoryIdentityStorage {
    fn store(&self, record: IdentityRecord) -> TerasResult<()> {
        let mut records =
            self.records
                .write()
                .map_err(|_| TerasError::BiometricEnrollmentFailed {
                    reason: "Storage lock failed".to_string(),
                })?;

        records.insert(record.id.as_str().to_string(), record);
        Ok(())
    }

    fn get(&self, id: &IdentityId) -> TerasResult<Option<IdentityRecord>> {
        let records = self
            .records
            .read()
            .map_err(|_| TerasError::BiometricVerificationFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        Ok(records.get(id.as_str()).cloned())
    }

    fn get_by_user(&self, user_id: &str) -> TerasResult<Vec<IdentityRecord>> {
        let records = self
            .records
            .read()
            .map_err(|_| TerasError::BiometricVerificationFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        Ok(records
            .values()
            .filter(|r| r.user_id == user_id)
            .cloned()
            .collect())
    }

    fn update_status(&self, id: &IdentityId, status: IdentityStatus) -> TerasResult<bool> {
        let mut records =
            self.records
                .write()
                .map_err(|_| TerasError::BiometricVerificationFailed {
                    reason: "Storage lock failed".to_string(),
                })?;

        if let Some(record) = records.get_mut(id.as_str()) {
            record.status = status;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn update_verified(&self, id: &IdentityId) -> TerasResult<bool> {
        let mut records =
            self.records
                .write()
                .map_err(|_| TerasError::BiometricVerificationFailed {
                    reason: "Storage lock failed".to_string(),
                })?;

        if let Some(record) = records.get_mut(id.as_str()) {
            record.last_verified_at = Some(chrono::Utc::now());
            record.verification_count += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn delete(&self, id: &IdentityId) -> TerasResult<bool> {
        let mut records =
            self.records
                .write()
                .map_err(|_| TerasError::BiometricVerificationFailed {
                    reason: "Storage lock failed".to_string(),
                })?;

        Ok(records.remove(id.as_str()).is_some())
    }

    fn exists(&self, id: &IdentityId) -> bool {
        self.records
            .read()
            .map(|r| r.contains_key(id.as_str()))
            .unwrap_or(false)
    }

    fn count(&self) -> TerasResult<usize> {
        let records = self
            .records
            .read()
            .map_err(|_| TerasError::BiometricVerificationFailed {
                reason: "Storage lock failed".to_string(),
            })?;

        Ok(records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BiometricType;
    use chrono::Utc;

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
    fn test_store_and_get() {
        let storage = MemoryIdentityStorage::new();
        let record = create_test_record("id-1");

        storage.store(record.clone()).unwrap();

        let retrieved = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
        assert_eq!(retrieved.user_id, "user-1");
    }

    #[test]
    fn test_get_nonexistent() {
        let storage = MemoryIdentityStorage::new();

        let result = storage.get(&IdentityId::new("nonexistent")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_by_user() {
        let storage = MemoryIdentityStorage::new();

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

        let user_b = storage.get_by_user("user-B").unwrap();
        assert_eq!(user_b.len(), 1);

        let user_c = storage.get_by_user("user-C").unwrap();
        assert!(user_c.is_empty());
    }

    #[test]
    fn test_update_status() {
        let storage = MemoryIdentityStorage::new();
        let record = create_test_record("id-1");
        storage.store(record).unwrap();

        let updated = storage
            .update_status(&IdentityId::new("id-1"), IdentityStatus::Suspended)
            .unwrap();
        assert!(updated);

        let retrieved = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
        assert_eq!(retrieved.status, IdentityStatus::Suspended);
    }

    #[test]
    fn test_update_status_nonexistent() {
        let storage = MemoryIdentityStorage::new();

        let updated = storage
            .update_status(&IdentityId::new("nonexistent"), IdentityStatus::Suspended)
            .unwrap();
        assert!(!updated);
    }

    #[test]
    fn test_update_verified() {
        let storage = MemoryIdentityStorage::new();
        let record = create_test_record("id-1");
        storage.store(record).unwrap();

        storage.update_verified(&IdentityId::new("id-1")).unwrap();

        let retrieved = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
        assert!(retrieved.last_verified_at.is_some());
        assert_eq!(retrieved.verification_count, 1);
    }

    #[test]
    fn test_update_verified_increments() {
        let storage = MemoryIdentityStorage::new();
        let record = create_test_record("id-1");
        storage.store(record).unwrap();

        storage.update_verified(&IdentityId::new("id-1")).unwrap();
        storage.update_verified(&IdentityId::new("id-1")).unwrap();
        storage.update_verified(&IdentityId::new("id-1")).unwrap();

        let retrieved = storage.get(&IdentityId::new("id-1")).unwrap().unwrap();
        assert_eq!(retrieved.verification_count, 3);
    }

    #[test]
    fn test_delete() {
        let storage = MemoryIdentityStorage::new();
        let record = create_test_record("id-1");
        storage.store(record).unwrap();

        assert!(storage.exists(&IdentityId::new("id-1")));
        let deleted = storage.delete(&IdentityId::new("id-1")).unwrap();
        assert!(deleted);
        assert!(!storage.exists(&IdentityId::new("id-1")));
    }

    #[test]
    fn test_delete_nonexistent() {
        let storage = MemoryIdentityStorage::new();

        let deleted = storage.delete(&IdentityId::new("nonexistent")).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_exists() {
        let storage = MemoryIdentityStorage::new();
        let record = create_test_record("id-1");

        assert!(!storage.exists(&IdentityId::new("id-1")));
        storage.store(record).unwrap();
        assert!(storage.exists(&IdentityId::new("id-1")));
    }

    #[test]
    fn test_count() {
        let storage = MemoryIdentityStorage::new();

        assert_eq!(storage.count().unwrap(), 0);

        storage.store(create_test_record("id-1")).unwrap();
        assert_eq!(storage.count().unwrap(), 1);

        storage.store(create_test_record("id-2")).unwrap();
        assert_eq!(storage.count().unwrap(), 2);
    }

    #[test]
    fn test_default() {
        let storage = MemoryIdentityStorage::default();
        assert_eq!(storage.count().unwrap(), 0);
    }
}
