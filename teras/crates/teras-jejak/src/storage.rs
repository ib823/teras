//! Storage backends for audit logs.
//!
//! Provides the `AuditStorage` trait and implementations.

use crate::entry::AuditLogEntry;
use std::sync::{Arc, RwLock};
use teras_core::TerasError;

/// Storage backend trait for audit logs.
///
/// Implementations MUST guarantee:
/// - Append-only semantics (no delete, no modify)
/// - Durability appropriate to the backend
/// - Thread-safe access
pub trait AuditStorage: Send + Sync {
    /// Append an entry to storage.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn append(&self, entry: &AuditLogEntry) -> Result<(), TerasError>;

    /// Get entry by event ID.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn get(&self, event_id: u64) -> Result<Option<AuditLogEntry>, TerasError>;

    /// Get the last entry in the log.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn last(&self) -> Result<Option<AuditLogEntry>, TerasError>;

    /// Get total number of entries.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn count(&self) -> Result<u64, TerasError>;

    /// Get all entries in order.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn all_entries(&self) -> Result<Box<dyn Iterator<Item = AuditLogEntry> + '_>, TerasError>;

    /// Get entries in a range (inclusive).
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn range(&self, start: u64, end: u64) -> Result<Vec<AuditLogEntry>, TerasError>;
}

/// In-memory storage for testing and development.
///
/// NOT suitable for production use - data is lost on restart.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    entries: Arc<RwLock<Vec<AuditLogEntry>>>,
}

impl MemoryStorage {
    /// Create a new empty memory storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl AuditStorage for MemoryStorage {
    fn append(&self, entry: &AuditLogEntry) -> Result<(), TerasError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| TerasError::InvalidFormat("storage lock poisoned".into()))?;
        entries.push(entry.clone());
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn get(&self, event_id: u64) -> Result<Option<AuditLogEntry>, TerasError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| TerasError::InvalidFormat("storage lock poisoned".into()))?;

        // Event IDs are 1-indexed
        // Safe truncation: we check bounds against entries.len() first
        let len = entries.len();
        if event_id == 0 || event_id > len as u64 {
            return Ok(None);
        }

        let idx = (event_id - 1) as usize;
        Ok(Some(entries[idx].clone()))
    }

    fn last(&self) -> Result<Option<AuditLogEntry>, TerasError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| TerasError::InvalidFormat("storage lock poisoned".into()))?;
        Ok(entries.last().cloned())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn count(&self) -> Result<u64, TerasError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| TerasError::InvalidFormat("storage lock poisoned".into()))?;
        Ok(entries.len() as u64)
    }

    fn all_entries(&self) -> Result<Box<dyn Iterator<Item = AuditLogEntry> + '_>, TerasError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| TerasError::InvalidFormat("storage lock poisoned".into()))?;

        // Clone entries to avoid holding lock during iteration
        let cloned: Vec<AuditLogEntry> = entries.clone();
        Ok(Box::new(cloned.into_iter()))
    }

    #[allow(clippy::cast_possible_truncation)]
    fn range(&self, start: u64, end: u64) -> Result<Vec<AuditLogEntry>, TerasError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| TerasError::InvalidFormat("storage lock poisoned".into()))?;

        if start == 0 || end < start {
            return Ok(Vec::new());
        }

        let len = entries.len();
        // Safe truncation: we clamp to entries.len()
        let start_idx = (start - 1) as usize;
        let end_idx = std::cmp::min(end as usize, len);

        if start_idx >= len {
            return Ok(Vec::new());
        }

        Ok(entries[start_idx..end_idx].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Action, ActionResult, Actor};

    fn make_test_entry() -> AuditLogEntry {
        AuditLogEntry::new(
            Actor::System {
                component: "test".into(),
            },
            Action::AuditOperation {
                operation: "test".into(),
            },
            "test-object",
            ActionResult::Success,
        )
    }

    #[test]
    fn test_memory_storage_append_and_get() {
        let storage = MemoryStorage::new();
        let mut entry = make_test_entry();
        entry.event_id = 1;

        storage.append(&entry).unwrap();

        let retrieved = storage.get(1).unwrap().unwrap();
        assert_eq!(retrieved.event_id, 1);
    }

    #[test]
    fn test_memory_storage_count() {
        let storage = MemoryStorage::new();

        assert_eq!(storage.count().unwrap(), 0);

        let mut entry1 = make_test_entry();
        entry1.event_id = 1;
        storage.append(&entry1).unwrap();

        let mut entry2 = make_test_entry();
        entry2.event_id = 2;
        storage.append(&entry2).unwrap();

        assert_eq!(storage.count().unwrap(), 2);
    }

    #[test]
    fn test_memory_storage_last() {
        let storage = MemoryStorage::new();

        assert!(storage.last().unwrap().is_none());

        let mut entry1 = make_test_entry();
        entry1.event_id = 1;
        storage.append(&entry1).unwrap();

        let mut entry2 = make_test_entry();
        entry2.event_id = 2;
        storage.append(&entry2).unwrap();

        let last = storage.last().unwrap().unwrap();
        assert_eq!(last.event_id, 2);
    }

    #[test]
    fn test_memory_storage_range() {
        let storage = MemoryStorage::new();

        for i in 1..=5 {
            let mut entry = make_test_entry();
            entry.event_id = i;
            storage.append(&entry).unwrap();
        }

        let range = storage.range(2, 4).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].event_id, 2);
        assert_eq!(range[2].event_id, 4);
    }

    #[test]
    fn test_memory_storage_all_entries() {
        let storage = MemoryStorage::new();

        for i in 1..=3 {
            let mut entry = make_test_entry();
            entry.event_id = i;
            storage.append(&entry).unwrap();
        }

        let entries: Vec<_> = storage.all_entries().unwrap().collect();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_get_nonexistent() {
        let storage = MemoryStorage::new();
        assert!(storage.get(999).unwrap().is_none());
        assert!(storage.get(0).unwrap().is_none());
    }
}
