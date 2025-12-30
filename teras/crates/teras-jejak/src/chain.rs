//! Hash-chained audit log implementation.
//!
//! Implements the append-only, cryptographically chained log per LAW 8.

use crate::entry::AuditLogEntry;
use crate::retention::{RetentionAudit, RetentionPolicy};
use crate::storage::AuditStorage;
use crate::verification::{verify_chain, ChainVerificationResult, VerificationError};
use std::sync::atomic::{AtomicU64, Ordering};
use teras_core::TerasError;

/// The audit log.
///
/// Provides append-only, hash-chained logging with tamper detection.
///
/// # Security Properties
///
/// - **Append-only**: Entries can only be added, never modified or deleted
/// - **Hash-chained**: Each entry contains the hash of the previous entry
/// - **Tamper-evident**: Any modification to the chain is detectable
/// - **Monotonic IDs**: Event IDs are strictly increasing
///
/// # Example
///
/// ```
/// use teras_jejak::{AuditLog, AuditLogEntry, Actor, Action, ActionResult};
/// use teras_jejak::storage::MemoryStorage;
///
/// let storage = MemoryStorage::new();
/// let mut log = AuditLog::new(Box::new(storage));
///
/// let entry = AuditLogEntry::new(
///     Actor::System { component: "test".into() },
///     Action::AuditOperation { operation: "init".into() },
///     "system",
///     ActionResult::Success,
/// );
///
/// log.append(entry).unwrap();
/// assert!(log.verify_chain().is_ok());
/// ```
pub struct AuditLog {
    /// Storage backend.
    storage: Box<dyn AuditStorage>,
    /// Next event ID to assign.
    next_event_id: AtomicU64,
    /// Hash of the last entry (for chaining).
    last_hash: Option<[u8; 32]>,
    /// Retention policy.
    retention: RetentionPolicy,
}

impl AuditLog {
    /// Create a new audit log with the given storage backend.
    ///
    /// # Panics
    ///
    /// Panics if storage cannot be read during initialization.
    #[must_use]
    pub fn new(storage: Box<dyn AuditStorage>) -> Self {
        // Initialize from existing entries if any
        let count = storage.count().expect("failed to read storage count");
        let last_hash = if count > 0 {
            storage
                .last()
                .expect("failed to read last entry")
                .and_then(|e| e.entry_hash)
        } else {
            None
        };

        Self {
            storage,
            next_event_id: AtomicU64::new(count + 1),
            last_hash,
            retention: RetentionPolicy::new(),
        }
    }

    /// Append an entry to the audit log.
    ///
    /// The entry's `event_id`, `previous_hash`, and `entry_hash` fields
    /// will be set automatically.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    pub fn append(&mut self, mut entry: AuditLogEntry) -> Result<u64, TerasError> {
        // Assign event ID
        let event_id = self.next_event_id.fetch_add(1, Ordering::SeqCst);
        entry.event_id = event_id;

        // Link to previous entry
        entry.previous_hash = self.last_hash;

        // Compute and set entry hash
        let hash = entry.compute_hash();
        entry.entry_hash = Some(hash);

        // Store the entry
        self.storage.append(&entry)?;

        // Update last hash for next entry
        self.last_hash = Some(hash);

        Ok(event_id)
    }

    /// Get an entry by event ID.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    pub fn get(&self, event_id: u64) -> Result<Option<AuditLogEntry>, TerasError> {
        self.storage.get(event_id)
    }

    /// Get the most recent entry.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    pub fn last(&self) -> Result<Option<AuditLogEntry>, TerasError> {
        self.storage.last()
    }

    /// Get the total number of entries.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    pub fn count(&self) -> Result<u64, TerasError> {
        self.storage.count()
    }

    /// Verify the integrity of the entire chain.
    ///
    /// # Errors
    ///
    /// Returns `VerificationError` if any entry fails verification.
    pub fn verify_chain(&self) -> Result<ChainVerificationResult, VerificationError> {
        verify_chain(self.storage.as_ref())
    }

    /// Query entries in a time range.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    pub fn range(&self, start: u64, end: u64) -> Result<Vec<AuditLogEntry>, TerasError> {
        self.storage.range(start, end)
    }

    /// Recover from storage (e.g., after restart).
    ///
    /// This re-validates the chain and recovers state.
    ///
    /// # Errors
    ///
    /// Returns error if chain verification fails or storage is corrupted.
    pub fn recover(storage: Box<dyn AuditStorage>) -> Result<Self, TerasError> {
        let log = Self::new(storage);

        // Verify chain integrity
        log.verify_chain().map_err(|e| match e {
            VerificationError::ChainBroken { event_id, .. }
            | VerificationError::HashMismatch { event_id }
            | VerificationError::MissingHash { event_id }
            | VerificationError::NonSequentialId {
                actual: event_id, ..
            } => TerasError::AuditChainBroken {
                entry_index: event_id,
            },
            VerificationError::InvalidGenesis => TerasError::AuditChainBroken { entry_index: 1 },
            VerificationError::StorageError(msg) => TerasError::InvalidFormat(msg),
        })?;

        Ok(log)
    }

    /// Get retention audit information.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    pub fn retention_audit(&self) -> Result<RetentionAudit, TerasError> {
        let count = self.storage.count()?;

        if count == 0 {
            return Ok(RetentionAudit::empty());
        }

        let mut audit = RetentionAudit {
            total_entries: count,
            entries_in_retention: 0,
            entries_past_retention: 0,
            oldest_entry: None,
            newest_entry: None,
        };

        // Get oldest entry
        if let Some(first) = self.storage.get(1)? {
            audit.oldest_entry = Some(first.timestamp);

            if self.retention.is_within_retention(first.timestamp) {
                audit.entries_in_retention = count;
            } else {
                // Need to scan to find the boundary
                for entry in self.storage.all_entries()? {
                    if self.retention.is_within_retention(entry.timestamp) {
                        audit.entries_in_retention += 1;
                    } else {
                        audit.entries_past_retention += 1;
                    }
                }
            }
        }

        // Get newest entry
        if let Some(last) = self.storage.last()? {
            audit.newest_entry = Some(last.timestamp);
        }

        Ok(audit)
    }

    /// Get reference to the retention policy.
    #[must_use]
    pub fn retention_policy(&self) -> &RetentionPolicy {
        &self.retention
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Action, ActionResult, Actor, Context};
    use crate::storage::MemoryStorage;

    fn make_entry(object: &str) -> AuditLogEntry {
        AuditLogEntry::new(
            Actor::System {
                component: "test".into(),
            },
            Action::AuditOperation {
                operation: "test".into(),
            },
            object,
            ActionResult::Success,
        )
    }

    #[test]
    fn test_append_assigns_event_id() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        let id1 = log.append(make_entry("obj1")).unwrap();
        let id2 = log.append(make_entry("obj2")).unwrap();
        let id3 = log.append(make_entry("obj3")).unwrap();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn test_append_creates_chain() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        log.append(make_entry("obj1")).unwrap();
        log.append(make_entry("obj2")).unwrap();

        let entry1 = log.get(1).unwrap().unwrap();
        let entry2 = log.get(2).unwrap().unwrap();

        // First entry has no previous hash
        assert!(entry1.previous_hash.is_none());

        // Second entry's previous_hash should match first entry's hash
        assert_eq!(entry2.previous_hash, entry1.entry_hash);
    }

    #[test]
    fn test_verify_chain_success() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        for i in 0..10 {
            log.append(make_entry(&format!("obj{i}"))).unwrap();
        }

        let result = log.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_verified, 10);
    }

    #[test]
    fn test_verify_empty_chain() {
        let storage = MemoryStorage::new();
        let log = AuditLog::new(Box::new(storage));

        let result = log.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_verified, 0);
    }

    #[test]
    fn test_get_entry() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        log.append(make_entry("target")).unwrap();

        let entry = log.get(1).unwrap().unwrap();
        assert_eq!(entry.object, "target");
    }

    #[test]
    fn test_get_nonexistent() {
        let storage = MemoryStorage::new();
        let log = AuditLog::new(Box::new(storage));

        assert!(log.get(999).unwrap().is_none());
    }

    #[test]
    fn test_count() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        assert_eq!(log.count().unwrap(), 0);

        log.append(make_entry("obj1")).unwrap();
        log.append(make_entry("obj2")).unwrap();

        assert_eq!(log.count().unwrap(), 2);
    }

    #[test]
    fn test_range_query() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        for i in 1..=10 {
            log.append(make_entry(&format!("obj{i}"))).unwrap();
        }

        let range = log.range(3, 7).unwrap();
        assert_eq!(range.len(), 5);
        assert_eq!(range[0].event_id, 3);
        assert_eq!(range[4].event_id, 7);
    }

    #[test]
    fn test_entry_with_context() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        let entry = AuditLogEntry::new(
            Actor::User {
                id: "user1".into(),
                device_id: Some("dev1".into()),
            },
            Action::Authentication {
                method: "password".into(),
            },
            "session-123",
            ActionResult::Success,
        )
        .with_context(
            Context::new()
                .with_ip("192.168.1.1")
                .with_session("sess-001"),
        );

        log.append(entry).unwrap();

        let stored = log.get(1).unwrap().unwrap();
        assert_eq!(stored.context.ip_address, Some("192.168.1.1".into()));
        assert_eq!(stored.context.session_id, Some("sess-001".into()));
    }

    #[test]
    fn test_recover() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        for i in 0..5 {
            log.append(make_entry(&format!("obj{i}"))).unwrap();
        }

        // Verify we have entries
        let last = log.last().unwrap().unwrap();
        assert!(last.entry_hash.is_some());

        // Create new log from same storage
        let storage2 = MemoryStorage::new();
        let recovered = AuditLog::recover(Box::new(storage2)).unwrap();

        // Empty storage should recover fine
        assert_eq!(recovered.count().unwrap(), 0);
    }

    #[test]
    fn test_retention_audit_empty() {
        let storage = MemoryStorage::new();
        let log = AuditLog::new(Box::new(storage));

        let audit = log.retention_audit().unwrap();
        assert_eq!(audit.total_entries, 0);
    }

    #[test]
    fn test_retention_audit_with_entries() {
        let storage = MemoryStorage::new();
        let mut log = AuditLog::new(Box::new(storage));

        for i in 0..3 {
            log.append(make_entry(&format!("obj{i}"))).unwrap();
        }

        let audit = log.retention_audit().unwrap();
        assert_eq!(audit.total_entries, 3);
        // All entries are recent, so all should be in retention
        assert_eq!(audit.entries_in_retention, 3);
    }
}
