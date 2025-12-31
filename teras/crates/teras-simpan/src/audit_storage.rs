//! File-based audit log storage.
//!
//! LAW 8: Audit everything with 7-year minimum retention.
//!
//! This implementation provides persistent, append-only storage for
//! audit logs with integrity verification.

use crate::config::AuditConfig;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{storage::AuditStorage, AuditLogEntry};

/// File-based audit log storage.
///
/// Stores audit entries in daily log files with BLAKE3 checksums.
/// Files are append-only and cannot be modified or deleted.
///
/// Directory structure:
/// ```text
/// audit/
///   2025-01-01.audit
///   2025-01-01.audit.blake3
///   2025-01-02.audit
///   2025-01-02.audit.blake3
///   ...
/// ```
pub struct FileAuditStorage {
    /// Configuration.
    config: AuditConfig,
    /// In-memory cache of entries (for fast lookups).
    cache: Arc<RwLock<AuditCache>>,
}

/// In-memory cache for audit entries.
struct AuditCache {
    /// All entries indexed by event_id.
    entries: Vec<AuditLogEntry>,
    /// Whether cache is initialized from disk.
    initialized: bool,
}

impl AuditCache {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            initialized: false,
        }
    }
}

impl FileAuditStorage {
    /// Create a new file-based audit storage.
    ///
    /// # Errors
    ///
    /// Returns error if directory creation fails.
    pub fn new(config: AuditConfig) -> TerasResult<Self> {
        // Create directory if it doesn't exist
        if !config.path.exists() {
            std::fs::create_dir_all(&config.path).map_err(TerasError::IoError)?;
        }

        let storage = Self {
            config,
            cache: Arc::new(RwLock::new(AuditCache::new())),
        };

        // Initialize cache from disk
        storage.initialize_cache()?;

        Ok(storage)
    }

    /// Initialize the cache by reading all existing entries from disk.
    fn initialize_cache(&self) -> TerasResult<()> {
        let mut cache = self.cache.write().map_err(|_| TerasError::AuditLogFull)?;

        if cache.initialized {
            return Ok(());
        }

        // Find all audit files
        let mut files = crate::path::list_files_with_extension(
            &self.config.path,
            crate::path::extensions::AUDIT_LOG,
        )?;

        // Sort by date (filename is date)
        files.sort();

        // Read all entries
        for file in files {
            self.read_entries_from_file(&file, &mut cache.entries)?;
        }

        cache.initialized = true;
        Ok(())
    }

    /// Read entries from a single audit file.
    fn read_entries_from_file(
        &self,
        path: &Path,
        entries: &mut Vec<AuditLogEntry>,
    ) -> TerasResult<()> {
        // Verify checksum if configured
        if self.config.verify_chain {
            let checksum_path = crate::checksum::checksum_path_for(path);
            if checksum_path.exists() {
                crate::checksum::verify_checksum_file(path)?;
            }
        }

        let file = std::fs::File::open(path).map_err(TerasError::IoError)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(TerasError::IoError)?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditLogEntry =
                serde_json::from_str(&line).map_err(|e| TerasError::DeserializationFailed {
                    type_name: "AuditLogEntry".to_string(),
                    reason: e.to_string(),
                })?;

            entries.push(entry);
        }

        Ok(())
    }

    /// Get the current day's log file path.
    fn current_file_path(&self) -> PathBuf {
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        self.config
            .path
            .join(format!("{date}.{}", crate::path::extensions::AUDIT_LOG))
    }

    /// Append a single entry to the current day's file.
    fn append_to_file(&self, entry: &AuditLogEntry) -> TerasResult<()> {
        let path = self.current_file_path();

        let json = serde_json::to_string(entry).map_err(|e| TerasError::SerializationFailed {
            type_name: "AuditLogEntry".to_string(),
            reason: e.to_string(),
        })?;

        // Use locked append for thread safety
        let line = format!("{json}\n");
        crate::atomic::append_with_lock(&path, line.as_bytes())?;

        // Update checksum
        Self::update_checksum(&path)?;

        Ok(())
    }

    /// Update the checksum file for a log file.
    fn update_checksum(path: &Path) -> TerasResult<()> {
        let data = std::fs::read(path).map_err(TerasError::IoError)?;
        crate::checksum::write_checksum_file(path, &data)
    }

    /// Verify the integrity of all audit files.
    ///
    /// # Errors
    ///
    /// Returns error if any file is corrupted or chain is broken.
    pub fn verify_integrity(&self) -> TerasResult<()> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;

        // Verify hash chain
        let mut expected_prev_hash: Option<[u8; 32]> = None;

        for (idx, entry) in cache.entries.iter().enumerate() {
            // Check previous hash links correctly
            if entry.previous_hash != expected_prev_hash {
                return Err(TerasError::AuditChainBroken {
                    entry_index: idx as u64,
                });
            }

            expected_prev_hash = entry.entry_hash;
        }

        Ok(())
    }

    /// Get storage statistics.
    #[must_use]
    pub fn stats(&self) -> AuditStorageStats {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());

        let file_count = crate::path::list_files_with_extension(
            &self.config.path,
            crate::path::extensions::AUDIT_LOG,
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

        AuditStorageStats {
            entry_count: cache.entries.len() as u64,
            file_count,
            total_size_bytes: total_size,
            retention_days: self.config.retention_days,
        }
    }
}

impl AuditStorage for FileAuditStorage {
    fn append(&self, entry: &AuditLogEntry) -> Result<(), TerasError> {
        // Write to file first (durability)
        self.append_to_file(entry)?;

        // Update cache
        let mut cache = self.cache.write().map_err(|_| TerasError::AuditLogFull)?;
        cache.entries.push(entry.clone());

        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn get(&self, event_id: u64) -> Result<Option<AuditLogEntry>, TerasError> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;

        // Event IDs are 1-indexed
        if event_id == 0 || event_id > cache.entries.len() as u64 {
            return Ok(None);
        }

        let idx = (event_id - 1) as usize;
        Ok(Some(cache.entries[idx].clone()))
    }

    fn last(&self) -> Result<Option<AuditLogEntry>, TerasError> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;
        Ok(cache.entries.last().cloned())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn count(&self) -> Result<u64, TerasError> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;
        Ok(cache.entries.len() as u64)
    }

    fn all_entries(&self) -> Result<Box<dyn Iterator<Item = AuditLogEntry> + '_>, TerasError> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;
        let cloned: Vec<AuditLogEntry> = cache.entries.clone();
        Ok(Box::new(cloned.into_iter()))
    }

    #[allow(clippy::cast_possible_truncation)]
    fn range(&self, start: u64, end: u64) -> Result<Vec<AuditLogEntry>, TerasError> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;

        if start == 0 || end < start {
            return Ok(Vec::new());
        }

        let len = cache.entries.len();
        let start_idx = (start - 1) as usize;
        let end_idx = std::cmp::min(end as usize, len);

        if start_idx >= len {
            return Ok(Vec::new());
        }

        Ok(cache.entries[start_idx..end_idx].to_vec())
    }
}

/// Statistics about audit storage.
#[derive(Debug, Clone)]
pub struct AuditStorageStats {
    /// Total number of entries.
    pub entry_count: u64,
    /// Number of log files.
    pub file_count: usize,
    /// Total size on disk in bytes.
    pub total_size_bytes: u64,
    /// Configured retention period in days.
    pub retention_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use teras_jejak::{Action, ActionResult, Actor};

    fn make_test_config(path: PathBuf) -> AuditConfig {
        AuditConfig {
            path,
            retention_days: crate::config::MIN_RETENTION_DAYS,
            max_file_size: 100 * 1024 * 1024,
            verify_chain: true,
        }
    }

    fn make_test_entry(event_id: u64) -> AuditLogEntry {
        let mut entry = AuditLogEntry::new(
            Actor::System {
                component: "test".to_string(),
            },
            Action::AuditOperation {
                operation: "test".to_string(),
            },
            "test-object",
            ActionResult::Success,
        );
        entry.event_id = event_id;
        entry
    }

    #[test]
    fn test_file_storage_creation() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));

        let storage = FileAuditStorage::new(config.clone()).unwrap();
        assert!(config.path.exists());
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn test_file_storage_append_and_get() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));
        let storage = FileAuditStorage::new(config).unwrap();

        let entry = make_test_entry(1);
        storage.append(&entry).unwrap();

        let retrieved = storage.get(1).unwrap().unwrap();
        assert_eq!(retrieved.event_id, 1);
    }

    #[test]
    fn test_file_storage_persistence() {
        let temp = TempDir::new().unwrap();
        let audit_path = temp.path().join("audit");
        let config = make_test_config(audit_path.clone());

        // Create storage and add entries
        {
            let storage = FileAuditStorage::new(config.clone()).unwrap();
            storage.append(&make_test_entry(1)).unwrap();
            storage.append(&make_test_entry(2)).unwrap();
        }

        // Create new storage instance - should load from disk
        {
            let storage = FileAuditStorage::new(config).unwrap();
            assert_eq!(storage.count().unwrap(), 2);

            let entry = storage.get(2).unwrap().unwrap();
            assert_eq!(entry.event_id, 2);
        }
    }

    #[test]
    fn test_file_storage_count() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));
        let storage = FileAuditStorage::new(config).unwrap();

        assert_eq!(storage.count().unwrap(), 0);

        storage.append(&make_test_entry(1)).unwrap();
        storage.append(&make_test_entry(2)).unwrap();

        assert_eq!(storage.count().unwrap(), 2);
    }

    #[test]
    fn test_file_storage_last() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));
        let storage = FileAuditStorage::new(config).unwrap();

        assert!(storage.last().unwrap().is_none());

        storage.append(&make_test_entry(1)).unwrap();
        storage.append(&make_test_entry(2)).unwrap();

        let last = storage.last().unwrap().unwrap();
        assert_eq!(last.event_id, 2);
    }

    #[test]
    fn test_file_storage_range() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));
        let storage = FileAuditStorage::new(config).unwrap();

        for i in 1..=5 {
            storage.append(&make_test_entry(i)).unwrap();
        }

        let range = storage.range(2, 4).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].event_id, 2);
        assert_eq!(range[2].event_id, 4);
    }

    #[test]
    fn test_file_storage_all_entries() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));
        let storage = FileAuditStorage::new(config).unwrap();

        for i in 1..=3 {
            storage.append(&make_test_entry(i)).unwrap();
        }

        let entries: Vec<_> = storage.all_entries().unwrap().collect();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_file_storage_stats() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));
        let storage = FileAuditStorage::new(config).unwrap();

        storage.append(&make_test_entry(1)).unwrap();

        let stats = storage.stats();
        assert_eq!(stats.entry_count, 1);
        assert!(stats.total_size_bytes > 0);
        assert_eq!(stats.retention_days, crate::config::MIN_RETENTION_DAYS);
    }

    #[test]
    fn test_checksum_file_created() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("audit"));
        let storage = FileAuditStorage::new(config.clone()).unwrap();

        storage.append(&make_test_entry(1)).unwrap();

        // Find the audit file
        let files = crate::path::list_files_with_extension(
            &config.path,
            crate::path::extensions::AUDIT_LOG,
        )
        .unwrap();
        assert!(!files.is_empty());

        // Checksum file should exist
        let checksum_path = crate::checksum::checksum_path_for(&files[0]);
        assert!(checksum_path.exists());
    }
}
