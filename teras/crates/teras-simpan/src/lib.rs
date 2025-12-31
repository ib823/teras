//! TERAS Persistent Storage (teras-simpan)
//!
//! Provides file-based persistent storage for all TERAS components.
//!
//! # LAW 8 Compliance
//!
//! This crate enforces LAW 8 (7-year audit retention) through:
//! - Configuration validation rejecting retention < 2555 days
//! - Append-only audit log storage
//! - Hash-chained integrity verification
//! - Encrypted at-rest key storage
//!
//! # Storage Backends
//!
//! - [`FileAuditStorage`] - Append-only audit logs with hash chains
//! - [`FileKeyStore`] - Encrypted signing key storage
//! - [`FileIdentityStorage`] - Identity records with checksums
//! - [`FileIndicatorStorage`] - Threat indicators with checksums
//!
//! # Features
//!
//! - **Atomic Operations**: All writes use write-to-temp-then-rename
//! - **Integrity Verification**: BLAKE3 checksums for all stored data
//! - **Encryption at Rest**: AES-256-GCM for sensitive data
//! - **Backup/Restore**: Full backup capability with verification
//!
//! # Example
//!
//! ```no_run
//! use teras_simpan::StorageManager;
//!
//! // Create storage manager with defaults
//! let manager = StorageManager::with_defaults(
//!     "/var/lib/teras",
//!     b"master_password"
//! ).expect("Failed to initialize storage");
//!
//! // Access individual storage backends
//! let audit = manager.audit().expect("Audit not initialized");
//! let keys = manager.keys().expect("Keys not initialized");
//!
//! // Create a backup
//! let backup = manager.create_backup().expect("Backup failed");
//! println!("Created backup: {}", backup.name);
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::type_complexity)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::unused_self)]

pub mod atomic;
pub mod audit_storage;
pub mod backup;
pub mod checksum;
pub mod config;
pub mod encryption;
pub mod identity_storage;
pub mod indicator_storage;
pub mod key_storage;
pub mod manager;
pub mod path;

// Re-export main types
pub use audit_storage::{AuditStorageStats, FileAuditStorage};
pub use backup::{BackupInfo, BackupManager, BackupStats, RestoreInfo, VerifyResult};
pub use config::{
    AuditConfig, BackupConfig, IdentityStorageConfig, IndicatorStorageConfig, KeyStorageConfig,
    StorageConfig, MIN_RETENTION_DAYS,
};
pub use identity_storage::{
    FileIdentityStorage, StorageStats as IdentityStorageStats, VerificationReport,
};
pub use indicator_storage::{FileIndicatorStorage, IndicatorStorageStats, StoredIndicator};
pub use key_storage::{FileKeyStore, StoredKeyMetadata};
pub use manager::{IntegrityReport, StorageManager, StorageStats};
pub use path::{dirs, extensions, StoragePaths};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_manager_full_workflow() {
        let temp = TempDir::new().unwrap();

        // Initialize storage
        let manager = StorageManager::with_defaults(temp.path(), b"test_password").unwrap();

        // Verify LAW 8 compliance
        assert_eq!(manager.config().audit.retention_days, MIN_RETENTION_DAYS);

        // Store a key
        let keys = manager.keys().unwrap();
        keys.store_key("workflow-key", &[1, 2, 3], &[4, 5], &[6, 7], &[8, 9])
            .unwrap();
        assert!(keys.contains("workflow-key"));

        // Store an indicator
        let indicators = manager.indicators().unwrap();
        indicators
            .store(StoredIndicator::new(
                "ind-1",
                "ip",
                "192.168.1.100",
                85,
                "test",
            ))
            .unwrap();

        // Verify integrity
        let report = manager.verify_integrity().unwrap();
        assert!(report.paths_valid);

        // Get stats
        let stats = manager.stats();
        assert_eq!(stats.key_count, 1);
        assert_eq!(stats.indicator_count, 1);

        // Create backup
        let backup = manager.create_backup().unwrap();
        assert!(!backup.name.is_empty());

        // Cleanup
        manager.cleanup().unwrap();
    }

    #[test]
    fn test_law8_minimum_retention() {
        // Verify the constant is correct (7 years * 365 days)
        assert_eq!(MIN_RETENTION_DAYS, 7 * 365);
    }

    #[test]
    fn test_exports_available() {
        // Verify all expected types are exported
        let _ = std::any::TypeId::of::<StorageManager>();
        let _ = std::any::TypeId::of::<StorageConfig>();
        let _ = std::any::TypeId::of::<FileAuditStorage>();
        let _ = std::any::TypeId::of::<FileKeyStore>();
        let _ = std::any::TypeId::of::<FileIdentityStorage>();
        let _ = std::any::TypeId::of::<FileIndicatorStorage>();
        let _ = std::any::TypeId::of::<BackupManager>();
        let _ = std::any::TypeId::of::<StoragePaths>();
    }
}
