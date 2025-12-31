//! Unified storage manager for all TERAS storage backends.
//!
//! Provides a single interface to manage all persistent storage
//! with LAW 8 compliant configuration.

use crate::audit_storage::FileAuditStorage;
use crate::backup::BackupManager;
use crate::config::StorageConfig;
use crate::identity_storage::FileIdentityStorage;
use crate::indicator_storage::FileIndicatorStorage;
use crate::key_storage::FileKeyStore;
use crate::path::StoragePaths;
use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};

/// Unified storage manager.
///
/// Manages all TERAS storage backends through a single interface.
/// Ensures LAW 8 compliance and provides backup/restore capabilities.
pub struct StorageManager {
    /// Configuration.
    config: StorageConfig,
    /// Path utilities.
    paths: StoragePaths,
    /// Audit storage (lazy initialized).
    audit: Option<Arc<FileAuditStorage>>,
    /// Key storage (lazy initialized).
    keys: Option<Arc<FileKeyStore>>,
    /// Identity storage (lazy initialized).
    identities: Option<Arc<FileIdentityStorage>>,
    /// Indicator storage (lazy initialized).
    indicators: Option<Arc<FileIndicatorStorage>>,
    /// Backup manager (lazy initialized).
    backup: Option<Arc<BackupManager>>,
}

impl StorageManager {
    /// Create a new storage manager with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid or LAW 8 requirements
    /// are not met.
    pub fn new(config: StorageConfig) -> TerasResult<Self> {
        // Validate LAW 8 compliance
        config.validate_law8_compliance()?;

        let paths = StoragePaths::new(&config.base_path);
        paths.initialize()?;

        Ok(Self {
            config,
            paths,
            audit: None,
            keys: None,
            identities: None,
            indicators: None,
            backup: None,
        })
    }

    /// Create a storage manager from a configuration file.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or configuration is invalid.
    pub fn from_config_file(path: &std::path::Path) -> TerasResult<Self> {
        let config = StorageConfig::load(path)?;
        Self::new(config)
    }

    /// Create a storage manager with default configuration.
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base directory for all storage
    /// * `password` - Master password for key encryption
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    pub fn with_defaults(
        base_path: impl Into<std::path::PathBuf>,
        password: &[u8],
    ) -> TerasResult<Self> {
        let config = StorageConfig::new(base_path.into());
        let mut manager = Self::new(config)?;

        // Initialize all storage backends
        manager.initialize_all(password)?;

        Ok(manager)
    }

    /// Create a production-ready storage manager.
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base directory for all storage
    /// * `password` - Master password for key encryption
    ///
    /// # Errors
    ///
    /// Returns error if initialization fails.
    pub fn production(
        base_path: impl Into<std::path::PathBuf>,
        password: &[u8],
    ) -> TerasResult<Self> {
        let config = StorageConfig::production(base_path.into());
        let mut manager = Self::new(config)?;

        manager.initialize_all(password)?;

        Ok(manager)
    }

    /// Initialize all storage backends.
    fn initialize_all(&mut self, password: &[u8]) -> TerasResult<()> {
        self.initialize_audit()?;
        self.initialize_keys(password)?;
        self.initialize_identities()?;
        self.initialize_indicators()?;
        self.initialize_backup()?;
        Ok(())
    }

    /// Initialize audit storage.
    fn initialize_audit(&mut self) -> TerasResult<()> {
        let storage = FileAuditStorage::new(self.config.audit.clone())?;
        self.audit = Some(Arc::new(storage));
        Ok(())
    }

    /// Initialize key storage.
    fn initialize_keys(&mut self, password: &[u8]) -> TerasResult<()> {
        let storage = FileKeyStore::new(self.config.keys.clone(), password)?;
        self.keys = Some(Arc::new(storage));
        Ok(())
    }

    /// Initialize identity storage.
    fn initialize_identities(&mut self) -> TerasResult<()> {
        let storage = FileIdentityStorage::new(self.config.identities.clone())?;
        self.identities = Some(Arc::new(storage));
        Ok(())
    }

    /// Initialize indicator storage.
    fn initialize_indicators(&mut self) -> TerasResult<()> {
        let storage = FileIndicatorStorage::new(self.config.indicators.clone())?;
        self.indicators = Some(Arc::new(storage));
        Ok(())
    }

    /// Initialize backup manager.
    fn initialize_backup(&mut self) -> TerasResult<()> {
        let manager = BackupManager::new(self.config.backup.clone())?;
        self.backup = Some(Arc::new(manager));
        Ok(())
    }

    /// Get the storage configuration.
    #[must_use]
    pub fn config(&self) -> &StorageConfig {
        &self.config
    }

    /// Get the storage paths utility.
    #[must_use]
    pub fn paths(&self) -> &StoragePaths {
        &self.paths
    }

    /// Get the audit storage.
    ///
    /// # Errors
    ///
    /// Returns error if audit storage is not initialized.
    pub fn audit(&self) -> TerasResult<Arc<FileAuditStorage>> {
        self.audit.clone().ok_or_else(|| TerasError::ConfigError {
            message: "Audit storage not initialized".to_string(),
        })
    }

    /// Get the key storage.
    ///
    /// # Errors
    ///
    /// Returns error if key storage is not initialized.
    pub fn keys(&self) -> TerasResult<Arc<FileKeyStore>> {
        self.keys.clone().ok_or_else(|| TerasError::ConfigError {
            message: "Key storage not initialized".to_string(),
        })
    }

    /// Get the identity storage.
    ///
    /// # Errors
    ///
    /// Returns error if identity storage is not initialized.
    pub fn identities(&self) -> TerasResult<Arc<FileIdentityStorage>> {
        self.identities
            .clone()
            .ok_or_else(|| TerasError::ConfigError {
                message: "Identity storage not initialized".to_string(),
            })
    }

    /// Get the indicator storage.
    ///
    /// # Errors
    ///
    /// Returns error if indicator storage is not initialized.
    pub fn indicators(&self) -> TerasResult<Arc<FileIndicatorStorage>> {
        self.indicators
            .clone()
            .ok_or_else(|| TerasError::ConfigError {
                message: "Indicator storage not initialized".to_string(),
            })
    }

    /// Get the backup manager.
    ///
    /// # Errors
    ///
    /// Returns error if backup manager is not initialized.
    pub fn backup(&self) -> TerasResult<Arc<BackupManager>> {
        self.backup.clone().ok_or_else(|| TerasError::ConfigError {
            message: "Backup manager not initialized".to_string(),
        })
    }

    /// Create a full backup of all storage.
    ///
    /// # Errors
    ///
    /// Returns error if backup fails.
    pub fn create_backup(&self) -> TerasResult<crate::backup::BackupInfo> {
        let backup = self.backup()?;
        backup.create_backup(&self.config.base_path, &[])
    }

    /// Restore from a backup.
    ///
    /// # Arguments
    ///
    /// * `backup_name` - Name of the backup to restore
    ///
    /// # Errors
    ///
    /// Returns error if restore fails.
    pub fn restore_backup(&self, backup_name: &str) -> TerasResult<crate::backup::RestoreInfo> {
        let backup = self.backup()?;
        backup.restore_backup(backup_name, &self.config.base_path)
    }

    /// Verify all storage integrity.
    ///
    /// # Errors
    ///
    /// Returns error if verification fails.
    pub fn verify_integrity(&self) -> TerasResult<IntegrityReport> {
        let mut report = IntegrityReport::default();

        // Verify audit storage
        if let Some(audit) = &self.audit {
            match audit.verify_integrity() {
                Ok(()) => report.audit_valid = true,
                Err(e) => report.errors.push(format!("Audit: {e}")),
            }
        }

        // Verify identity storage
        if let Some(identities) = &self.identities {
            match identities.verify_integrity() {
                Ok(r) => {
                    report.identity_valid = r.is_valid();
                    if !r.is_valid() {
                        for path in r.corrupted {
                            report.errors.push(format!("Identity corrupted: {path}"));
                        }
                    }
                }
                Err(e) => report.errors.push(format!("Identity: {e}")),
            }
        }

        // Verify paths exist
        match self.paths.verify() {
            Ok(()) => report.paths_valid = true,
            Err(e) => report.errors.push(format!("Paths: {e}")),
        }

        report.valid = report.audit_valid && report.identity_valid && report.paths_valid;

        Ok(report)
    }

    /// Get comprehensive storage statistics.
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        let audit_stats = self.audit.as_ref().map(|a| a.stats());
        let identity_stats = self.identities.as_ref().map(|i| i.stats());
        let indicator_stats = self.indicators.as_ref().map(|i| i.stats());
        let backup_stats = self.backup.as_ref().map(|b| b.stats());
        let key_count = self.keys.as_ref().map(|k| k.count()).unwrap_or(0);

        StorageStats {
            audit_entries: audit_stats.as_ref().map(|s| s.entry_count).unwrap_or(0),
            identity_count: identity_stats.as_ref().map(|s| s.record_count).unwrap_or(0),
            indicator_count: indicator_stats.as_ref().map(|s| s.total_count).unwrap_or(0),
            key_count,
            backup_count: backup_stats.as_ref().map(|s| s.backup_count).unwrap_or(0),
            retention_days: self.config.audit.retention_days,
        }
    }

    /// Save the current configuration to file.
    ///
    /// # Errors
    ///
    /// Returns error if save fails.
    pub fn save_config(&self) -> TerasResult<()> {
        let config_path = self.paths.config_file();
        self.config.save(&config_path)
    }

    /// Cleanup temporary files.
    ///
    /// # Errors
    ///
    /// Returns error if cleanup fails.
    pub fn cleanup(&self) -> TerasResult<()> {
        self.paths.cleanup_temp()
    }
}

/// Report from integrity verification.
#[derive(Debug, Clone, Default)]
pub struct IntegrityReport {
    /// Overall validity.
    pub valid: bool,
    /// Audit storage valid.
    pub audit_valid: bool,
    /// Identity storage valid.
    pub identity_valid: bool,
    /// Path structure valid.
    pub paths_valid: bool,
    /// Error messages.
    pub errors: Vec<String>,
}

/// Comprehensive storage statistics.
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Number of audit entries.
    pub audit_entries: u64,
    /// Number of identity records.
    pub identity_count: usize,
    /// Number of threat indicators.
    pub indicator_count: usize,
    /// Number of stored keys.
    pub key_count: usize,
    /// Number of backups.
    pub backup_count: usize,
    /// Configured retention period in days.
    pub retention_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_manager_creation() {
        let temp = TempDir::new().unwrap();
        let config = StorageConfig::new(temp.path().to_path_buf());

        let _manager = StorageManager::new(config).unwrap();

        // Paths should be initialized
        assert!(temp.path().join("audit").exists());
        assert!(temp.path().join("keys").exists());
        assert!(temp.path().join("identities").exists());
    }

    #[test]
    fn test_storage_manager_with_defaults() {
        let temp = TempDir::new().unwrap();

        let manager = StorageManager::with_defaults(temp.path(), b"password").unwrap();

        // All storage backends should be initialized
        assert!(manager.audit().is_ok());
        assert!(manager.keys().is_ok());
        assert!(manager.identities().is_ok());
        assert!(manager.indicators().is_ok());
        assert!(manager.backup().is_ok());
    }

    #[test]
    fn test_storage_manager_production() {
        let temp = TempDir::new().unwrap();

        let manager = StorageManager::production(temp.path(), b"password").unwrap();

        assert!(manager.config().keys.encrypt_at_rest);
        assert!(manager.config().backup.enabled);
    }

    #[test]
    fn test_storage_manager_stats() {
        let temp = TempDir::new().unwrap();
        let manager = StorageManager::with_defaults(temp.path(), b"password").unwrap();

        let stats = manager.stats();

        assert_eq!(stats.audit_entries, 0);
        assert_eq!(stats.identity_count, 0);
        assert_eq!(stats.indicator_count, 0);
        assert_eq!(stats.key_count, 0);
        assert_eq!(stats.retention_days, crate::config::MIN_RETENTION_DAYS);
    }

    #[test]
    fn test_storage_manager_verify_integrity() {
        let temp = TempDir::new().unwrap();
        let manager = StorageManager::with_defaults(temp.path(), b"password").unwrap();

        let report = manager.verify_integrity().unwrap();

        assert!(report.valid);
        assert!(report.paths_valid);
    }

    #[test]
    fn test_storage_manager_save_config() {
        let temp = TempDir::new().unwrap();
        let manager = StorageManager::with_defaults(temp.path(), b"password").unwrap();

        manager.save_config().unwrap();

        let config_path = manager.paths().config_file();
        assert!(config_path.exists());
    }

    #[test]
    fn test_storage_manager_cleanup() {
        let temp = TempDir::new().unwrap();
        let manager = StorageManager::with_defaults(temp.path(), b"password").unwrap();

        // Create a temp file
        let temp_file = manager.paths().temp_file("test.tmp");
        std::fs::write(&temp_file, b"temp").unwrap();
        assert!(temp_file.exists());

        // Cleanup should remove it
        manager.cleanup().unwrap();
        assert!(!temp_file.exists());
    }

    #[test]
    fn test_law8_violation_rejected() {
        let temp = TempDir::new().unwrap();
        let mut config = StorageConfig::new(temp.path().to_path_buf());
        config.audit.retention_days = 30; // Invalid - less than 7 years

        let result = StorageManager::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_and_list_backup() {
        let temp = TempDir::new().unwrap();
        let manager = StorageManager::with_defaults(temp.path(), b"password").unwrap();

        // Create some test data
        let keys = manager.keys().unwrap();
        keys.store_key("test-key", &[1], &[2], &[3], &[4]).unwrap();

        // Create backup
        let backup_info = manager.create_backup().unwrap();
        assert!(!backup_info.name.is_empty());

        // List backups
        let backup_mgr = manager.backup().unwrap();
        let backups = backup_mgr.list_backups().unwrap();
        assert_eq!(backups.len(), 1);
    }
}
