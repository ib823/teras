//! Storage configuration with LAW 8 retention enforcement.
//!
//! LAW 8: Audit everything - 7-year minimum retention.
//!
//! This module provides TOML-based configuration for persistent storage
//! with mandatory retention period enforcement.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use teras_core::error::{TerasError, TerasResult};

/// Minimum retention period in days (7 years).
/// LAW 8: This is a hard requirement that cannot be reduced.
pub const MIN_RETENTION_DAYS: u32 = 7 * 365; // 2555 days

/// Default backup interval in hours.
pub const DEFAULT_BACKUP_INTERVAL_HOURS: u32 = 24;

/// Storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for all storage.
    pub base_path: PathBuf,

    /// Audit log configuration.
    pub audit: AuditConfig,

    /// Key storage configuration.
    pub keys: KeyStorageConfig,

    /// Identity storage configuration.
    pub identities: IdentityStorageConfig,

    /// Threat indicator storage configuration.
    pub indicators: IndicatorStorageConfig,

    /// Backup configuration.
    pub backup: BackupConfig,
}

impl StorageConfig {
    /// Create a new storage configuration with the given base path.
    ///
    /// Uses LAW 8 compliant defaults.
    #[must_use]
    pub fn new(base_path: impl AsRef<std::path::Path>) -> Self {
        let base_path = base_path.as_ref();
        Self {
            base_path: base_path.to_path_buf(),
            audit: AuditConfig::default_with_base(base_path),
            keys: KeyStorageConfig::default_with_base(base_path),
            identities: IdentityStorageConfig::default_with_base(base_path),
            indicators: IndicatorStorageConfig::default_with_base(base_path),
            backup: BackupConfig::default_with_base(base_path),
        }
    }

    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or parsed, or if LAW 8
    /// retention requirements are violated.
    pub fn load(path: &std::path::Path) -> TerasResult<Self> {
        let content = std::fs::read_to_string(path).map_err(TerasError::IoError)?;
        let config: Self = toml::from_str(&content).map_err(|e| TerasError::ConfigError {
            message: format!("Failed to parse config: {e}"),
        })?;

        // Validate LAW 8 compliance
        config.validate_law8_compliance()?;

        Ok(config)
    }

    /// Save configuration to a TOML file.
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be written.
    pub fn save(&self, path: &std::path::Path) -> TerasResult<()> {
        // Validate before saving
        self.validate_law8_compliance()?;

        let content = toml::to_string_pretty(self).map_err(|e| TerasError::ConfigError {
            message: format!("Failed to serialize config: {e}"),
        })?;

        std::fs::write(path, content).map_err(TerasError::IoError)?;
        Ok(())
    }

    /// Validate that configuration meets LAW 8 requirements.
    ///
    /// # Errors
    ///
    /// Returns error if retention period is less than 7 years.
    pub fn validate_law8_compliance(&self) -> TerasResult<()> {
        if self.audit.retention_days < MIN_RETENTION_DAYS {
            return Err(TerasError::Law8Violation {
                message: format!(
                    "Audit retention period {} days is less than LAW 8 minimum {} days (7 years)",
                    self.audit.retention_days, MIN_RETENTION_DAYS
                ),
            });
        }

        Ok(())
    }

    /// Create default configuration for production use.
    #[must_use]
    pub fn production(base_path: PathBuf) -> Self {
        let mut config = Self::new(base_path);
        config.keys.encrypt_at_rest = true;
        config.backup.enabled = true;
        config.backup.interval_hours = 6;
        config
    }
}

/// Audit log storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Directory for audit log files.
    pub path: PathBuf,

    /// Retention period in days.
    /// LAW 8: Must be >= 2555 (7 years).
    pub retention_days: u32,

    /// Maximum file size before rotation (bytes).
    pub max_file_size: u64,

    /// Enable hash chain verification.
    pub verify_chain: bool,
}

impl AuditConfig {
    /// Create default audit config with given base path.
    #[must_use]
    pub fn default_with_base(base: &std::path::Path) -> Self {
        Self {
            path: base.join("audit"),
            retention_days: MIN_RETENTION_DAYS,
            max_file_size: 100 * 1024 * 1024, // 100 MB
            verify_chain: true,
        }
    }
}

/// Key storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStorageConfig {
    /// Directory for key files.
    pub path: PathBuf,

    /// Encrypt keys at rest with AES-256-GCM.
    pub encrypt_at_rest: bool,

    /// Key derivation iterations for encryption key.
    pub kdf_iterations: u32,
}

impl KeyStorageConfig {
    /// Create default key storage config with given base path.
    #[must_use]
    pub fn default_with_base(base: &std::path::Path) -> Self {
        Self {
            path: base.join("keys"),
            encrypt_at_rest: true,
            kdf_iterations: 100_000,
        }
    }
}

/// Identity storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStorageConfig {
    /// Directory for identity files.
    pub path: PathBuf,

    /// Include checksums for integrity verification.
    pub verify_checksums: bool,
}

impl IdentityStorageConfig {
    /// Create default identity storage config with given base path.
    #[must_use]
    pub fn default_with_base(base: &std::path::Path) -> Self {
        Self {
            path: base.join("identities"),
            verify_checksums: true,
        }
    }
}

/// Indicator storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorStorageConfig {
    /// Directory for indicator files.
    pub path: PathBuf,

    /// Include checksums for integrity verification.
    pub verify_checksums: bool,

    /// Retention period for indicators (days).
    pub retention_days: u32,
}

impl IndicatorStorageConfig {
    /// Create default indicator storage config with given base path.
    #[must_use]
    pub fn default_with_base(base: &std::path::Path) -> Self {
        Self {
            path: base.join("indicators"),
            verify_checksums: true,
            retention_days: 90, // 90 days for threat indicators
        }
    }
}

/// Backup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Directory for backup files.
    pub path: PathBuf,

    /// Enable automatic backups.
    pub enabled: bool,

    /// Backup interval in hours.
    pub interval_hours: u32,

    /// Number of backups to retain.
    pub retain_count: u32,

    /// Compress backups.
    pub compress: bool,
}

impl BackupConfig {
    /// Create default backup config with given base path.
    #[must_use]
    pub fn default_with_base(base: &std::path::Path) -> Self {
        Self {
            path: base.join("backups"),
            enabled: true,
            interval_hours: DEFAULT_BACKUP_INTERVAL_HOURS,
            retain_count: 30, // Keep 30 backups
            compress: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config_law8_compliant() {
        let temp = TempDir::new().unwrap();
        let config = StorageConfig::new(temp.path().to_path_buf());

        assert!(config.validate_law8_compliance().is_ok());
        assert_eq!(config.audit.retention_days, MIN_RETENTION_DAYS);
    }

    #[test]
    fn test_law8_violation_rejected() {
        let temp = TempDir::new().unwrap();
        let mut config = StorageConfig::new(temp.path().to_path_buf());

        // Attempt to reduce retention below 7 years
        config.audit.retention_days = 365; // 1 year

        let result = config.validate_law8_compliance();
        assert!(result.is_err());

        if let Err(TerasError::Law8Violation { message }) = result {
            assert!(message.contains("less than LAW 8 minimum"));
        } else {
            panic!("Expected Law8Violation error");
        }
    }

    #[test]
    fn test_config_save_load_roundtrip() {
        let temp = TempDir::new().unwrap();
        let config = StorageConfig::new(temp.path().to_path_buf());

        let config_path = temp.path().join("config.toml");
        config.save(&config_path).unwrap();

        let loaded = StorageConfig::load(&config_path).unwrap();
        assert_eq!(loaded.audit.retention_days, config.audit.retention_days);
        assert_eq!(loaded.keys.encrypt_at_rest, config.keys.encrypt_at_rest);
    }

    #[test]
    fn test_production_config() {
        let temp = TempDir::new().unwrap();
        let config = StorageConfig::production(temp.path().to_path_buf());

        assert!(config.keys.encrypt_at_rest);
        assert!(config.backup.enabled);
        assert_eq!(config.backup.interval_hours, 6);
    }

    #[test]
    fn test_config_cannot_save_invalid() {
        let temp = TempDir::new().unwrap();
        let mut config = StorageConfig::new(temp.path().to_path_buf());
        config.audit.retention_days = 30; // Invalid

        let config_path = temp.path().join("config.toml");
        let result = config.save(&config_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_min_retention_days_constant() {
        // 7 years = 7 * 365 = 2555 days
        assert_eq!(MIN_RETENTION_DAYS, 2555);
    }
}
