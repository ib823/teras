//! Directory structure utilities for persistent storage.
//!
//! Provides path management and directory initialization for
//! all storage types.

use std::path::{Path, PathBuf};
use teras_core::error::{TerasError, TerasResult};

/// Standard directory names used by TERAS storage.
pub mod dirs {
    /// Audit log directory.
    pub const AUDIT: &str = "audit";
    /// Key storage directory.
    pub const KEYS: &str = "keys";
    /// Identity storage directory.
    pub const IDENTITIES: &str = "identities";
    /// Threat indicator directory.
    pub const INDICATORS: &str = "indicators";
    /// Backup directory.
    pub const BACKUPS: &str = "backups";
    /// Temporary directory for atomic operations.
    pub const TEMP: &str = ".temp";
}

/// File extensions used by TERAS storage.
pub mod extensions {
    /// Audit log files.
    pub const AUDIT_LOG: &str = "audit";
    /// Encrypted key files.
    pub const KEY: &str = "key";
    /// Identity files.
    pub const IDENTITY: &str = "identity";
    /// Indicator files.
    pub const INDICATOR: &str = "ind";
    /// Checksum files.
    pub const CHECKSUM: &str = "blake3";
    /// Backup archive files.
    pub const BACKUP: &str = "backup";
    /// Configuration files.
    pub const CONFIG: &str = "toml";
}

/// Storage path builder for constructing file paths.
#[derive(Debug, Clone)]
pub struct StoragePaths {
    /// Base directory for all storage.
    base: PathBuf,
}

impl StoragePaths {
    /// Create a new storage paths manager.
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// Get the base directory.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Get the audit logs directory.
    #[must_use]
    pub fn audit_dir(&self) -> PathBuf {
        self.base.join(dirs::AUDIT)
    }

    /// Get the keys directory.
    #[must_use]
    pub fn keys_dir(&self) -> PathBuf {
        self.base.join(dirs::KEYS)
    }

    /// Get the identities directory.
    #[must_use]
    pub fn identities_dir(&self) -> PathBuf {
        self.base.join(dirs::IDENTITIES)
    }

    /// Get the indicators directory.
    #[must_use]
    pub fn indicators_dir(&self) -> PathBuf {
        self.base.join(dirs::INDICATORS)
    }

    /// Get the backups directory.
    #[must_use]
    pub fn backups_dir(&self) -> PathBuf {
        self.base.join(dirs::BACKUPS)
    }

    /// Get the temporary directory.
    #[must_use]
    pub fn temp_dir(&self) -> PathBuf {
        self.base.join(dirs::TEMP)
    }

    /// Get an audit log file path for a given date.
    #[must_use]
    pub fn audit_file(&self, date: &str) -> PathBuf {
        self.audit_dir()
            .join(format!("{date}.{}", extensions::AUDIT_LOG))
    }

    /// Get a key file path for a given key ID.
    #[must_use]
    pub fn key_file(&self, key_id: &str) -> PathBuf {
        self.keys_dir()
            .join(format!("{key_id}.{}", extensions::KEY))
    }

    /// Get an identity file path for a given identity ID.
    #[must_use]
    pub fn identity_file(&self, identity_id: &str) -> PathBuf {
        self.identities_dir()
            .join(format!("{identity_id}.{}", extensions::IDENTITY))
    }

    /// Get an indicator file path for a given indicator ID.
    #[must_use]
    pub fn indicator_file(&self, indicator_id: &str) -> PathBuf {
        self.indicators_dir()
            .join(format!("{indicator_id}.{}", extensions::INDICATOR))
    }

    /// Get a backup file path for a given timestamp.
    #[must_use]
    pub fn backup_file(&self, timestamp: &str) -> PathBuf {
        self.backups_dir()
            .join(format!("{timestamp}.{}", extensions::BACKUP))
    }

    /// Get the config file path.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.base.join(format!("config.{}", extensions::CONFIG))
    }

    /// Get a checksum file path for a given data file.
    #[must_use]
    pub fn checksum_file(&self, data_file: &Path) -> PathBuf {
        let mut path = data_file.to_path_buf();
        let new_ext = format!(
            "{}.{}",
            path.extension().unwrap_or_default().to_string_lossy(),
            extensions::CHECKSUM
        );
        path.set_extension(new_ext);
        path
    }

    /// Get a temporary file path for atomic operations.
    #[must_use]
    pub fn temp_file(&self, name: &str) -> PathBuf {
        self.temp_dir().join(name)
    }

    /// Initialize all storage directories.
    ///
    /// Creates all required directories if they don't exist.
    ///
    /// # Errors
    ///
    /// Returns error if directory creation fails.
    pub fn initialize(&self) -> TerasResult<()> {
        let directories = [
            self.base.clone(),
            self.audit_dir(),
            self.keys_dir(),
            self.identities_dir(),
            self.indicators_dir(),
            self.backups_dir(),
            self.temp_dir(),
        ];

        for dir in &directories {
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(TerasError::IoError)?;
            }
        }

        // Set restrictive permissions on sensitive directories
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let restrictive = std::fs::Permissions::from_mode(0o700);

            for dir in &[self.keys_dir(), self.identities_dir()] {
                std::fs::set_permissions(dir, restrictive.clone()).map_err(TerasError::IoError)?;
            }
        }

        Ok(())
    }

    /// Clean up temporary files.
    ///
    /// Removes all files in the temp directory.
    ///
    /// # Errors
    ///
    /// Returns error if cleanup fails.
    pub fn cleanup_temp(&self) -> TerasResult<()> {
        let temp = self.temp_dir();
        if temp.exists() {
            for entry in std::fs::read_dir(&temp).map_err(TerasError::IoError)? {
                let entry = entry.map_err(TerasError::IoError)?;
                let path = entry.path();
                if path.is_file() {
                    std::fs::remove_file(&path).map_err(TerasError::IoError)?;
                }
            }
        }
        Ok(())
    }

    /// Verify directory structure exists.
    ///
    /// # Errors
    ///
    /// Returns error if any required directory is missing.
    pub fn verify(&self) -> TerasResult<()> {
        let required = [
            self.audit_dir(),
            self.keys_dir(),
            self.identities_dir(),
            self.indicators_dir(),
            self.backups_dir(),
        ];

        for dir in &required {
            if !dir.exists() {
                return Err(TerasError::ConfigError {
                    message: format!("Required directory missing: {}", dir.display()),
                });
            }
        }

        Ok(())
    }
}

/// List all files in a directory with a specific extension.
///
/// # Errors
///
/// Returns error if directory cannot be read.
pub fn list_files_with_extension(dir: &Path, ext: &str) -> TerasResult<Vec<PathBuf>> {
    let mut files = Vec::new();

    if !dir.exists() {
        return Ok(files);
    }

    for entry in std::fs::read_dir(dir).map_err(TerasError::IoError)? {
        let entry = entry.map_err(TerasError::IoError)?;
        let path = entry.path();

        if path.is_file() {
            if let Some(file_ext) = path.extension() {
                if file_ext == ext {
                    files.push(path);
                }
            }
        }
    }

    files.sort();
    Ok(files)
}

/// Extract ID from a storage filename.
///
/// Assumes filename format: `{id}.{extension}`
#[must_use]
pub fn extract_id_from_filename(path: &Path) -> Option<String> {
    path.file_stem().and_then(|s| s.to_str()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_paths_construction() {
        let temp = TempDir::new().unwrap();
        let paths = StoragePaths::new(temp.path());

        assert_eq!(paths.base(), temp.path());
        assert_eq!(paths.audit_dir(), temp.path().join("audit"));
        assert_eq!(paths.keys_dir(), temp.path().join("keys"));
    }

    #[test]
    fn test_file_path_construction() {
        let temp = TempDir::new().unwrap();
        let paths = StoragePaths::new(temp.path());

        let audit = paths.audit_file("2025-01-01");
        assert!(audit.to_string_lossy().contains("2025-01-01.audit"));

        let key = paths.key_file("key-123");
        assert!(key.to_string_lossy().contains("key-123.key"));
    }

    #[test]
    fn test_checksum_file_path() {
        let temp = TempDir::new().unwrap();
        let paths = StoragePaths::new(temp.path());

        let data_file = paths.identity_file("user-1");
        let checksum = paths.checksum_file(&data_file);

        assert!(checksum.to_string_lossy().ends_with(".identity.blake3"));
    }

    #[test]
    fn test_initialize_creates_directories() {
        let temp = TempDir::new().unwrap();
        let paths = StoragePaths::new(temp.path());

        paths.initialize().unwrap();

        assert!(paths.audit_dir().exists());
        assert!(paths.keys_dir().exists());
        assert!(paths.identities_dir().exists());
        assert!(paths.indicators_dir().exists());
        assert!(paths.backups_dir().exists());
        assert!(paths.temp_dir().exists());
    }

    #[test]
    fn test_verify_fails_on_missing_dirs() {
        let temp = TempDir::new().unwrap();
        let paths = StoragePaths::new(temp.path());

        let result = paths.verify();
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_succeeds_after_init() {
        let temp = TempDir::new().unwrap();
        let paths = StoragePaths::new(temp.path());

        paths.initialize().unwrap();
        paths.verify().unwrap();
    }

    #[test]
    fn test_list_files_with_extension() {
        let temp = TempDir::new().unwrap();

        // Create test files
        std::fs::write(temp.path().join("file1.key"), b"test").unwrap();
        std::fs::write(temp.path().join("file2.key"), b"test").unwrap();
        std::fs::write(temp.path().join("file3.txt"), b"test").unwrap();

        let files = list_files_with_extension(temp.path(), "key").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_extract_id_from_filename() {
        let path = Path::new("/some/path/user-123.identity");
        assert_eq!(extract_id_from_filename(path), Some("user-123".to_string()));

        let path = Path::new("key-abc.key");
        assert_eq!(extract_id_from_filename(path), Some("key-abc".to_string()));
    }

    #[test]
    fn test_cleanup_temp() {
        let temp = TempDir::new().unwrap();
        let paths = StoragePaths::new(temp.path());
        paths.initialize().unwrap();

        // Create temp files
        std::fs::write(paths.temp_file("temp1"), b"data").unwrap();
        std::fs::write(paths.temp_file("temp2"), b"data").unwrap();

        assert!(paths.temp_file("temp1").exists());

        paths.cleanup_temp().unwrap();

        assert!(!paths.temp_file("temp1").exists());
        assert!(!paths.temp_file("temp2").exists());
    }
}
