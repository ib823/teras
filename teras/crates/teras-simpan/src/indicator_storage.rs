//! File-based threat indicator storage.
//!
//! Stores threat indicators from teras-suap with checksum verification.

use crate::config::IndicatorStorageConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use teras_core::error::{TerasError, TerasResult};

/// Stored threat indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIndicator {
    /// Unique indicator ID.
    pub id: String,
    /// Indicator type (ip, domain, hash, etc.).
    pub indicator_type: String,
    /// The actual indicator value.
    pub value: String,
    /// Threat score (0-100).
    pub threat_score: u8,
    /// Source of the indicator.
    pub source: String,
    /// When the indicator was first seen.
    pub first_seen: DateTime<Utc>,
    /// When the indicator was last updated.
    pub last_updated: DateTime<Utc>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl StoredIndicator {
    /// Create a new stored indicator.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        indicator_type: impl Into<String>,
        value: impl Into<String>,
        threat_score: u8,
        source: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            indicator_type: indicator_type.into(),
            value: value.into(),
            threat_score,
            source: source.into(),
            first_seen: now,
            last_updated: now,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// File-based indicator storage.
///
/// Stores each indicator as a JSON file with BLAKE3 checksum.
pub struct FileIndicatorStorage {
    /// Configuration.
    config: IndicatorStorageConfig,
    /// In-memory cache.
    cache: RwLock<HashMap<String, StoredIndicator>>,
}

impl FileIndicatorStorage {
    /// Create a new file-based indicator storage.
    ///
    /// # Errors
    ///
    /// Returns error if directory creation fails.
    pub fn new(config: IndicatorStorageConfig) -> TerasResult<Self> {
        // Create directory if it doesn't exist
        if !config.path.exists() {
            std::fs::create_dir_all(&config.path).map_err(TerasError::IoError)?;
        }

        let storage = Self {
            config,
            cache: RwLock::new(HashMap::new()),
        };

        // Load existing indicators into cache
        storage.load_cache()?;

        Ok(storage)
    }

    /// Load all indicators into cache.
    fn load_cache(&self) -> TerasResult<()> {
        let files = crate::path::list_files_with_extension(
            &self.config.path,
            crate::path::extensions::INDICATOR,
        )?;

        let mut cache = self.cache.write().map_err(|_| TerasError::AuditLogFull)?;

        for file in files {
            if let Ok(indicator) = self.load_indicator_from_file(&file) {
                cache.insert(indicator.id.clone(), indicator);
            }
        }

        Ok(())
    }

    /// Load a single indicator from file.
    fn load_indicator_from_file(&self, path: &std::path::Path) -> TerasResult<StoredIndicator> {
        // Verify checksum if configured
        if self.config.verify_checksums {
            crate::checksum::verify_checksum_file(path)?;
        }

        let data = std::fs::read(path).map_err(TerasError::IoError)?;

        serde_json::from_slice(&data).map_err(|e| TerasError::DeserializationFailed {
            type_name: "StoredIndicator".to_string(),
            reason: e.to_string(),
        })
    }

    /// Get the file path for an indicator.
    fn indicator_file_path(&self, id: &str) -> PathBuf {
        self.config
            .path
            .join(format!("{}.{}", id, crate::path::extensions::INDICATOR))
    }

    /// Write an indicator to file with checksum.
    fn write_indicator(&self, indicator: &StoredIndicator) -> TerasResult<()> {
        let path = self.indicator_file_path(&indicator.id);

        let json =
            serde_json::to_vec_pretty(indicator).map_err(|e| TerasError::SerializationFailed {
                type_name: "StoredIndicator".to_string(),
                reason: e.to_string(),
            })?;

        if self.config.verify_checksums {
            crate::atomic::atomic_write_with_checksum(&path, &json)
        } else {
            crate::atomic::atomic_write(&path, &json)
        }
    }

    /// Store an indicator.
    ///
    /// # Errors
    ///
    /// Returns error if storage fails.
    pub fn store(&self, indicator: StoredIndicator) -> TerasResult<()> {
        // Write to file first
        self.write_indicator(&indicator)?;

        // Update cache
        let mut cache = self.cache.write().map_err(|_| TerasError::AuditLogFull)?;
        cache.insert(indicator.id.clone(), indicator);

        Ok(())
    }

    /// Get an indicator by ID.
    pub fn get(&self, id: &str) -> TerasResult<Option<StoredIndicator>> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;
        Ok(cache.get(id).cloned())
    }

    /// Get indicators by type.
    pub fn get_by_type(&self, indicator_type: &str) -> TerasResult<Vec<StoredIndicator>> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;

        Ok(cache
            .values()
            .filter(|i| i.indicator_type == indicator_type)
            .cloned()
            .collect())
    }

    /// Search for indicators by value pattern.
    pub fn search(&self, pattern: &str) -> TerasResult<Vec<StoredIndicator>> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;

        Ok(cache
            .values()
            .filter(|i| i.value.contains(pattern))
            .cloned()
            .collect())
    }

    /// Update an indicator's threat score.
    pub fn update_score(&self, id: &str, score: u8) -> TerasResult<bool> {
        let mut cache = self.cache.write().map_err(|_| TerasError::AuditLogFull)?;

        if let Some(indicator) = cache.get_mut(id) {
            indicator.threat_score = score;
            indicator.last_updated = Utc::now();

            // Write to file
            self.write_indicator(indicator)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete an indicator.
    pub fn delete(&self, id: &str) -> TerasResult<bool> {
        let path = self.indicator_file_path(id);

        if !path.exists() {
            return Ok(false);
        }

        if self.config.verify_checksums {
            crate::atomic::atomic_delete_with_checksum(&path)?;
        } else {
            crate::atomic::atomic_delete(&path)?;
        }

        let mut cache = self.cache.write().map_err(|_| TerasError::AuditLogFull)?;
        cache.remove(id);

        Ok(true)
    }

    /// Check if indicator exists.
    #[must_use]
    pub fn exists(&self, id: &str) -> bool {
        self.cache
            .read()
            .map(|c| c.contains_key(id))
            .unwrap_or(false)
    }

    /// Count total indicators.
    pub fn count(&self) -> TerasResult<usize> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;
        Ok(cache.len())
    }

    /// List all indicator IDs.
    pub fn list_ids(&self) -> TerasResult<Vec<String>> {
        let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;
        Ok(cache.keys().cloned().collect())
    }

    /// Cleanup expired indicators based on retention policy.
    ///
    /// # Errors
    ///
    /// Returns error if cleanup fails.
    pub fn cleanup_expired(&self) -> TerasResult<usize> {
        let cutoff = Utc::now()
            - chrono::TimeDelta::try_days(i64::from(self.config.retention_days))
                .unwrap_or_default();

        let mut expired_ids = Vec::new();

        {
            let cache = self.cache.read().map_err(|_| TerasError::AuditLogFull)?;

            for (id, indicator) in cache.iter() {
                if indicator.last_updated < cutoff {
                    expired_ids.push(id.clone());
                }
            }
        }

        let mut count = 0;
        for id in expired_ids {
            if self.delete(&id)? {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Get storage statistics.
    #[must_use]
    pub fn stats(&self) -> IndicatorStorageStats {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());

        let by_type: HashMap<String, usize> = cache.values().fold(HashMap::new(), |mut acc, i| {
            *acc.entry(i.indicator_type.clone()).or_insert(0) += 1;
            acc
        });

        let high_threat = cache.values().filter(|i| i.threat_score >= 80).count();

        IndicatorStorageStats {
            total_count: cache.len(),
            by_type,
            high_threat_count: high_threat,
            retention_days: self.config.retention_days,
        }
    }
}

/// Indicator storage statistics.
#[derive(Debug, Clone)]
pub struct IndicatorStorageStats {
    /// Total number of indicators.
    pub total_count: usize,
    /// Count by indicator type.
    pub by_type: HashMap<String, usize>,
    /// Number of high-threat indicators (score >= 80).
    pub high_threat_count: usize,
    /// Configured retention days.
    pub retention_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_config(path: PathBuf) -> IndicatorStorageConfig {
        IndicatorStorageConfig {
            path,
            verify_checksums: true,
            retention_days: 90,
        }
    }

    #[test]
    fn test_indicator_storage_creation() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));

        let storage = FileIndicatorStorage::new(config.clone()).unwrap();
        assert!(config.path.exists());
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn test_store_and_get() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));
        let storage = FileIndicatorStorage::new(config).unwrap();

        let indicator = StoredIndicator::new("ind-1", "ip", "192.168.1.1", 75, "test");
        storage.store(indicator).unwrap();

        let retrieved = storage.get("ind-1").unwrap().unwrap();
        assert_eq!(retrieved.value, "192.168.1.1");
        assert_eq!(retrieved.threat_score, 75);
    }

    #[test]
    fn test_persistence() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("indicators");
        let config = make_test_config(path.clone());

        // Store indicator
        {
            let storage = FileIndicatorStorage::new(config.clone()).unwrap();
            storage
                .store(StoredIndicator::new(
                    "ind-1", "domain", "evil.com", 90, "test",
                ))
                .unwrap();
        }

        // Load in new instance
        {
            let storage = FileIndicatorStorage::new(config).unwrap();
            assert!(storage.exists("ind-1"));

            let indicator = storage.get("ind-1").unwrap().unwrap();
            assert_eq!(indicator.value, "evil.com");
        }
    }

    #[test]
    fn test_get_by_type() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));
        let storage = FileIndicatorStorage::new(config).unwrap();

        storage
            .store(StoredIndicator::new("ind-1", "ip", "1.2.3.4", 50, "test"))
            .unwrap();
        storage
            .store(StoredIndicator::new("ind-2", "ip", "5.6.7.8", 60, "test"))
            .unwrap();
        storage
            .store(StoredIndicator::new(
                "ind-3", "domain", "bad.com", 70, "test",
            ))
            .unwrap();

        let ips = storage.get_by_type("ip").unwrap();
        assert_eq!(ips.len(), 2);

        let domains = storage.get_by_type("domain").unwrap();
        assert_eq!(domains.len(), 1);
    }

    #[test]
    fn test_search() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));
        let storage = FileIndicatorStorage::new(config).unwrap();

        storage
            .store(StoredIndicator::new(
                "ind-1", "domain", "evil.com", 90, "test",
            ))
            .unwrap();
        storage
            .store(StoredIndicator::new(
                "ind-2",
                "domain",
                "evilsite.org",
                85,
                "test",
            ))
            .unwrap();
        storage
            .store(StoredIndicator::new(
                "ind-3", "domain", "good.com", 10, "test",
            ))
            .unwrap();

        let results = storage.search("evil").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_update_score() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));
        let storage = FileIndicatorStorage::new(config).unwrap();

        storage
            .store(StoredIndicator::new("ind-1", "ip", "1.2.3.4", 50, "test"))
            .unwrap();

        let updated = storage.update_score("ind-1", 95).unwrap();
        assert!(updated);

        let indicator = storage.get("ind-1").unwrap().unwrap();
        assert_eq!(indicator.threat_score, 95);
    }

    #[test]
    fn test_delete() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));
        let storage = FileIndicatorStorage::new(config).unwrap();

        storage
            .store(StoredIndicator::new("ind-1", "ip", "1.2.3.4", 50, "test"))
            .unwrap();
        assert!(storage.exists("ind-1"));

        let deleted = storage.delete("ind-1").unwrap();
        assert!(deleted);
        assert!(!storage.exists("ind-1"));
    }

    #[test]
    fn test_stats() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));
        let storage = FileIndicatorStorage::new(config).unwrap();

        storage
            .store(StoredIndicator::new("ind-1", "ip", "1.2.3.4", 50, "test"))
            .unwrap();
        storage
            .store(StoredIndicator::new("ind-2", "ip", "5.6.7.8", 90, "test"))
            .unwrap();
        storage
            .store(StoredIndicator::new(
                "ind-3", "domain", "bad.com", 85, "test",
            ))
            .unwrap();

        let stats = storage.stats();
        assert_eq!(stats.total_count, 3);
        assert_eq!(stats.by_type.get("ip"), Some(&2));
        assert_eq!(stats.by_type.get("domain"), Some(&1));
        assert_eq!(stats.high_threat_count, 2);
    }

    #[test]
    fn test_checksum_files_created() {
        let temp = TempDir::new().unwrap();
        let config = make_test_config(temp.path().join("indicators"));
        let storage = FileIndicatorStorage::new(config.clone()).unwrap();

        storage
            .store(StoredIndicator::new("ind-1", "ip", "1.2.3.4", 50, "test"))
            .unwrap();

        let checksum_path = config.path.join("ind-1.ind.blake3");
        assert!(checksum_path.exists());
    }
}
