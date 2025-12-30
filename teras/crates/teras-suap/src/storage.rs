//! Indicator storage.
//!
//! Trait and implementations for storing threat indicators.

use crate::indicator::{IndicatorType, ThreatIndicator};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use teras_core::TerasResult;

/// Trait for indicator storage backends.
pub trait IndicatorStorage: Send + Sync {
    /// Store an indicator.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn store(&self, indicator: ThreatIndicator) -> TerasResult<()>;

    /// Store multiple indicators.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn store_batch(&self, indicators: Vec<ThreatIndicator>) -> TerasResult<usize>;

    /// Get indicator by ID.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn get(&self, id: &str) -> TerasResult<Option<ThreatIndicator>>;

    /// Check if a value exists.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn contains(&self, indicator_type: IndicatorType, value: &str) -> TerasResult<bool>;

    /// Get count of stored indicators.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn count(&self) -> TerasResult<usize>;

    /// Search by value prefix.
    ///
    /// # Errors
    ///
    /// Returns error if storage operation fails.
    fn search(&self, query: &str, limit: usize) -> TerasResult<Vec<ThreatIndicator>>;
}

/// In-memory indicator storage for testing and development.
///
/// **WARNING**: Not suitable for production - no persistence.
#[derive(Clone, Default)]
pub struct MemoryIndicatorStorage {
    by_id: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    by_value: Arc<RwLock<HashMap<(IndicatorType, String), String>>>,
}

impl MemoryIndicatorStorage {
    /// Create new in-memory storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_id: Arc::new(RwLock::new(HashMap::new())),
            by_value: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl IndicatorStorage for MemoryIndicatorStorage {
    fn store(&self, indicator: ThreatIndicator) -> TerasResult<()> {
        let id = indicator.id.clone();
        let key = (indicator.indicator_type, indicator.value.clone());

        let mut by_id = self.by_id.write().unwrap();
        let mut by_value = self.by_value.write().unwrap();

        by_value.insert(key, id.clone());
        by_id.insert(id, indicator);

        Ok(())
    }

    fn store_batch(&self, indicators: Vec<ThreatIndicator>) -> TerasResult<usize> {
        let count = indicators.len();
        for indicator in indicators {
            self.store(indicator)?;
        }
        Ok(count)
    }

    fn get(&self, id: &str) -> TerasResult<Option<ThreatIndicator>> {
        let by_id = self.by_id.read().unwrap();
        Ok(by_id.get(id).cloned())
    }

    fn contains(&self, indicator_type: IndicatorType, value: &str) -> TerasResult<bool> {
        let by_value = self.by_value.read().unwrap();
        Ok(by_value.contains_key(&(indicator_type, value.to_string())))
    }

    fn count(&self) -> TerasResult<usize> {
        let by_id = self.by_id.read().unwrap();
        Ok(by_id.len())
    }

    fn search(&self, query: &str, limit: usize) -> TerasResult<Vec<ThreatIndicator>> {
        let by_id = self.by_id.read().unwrap();
        let results: Vec<_> = by_id
            .values()
            .filter(|i| i.value.contains(query))
            .take(limit)
            .cloned()
            .collect();
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_indicator(id: &str, value: &str) -> ThreatIndicator {
        ThreatIndicator::new(id, IndicatorType::Ipv4, value, "test")
    }

    #[test]
    fn test_store_and_get() {
        let storage = MemoryIndicatorStorage::new();
        let indicator = make_indicator("test-1", "1.2.3.4");

        storage.store(indicator.clone()).unwrap();

        let retrieved = storage.get("test-1").unwrap().unwrap();
        assert_eq!(retrieved.value, "1.2.3.4");
    }

    #[test]
    fn test_contains() {
        let storage = MemoryIndicatorStorage::new();
        let indicator = make_indicator("test-1", "1.2.3.4");

        storage.store(indicator).unwrap();

        assert!(storage.contains(IndicatorType::Ipv4, "1.2.3.4").unwrap());
        assert!(!storage.contains(IndicatorType::Ipv4, "5.6.7.8").unwrap());
    }

    #[test]
    fn test_count() {
        let storage = MemoryIndicatorStorage::new();

        assert_eq!(storage.count().unwrap(), 0);

        storage.store(make_indicator("1", "1.1.1.1")).unwrap();
        storage.store(make_indicator("2", "2.2.2.2")).unwrap();

        assert_eq!(storage.count().unwrap(), 2);
    }

    #[test]
    fn test_search() {
        let storage = MemoryIndicatorStorage::new();

        storage.store(make_indicator("1", "192.168.1.1")).unwrap();
        storage.store(make_indicator("2", "192.168.1.2")).unwrap();
        storage.store(make_indicator("3", "10.0.0.1")).unwrap();

        let results = storage.search("192.168", 10).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_batch_store() {
        let storage = MemoryIndicatorStorage::new();
        let indicators = vec![
            make_indicator("1", "1.1.1.1"),
            make_indicator("2", "2.2.2.2"),
            make_indicator("3", "3.3.3.3"),
        ];

        let count = storage.store_batch(indicators).unwrap();
        assert_eq!(count, 3);
        assert_eq!(storage.count().unwrap(), 3);
    }
}
