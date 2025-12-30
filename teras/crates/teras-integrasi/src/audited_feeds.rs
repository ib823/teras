//! Audited threat feed operations.
//!
//! Wraps teras-suap operations with automatic LAW 8 audit logging.

use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};
use teras_suap::sources::AbuseCh;
use teras_suap::storage::{IndicatorStorage, MemoryIndicatorStorage};
use teras_suap::{FeedManager, FeedSource, ThreatIndicator};

/// Audited threat feed operations.
///
/// Every operation creates an audit log entry per LAW 8.
pub struct AuditedFeeds {
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
    storage: Arc<MemoryIndicatorStorage>,
    manager: FeedManager,
}

impl AuditedFeeds {
    /// Create new audited feeds wrapper.
    pub(crate) fn new(
        audit_log: Arc<std::sync::RwLock<AuditLog>>,
        storage: Arc<MemoryIndicatorStorage>,
    ) -> Self {
        let mut manager = FeedManager::new();

        // Register default sources (REALITY 6)
        manager.register_source(AbuseCh::urlhaus());
        manager.register_source(AbuseCh::feodo());

        Self {
            audit_log,
            storage,
            manager,
        }
    }

    fn log_operation(
        &self,
        operation: &str,
        source: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<u64> {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "teras-suap".to_string(),
            },
            Action::SecurityEvent {
                event_type: format!("feed_{operation}"),
                severity: "info".to_string(),
            },
            format!("feed:{source}"),
            result,
        )
        .with_context(context.unwrap_or_default());

        let mut log = self
            .audit_log
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        log.append(entry)
    }

    /// Fetch all registered feeds.
    ///
    /// # Errors
    ///
    /// Returns error if any feed fails to fetch.
    #[allow(clippy::cast_possible_truncation)]
    pub async fn fetch_all(&self) -> TerasResult<FeedFetchResult> {
        let start = std::time::Instant::now();

        match self.manager.fetch_all().await {
            Ok(indicators) => {
                let count = indicators.len();

                // Store indicators
                let stored = self.storage.store_batch(indicators)?;

                // Log success
                self.log_operation(
                    "fetch_all",
                    "all",
                    ActionResult::Success,
                    Some(
                        Context::new()
                            .with_extra("indicators_fetched", count.to_string())
                            .with_extra("indicators_stored", stored.to_string())
                            .with_extra("duration_ms", start.elapsed().as_millis().to_string()),
                    ),
                )?;

                Ok(FeedFetchResult {
                    success: true,
                    indicators_fetched: count,
                    indicators_stored: stored,
                    duration_ms: start.elapsed().as_millis() as u64,
                    errors: Vec::new(),
                })
            }
            Err(e) => {
                // Log failure
                self.log_operation(
                    "fetch_all",
                    "all",
                    ActionResult::Failure {
                        reason: e.to_string(),
                        code: None,
                    },
                    None,
                )?;

                Err(e)
            }
        }
    }

    /// Fetch a specific feed source.
    ///
    /// # Errors
    ///
    /// Returns error if feed fails to fetch.
    #[allow(clippy::cast_possible_truncation)]
    pub async fn fetch_source(&self, source_id: &str) -> TerasResult<FeedFetchResult> {
        let start = std::time::Instant::now();

        match self.manager.fetch_source(source_id).await {
            Ok(indicators) => {
                let count = indicators.len();
                let stored = self.storage.store_batch(indicators)?;

                self.log_operation(
                    "fetch_source",
                    source_id,
                    ActionResult::Success,
                    Some(
                        Context::new()
                            .with_extra("indicators_fetched", count.to_string())
                            .with_extra("indicators_stored", stored.to_string()),
                    ),
                )?;

                Ok(FeedFetchResult {
                    success: true,
                    indicators_fetched: count,
                    indicators_stored: stored,
                    duration_ms: start.elapsed().as_millis() as u64,
                    errors: Vec::new(),
                })
            }
            Err(e) => {
                self.log_operation(
                    "fetch_source",
                    source_id,
                    ActionResult::Failure {
                        reason: e.to_string(),
                        code: None,
                    },
                    None,
                )?;

                Err(e)
            }
        }
    }

    /// Get list of registered feed source IDs.
    #[must_use]
    pub fn source_ids(&self) -> Vec<&str> {
        self.manager.source_ids()
    }

    /// Search stored indicators.
    ///
    /// # Errors
    ///
    /// Returns error if storage query fails.
    pub fn search(&self, query: &str, limit: usize) -> TerasResult<Vec<ThreatIndicator>> {
        let results = self.storage.search(query, limit)?;

        // Log search (for audit trail)
        self.log_operation(
            "search",
            "storage",
            ActionResult::Success,
            Some(
                Context::new()
                    .with_extra("query", query.to_string())
                    .with_extra("results", results.len().to_string()),
            ),
        )?;

        Ok(results)
    }

    /// Get total count of stored indicators.
    ///
    /// # Errors
    ///
    /// Returns error if storage query fails.
    pub fn indicator_count(&self) -> TerasResult<usize> {
        self.storage.count()
    }

    /// Register an additional feed source.
    pub fn register_source(&mut self, source: impl FeedSource + 'static) {
        self.manager.register_source(source);
    }
}

/// Result of a feed fetch operation.
#[derive(Debug, Clone)]
pub struct FeedFetchResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Number of indicators fetched.
    pub indicators_fetched: usize,
    /// Number of indicators stored (after dedup/validation).
    pub indicators_stored: usize,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Any errors encountered.
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use teras_jejak::storage::MemoryStorage as AuditMemoryStorage;

    fn create_test_feeds() -> AuditedFeeds {
        let audit_storage = AuditMemoryStorage::new();
        let audit_log = AuditLog::new(Box::new(audit_storage));
        let indicator_storage = MemoryIndicatorStorage::new();

        AuditedFeeds::new(
            Arc::new(std::sync::RwLock::new(audit_log)),
            Arc::new(indicator_storage),
        )
    }

    #[test]
    fn test_source_ids() {
        let feeds = create_test_feeds();
        let ids = feeds.source_ids();

        assert!(ids.contains(&"abusech-urlhaus"));
        assert!(ids.contains(&"abusech-feodo"));
    }

    #[test]
    fn test_indicator_count_empty() {
        let feeds = create_test_feeds();
        assert_eq!(feeds.indicator_count().unwrap(), 0);
    }

    #[test]
    fn test_search_empty() {
        let feeds = create_test_feeds();
        let results = feeds.search("test", 10).unwrap();
        assert!(results.is_empty());

        // Verify search was logged
        let log = feeds.audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    // Note: fetch_all and fetch_source tests would require network mocking
    // These are tested in integration tests with mockito
}
