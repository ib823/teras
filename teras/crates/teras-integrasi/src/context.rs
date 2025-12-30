//! Unified TERAS runtime context.
//!
//! Holds all state needed for TERAS operations.

use crate::audited_crypto::AuditedCrypto;
use crate::audited_feeds::AuditedFeeds;
use crate::config::TerasConfig;
use std::sync::Arc;
use teras_jejak::{storage::MemoryStorage as AuditMemoryStorage, AuditLog};
use teras_suap::storage::MemoryIndicatorStorage;

/// Unified TERAS runtime context.
///
/// This is the main entry point for all TERAS operations.
/// It ensures all operations are properly audited per LAW 8.
pub struct TerasContext {
    config: TerasConfig,
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
    indicator_storage: Arc<MemoryIndicatorStorage>,
}

impl TerasContext {
    /// Create a new context with in-memory storage.
    ///
    /// **NOTE**: For development/testing only. Production should use
    /// persistent storage.
    #[must_use]
    pub fn new_in_memory() -> Self {
        let audit_storage = AuditMemoryStorage::new();
        let audit_log = AuditLog::new(Box::new(audit_storage));

        Self {
            config: TerasConfig::default(),
            audit_log: Arc::new(std::sync::RwLock::new(audit_log)),
            indicator_storage: Arc::new(MemoryIndicatorStorage::new()),
        }
    }

    /// Create context with custom configuration.
    #[must_use]
    pub fn with_config(config: TerasConfig) -> Self {
        let audit_storage = AuditMemoryStorage::new();
        let audit_log = AuditLog::new(Box::new(audit_storage));

        Self {
            config,
            audit_log: Arc::new(std::sync::RwLock::new(audit_log)),
            indicator_storage: Arc::new(MemoryIndicatorStorage::new()),
        }
    }

    /// Get audited crypto operations.
    #[must_use]
    pub fn crypto(&self) -> AuditedCrypto {
        AuditedCrypto::new(Arc::clone(&self.audit_log))
    }

    /// Get audited feed operations.
    #[must_use]
    pub fn feeds(&self) -> AuditedFeeds {
        AuditedFeeds::new(
            Arc::clone(&self.audit_log),
            Arc::clone(&self.indicator_storage),
        )
    }

    /// Get direct access to audit log for verification.
    ///
    /// Returns a read guard to the audit log.
    ///
    /// # Panics
    ///
    /// Panics if the audit log lock is poisoned.
    pub fn audit(&self) -> std::sync::RwLockReadGuard<'_, AuditLog> {
        self.audit_log.read().expect("Audit log lock poisoned")
    }

    /// Get mutable access to audit log.
    ///
    /// # Panics
    ///
    /// Panics if the audit log lock is poisoned.
    pub fn audit_mut(&self) -> std::sync::RwLockWriteGuard<'_, AuditLog> {
        self.audit_log.write().expect("Audit log lock poisoned")
    }

    /// Get configuration.
    #[must_use]
    pub fn config(&self) -> &TerasConfig {
        &self.config
    }

    /// Get indicator storage for queries.
    #[must_use]
    pub fn indicators(&self) -> Arc<MemoryIndicatorStorage> {
        Arc::clone(&self.indicator_storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = TerasContext::new_in_memory();
        assert_eq!(ctx.audit().count().unwrap(), 0);
    }

    #[test]
    fn test_context_with_config() {
        let config = TerasConfig::default();
        let ctx = TerasContext::with_config(config);
        assert!(!ctx.config().component_name.is_empty());
    }
}
