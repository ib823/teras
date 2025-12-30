//! TERAS Suap - Threat Intelligence Feed Ingestion
//!
//! Implements REALITY 6: External threat intelligence bootstrap.
//!
//! Until TERAS reaches 50+ active customers, threat intelligence is
//! 100% sourced from external feeds.
//!
//! # Bootstrap Sources (prioritized)
//!
//! 1. abuse.ch (`URLhaus`, `ThreatFox`, Feodo) - FREE, daily updates
//! 2. `AlienVault` OTX - FREE with registration
//! 3. Emerging Threats - FREE ruleset
//! 4. MISP default feeds - FREE
//! 5. `MyCERT` (Malaysian) - FREE for Malaysian entities
//! 6. OWASP CRS - FREE, web attack patterns
//!
//! # Daily Workflow
//!
//! 1. **Fetch**: Download latest indicators (automated)
//! 2. **Review**: Security team reviews (15-20 min daily)
//! 3. **Deploy**: Push to TERAS (5 min)
//!
//! # Example
//!
//! ```no_run
//! use teras_suap::{FeedManager, sources::AbuseCh};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut manager = FeedManager::new();
//! manager.register_source(AbuseCh::urlhaus());
//!
//! // Fetch all registered feeds
//! let indicators = manager.fetch_all().await?;
//!
//! for indicator in indicators {
//!     println!("{}: {}", indicator.indicator_type, indicator.value);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod feed;
mod fetcher;
mod indicator;
pub mod parser;
pub mod sources;
pub mod storage;
mod validator;

pub use feed::{FeedFormat, FeedMetadata, FeedSource};
pub use fetcher::FeedFetcher;
pub use indicator::{Confidence, IndicatorType, Severity, ThreatIndicator};
pub use validator::IndicatorValidator;

use std::collections::HashMap;
use teras_core::{TerasError, TerasResult};

/// Manages multiple threat feed sources.
pub struct FeedManager {
    sources: HashMap<String, Box<dyn FeedSource>>,
    fetcher: FeedFetcher,
    validator: IndicatorValidator,
}

impl FeedManager {
    /// Create a new feed manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            fetcher: FeedFetcher::new(),
            validator: IndicatorValidator::new(),
        }
    }

    /// Register a feed source.
    pub fn register_source(&mut self, source: impl FeedSource + 'static) {
        self.sources
            .insert(source.id().to_string(), Box::new(source));
    }

    /// Fetch indicators from all registered sources.
    ///
    /// # Errors
    ///
    /// Returns error if any feed fails to fetch (partial success not yet implemented).
    pub async fn fetch_all(&self) -> TerasResult<Vec<ThreatIndicator>> {
        let mut all_indicators = Vec::new();

        for source in self.sources.values() {
            let raw = self.fetcher.fetch(source.as_ref()).await?;
            let parsed = source.parse(&raw)?;

            // Validate each indicator
            for indicator in parsed {
                if self.validator.validate(&indicator).is_ok() {
                    all_indicators.push(indicator);
                }
            }
        }

        // Deduplicate
        all_indicators.sort_by(|a, b| a.value.cmp(&b.value));
        all_indicators.dedup_by(|a, b| a.value == b.value && a.indicator_type == b.indicator_type);

        Ok(all_indicators)
    }

    /// Fetch from a specific source by ID.
    ///
    /// # Errors
    ///
    /// Returns error if source not found or fetch fails.
    pub async fn fetch_source(&self, source_id: &str) -> TerasResult<Vec<ThreatIndicator>> {
        let source =
            self.sources
                .get(source_id)
                .ok_or_else(|| TerasError::ThreatFeedFetchFailed {
                    source: source_id.to_string(),
                    reason: "Source not registered".to_string(),
                })?;

        let raw = self.fetcher.fetch(source.as_ref()).await?;
        let parsed = source.parse(&raw)?;

        let mut valid = Vec::new();
        for indicator in parsed {
            if self.validator.validate(&indicator).is_ok() {
                valid.push(indicator);
            }
        }

        Ok(valid)
    }

    /// Get list of registered source IDs.
    #[must_use]
    pub fn source_ids(&self) -> Vec<&str> {
        self.sources.keys().map(String::as_str).collect()
    }
}

impl Default for FeedManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_manager_creation() {
        let manager = FeedManager::new();
        assert!(manager.source_ids().is_empty());
    }

    #[test]
    fn test_register_source() {
        let mut manager = FeedManager::new();
        manager.register_source(sources::AbuseCh::urlhaus());

        let ids = manager.source_ids();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&"abusech-urlhaus"));
    }

    #[test]
    fn test_register_multiple_sources() {
        let mut manager = FeedManager::new();
        manager.register_source(sources::AbuseCh::urlhaus());
        manager.register_source(sources::AbuseCh::feodo());

        let ids = manager.source_ids();
        assert_eq!(ids.len(), 2);
    }
}
