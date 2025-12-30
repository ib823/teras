//! Feed parsers.
//!
//! Parsers for different feed formats.

pub mod csv;
pub mod json;
pub mod stix;

use crate::indicator::ThreatIndicator;
use teras_core::TerasResult;

/// Trait for feed parsers.
pub trait FeedParser: Send + Sync {
    /// Parse raw bytes into indicators.
    ///
    /// # Errors
    ///
    /// Returns error if parsing fails.
    fn parse(&self, data: &[u8]) -> TerasResult<Vec<ThreatIndicator>>;
}
