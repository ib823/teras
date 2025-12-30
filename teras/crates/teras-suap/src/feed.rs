//! Feed source definitions.
//!
//! Defines the trait for feed sources and their metadata.

use crate::indicator::ThreatIndicator;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use teras_core::TerasResult;

/// Format of the feed data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
    /// JSON format.
    Json,
    /// CSV format.
    Csv,
    /// STIX 2.1 format.
    Stix,
    /// Plain text (one indicator per line).
    PlainText,
    /// Custom format requiring specialized parser.
    Custom,
}

/// Metadata about a feed source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedMetadata {
    /// Unique identifier for this feed.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Organization providing the feed.
    pub provider: String,
    /// Feed description.
    pub description: String,
    /// URL to fetch the feed from.
    pub url: String,
    /// Format of the feed data.
    pub format: FeedFormat,
    /// Whether the feed is free.
    pub is_free: bool,
    /// Whether registration/API key is required.
    pub requires_auth: bool,
    /// Recommended update frequency in seconds.
    pub update_interval_secs: u64,
    /// Last successful fetch time.
    pub last_fetch: Option<DateTime<Utc>>,
}

/// Trait for feed sources.
///
/// Implement this trait to add a new feed source.
pub trait FeedSource: Send + Sync {
    /// Get the unique identifier for this feed.
    fn id(&self) -> &str;

    /// Get feed metadata.
    fn metadata(&self) -> &FeedMetadata;

    /// Get the URL to fetch.
    fn url(&self) -> &str {
        &self.metadata().url
    }

    /// Get any required headers (e.g., API key).
    fn headers(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Parse raw feed data into indicators.
    ///
    /// # Errors
    ///
    /// Returns error if parsing fails.
    fn parse(&self, raw: &[u8]) -> TerasResult<Vec<ThreatIndicator>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_format_serialization() {
        let format = FeedFormat::Json;
        let json = serde_json::to_string(&format).unwrap();
        assert_eq!(json, "\"json\"");
    }

    #[test]
    fn test_feed_metadata() {
        let meta = FeedMetadata {
            id: "test-feed".to_string(),
            name: "Test Feed".to_string(),
            provider: "Test Provider".to_string(),
            description: "A test feed".to_string(),
            url: "https://example.com/feed.json".to_string(),
            format: FeedFormat::Json,
            is_free: true,
            requires_auth: false,
            update_interval_secs: 3600,
            last_fetch: None,
        };

        assert_eq!(meta.id, "test-feed");
        assert!(meta.is_free);
    }
}
