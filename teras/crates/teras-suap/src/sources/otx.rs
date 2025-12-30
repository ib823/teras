//! `AlienVault` OTX feed source (stub).
//!
//! OTX requires registration and API key.
//! This is a stub for future implementation.

use crate::feed::{FeedFormat, FeedMetadata, FeedSource};
use crate::indicator::ThreatIndicator;
use teras_core::{TerasError, TerasResult};

/// `AlienVault` OTX feed source.
///
/// **NOTE**: Stub implementation. OTX requires API key.
pub struct Otx {
    metadata: FeedMetadata,
    api_key: Option<String>,
}

impl Otx {
    /// Create new OTX source.
    #[must_use]
    pub fn new(api_key: Option<String>) -> Self {
        let metadata = FeedMetadata {
            id: "alienvault-otx".to_string(),
            name: "AlienVault OTX".to_string(),
            provider: "AlienVault".to_string(),
            description: "Open Threat Exchange community threat intelligence".to_string(),
            url: "https://otx.alienvault.com/api/v1/pulses/subscribed".to_string(),
            format: FeedFormat::Json,
            is_free: true,
            requires_auth: true,
            update_interval_secs: 3600, // 1 hour
            last_fetch: None,
        };

        Self { metadata, api_key }
    }
}

impl FeedSource for Otx {
    fn id(&self) -> &str {
        &self.metadata.id
    }

    fn metadata(&self) -> &FeedMetadata {
        &self.metadata
    }

    fn headers(&self) -> Vec<(String, String)> {
        if let Some(ref key) = self.api_key {
            vec![("X-OTX-API-KEY".to_string(), key.clone())]
        } else {
            Vec::new()
        }
    }

    fn parse(&self, _raw: &[u8]) -> TerasResult<Vec<ThreatIndicator>> {
        // STUB: OTX parsing requires complex pulse/indicator extraction
        Err(TerasError::ThreatFeedParseFailed {
            format: "OTX".to_string(),
            reason: "OTX parser not yet implemented".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otx_metadata() {
        let source = Otx::new(None);
        assert_eq!(source.id(), "alienvault-otx");
        assert!(source.metadata().requires_auth);
    }

    #[test]
    fn test_otx_headers_without_key() {
        let source = Otx::new(None);
        assert!(source.headers().is_empty());
    }

    #[test]
    fn test_otx_headers_with_key() {
        let source = Otx::new(Some("test-key".to_string()));
        let headers = source.headers();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "X-OTX-API-KEY");
        assert_eq!(headers[0].1, "test-key");
    }
}
