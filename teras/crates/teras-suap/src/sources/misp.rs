//! MISP feed source (stub).
//!
//! MISP feeds can be self-hosted or from MISP communities.
//! This is a stub for future implementation.

use crate::feed::{FeedFormat, FeedMetadata, FeedSource};
use crate::indicator::ThreatIndicator;
use teras_core::{TerasError, TerasResult};

/// MISP feed source.
///
/// **NOTE**: Stub implementation.
pub struct Misp {
    metadata: FeedMetadata,
}

impl Misp {
    /// Create new MISP source from URL.
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        let name = name.into();
        let metadata = FeedMetadata {
            id: format!("misp-{}", name.to_lowercase().replace(' ', "-")),
            name,
            provider: "MISP".to_string(),
            description: "MISP threat intelligence feed".to_string(),
            url: url.into(),
            format: FeedFormat::Json,
            is_free: true,
            requires_auth: false,
            update_interval_secs: 3600,
            last_fetch: None,
        };

        Self { metadata }
    }
}

impl FeedSource for Misp {
    fn id(&self) -> &str {
        &self.metadata.id
    }

    fn metadata(&self) -> &FeedMetadata {
        &self.metadata
    }

    fn parse(&self, _raw: &[u8]) -> TerasResult<Vec<ThreatIndicator>> {
        // STUB: MISP format parsing is complex
        Err(TerasError::ThreatFeedParseFailed {
            format: "MISP".to_string(),
            reason: "MISP parser not yet implemented".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_misp_metadata() {
        let source = Misp::new("CIRCL OSINT", "https://www.circl.lu/doc/misp/feed-osint/");
        assert!(source.id().starts_with("misp-"));
        assert_eq!(source.metadata().provider, "MISP");
    }
}
