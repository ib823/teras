//! STIX 2.1 parser (stub for future implementation).

use crate::indicator::ThreatIndicator;
use crate::parser::FeedParser;
use teras_core::{TerasError, TerasResult};

/// STIX 2.1 format parser.
///
/// **NOTE**: This is a stub implementation. Full STIX 2.1 parsing
/// is complex and will be implemented in a future phase.
pub struct StixParser;

impl StixParser {
    /// Create a new STIX parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for StixParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FeedParser for StixParser {
    fn parse(&self, _data: &[u8]) -> TerasResult<Vec<ThreatIndicator>> {
        // STUB: STIX 2.1 parsing is complex and requires additional dependencies
        // This will be implemented in a future phase when needed
        Err(TerasError::ThreatFeedParseFailed {
            format: "STIX".to_string(),
            reason: "STIX parser not yet implemented".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stix_not_implemented() {
        let parser = StixParser::new();
        let result = parser.parse(b"{}");
        assert!(result.is_err());
    }
}
