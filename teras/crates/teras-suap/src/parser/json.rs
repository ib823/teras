//! Generic JSON feed parser.

use crate::indicator::ThreatIndicator;
use crate::parser::FeedParser;
use teras_core::{TerasError, TerasResult};

/// Generic JSON parser for feeds that return arrays of indicators.
pub struct JsonParser;

impl JsonParser {
    /// Create a new JSON parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for JsonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FeedParser for JsonParser {
    fn parse(&self, data: &[u8]) -> TerasResult<Vec<ThreatIndicator>> {
        serde_json::from_slice(data).map_err(|e| TerasError::ThreatFeedParseFailed {
            format: "JSON".to_string(),
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::IndicatorType;

    #[test]
    fn test_parse_json_array() {
        let json = r#"[
            {
                "id": "test-1",
                "indicator_type": "ipv4",
                "value": "1.2.3.4",
                "source": "test",
                "severity": "high",
                "confidence": 75,
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-01T00:00:00Z",
                "fetched_at": "2024-01-01T00:00:00Z",
                "tags": []
            }
        ]"#;

        let parser = JsonParser::new();
        let indicators = parser.parse(json.as_bytes()).unwrap();

        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].indicator_type, IndicatorType::Ipv4);
        assert_eq!(indicators[0].value, "1.2.3.4");
    }

    #[test]
    fn test_parse_invalid_json() {
        let parser = JsonParser::new();
        let result = parser.parse(b"not json");
        assert!(result.is_err());
    }
}
