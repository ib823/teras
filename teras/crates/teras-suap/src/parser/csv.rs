//! CSV feed parser (for abuse.ch and similar feeds).

use crate::indicator::{Confidence, IndicatorType, Severity, ThreatIndicator};
use crate::parser::FeedParser;
use chrono::Utc;
use teras_core::{TerasError, TerasResult};

/// CSV parser with configurable column mapping.
pub struct CsvParser {
    /// Column index for the indicator value.
    value_col: usize,
    /// Column index for indicator type (if present).
    type_col: Option<usize>,
    /// Default indicator type if not in data.
    default_type: IndicatorType,
    /// Number of header rows to skip.
    skip_rows: usize,
    /// Comment prefix to skip lines.
    comment_prefix: Option<String>,
    /// Source name for indicators.
    source: String,
}

impl CsvParser {
    /// Create a new CSV parser.
    #[must_use]
    pub fn new(source: impl Into<String>, value_col: usize, default_type: IndicatorType) -> Self {
        Self {
            value_col,
            type_col: None,
            default_type,
            skip_rows: 0,
            comment_prefix: Some("#".to_string()),
            source: source.into(),
        }
    }

    /// Set type column.
    #[must_use]
    pub const fn with_type_col(mut self, col: usize) -> Self {
        self.type_col = Some(col);
        self
    }

    /// Set number of header rows to skip.
    #[must_use]
    pub const fn with_skip_rows(mut self, rows: usize) -> Self {
        self.skip_rows = rows;
        self
    }

    /// Set comment prefix.
    #[must_use]
    pub fn with_comment_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.comment_prefix = Some(prefix.into());
        self
    }

    fn parse_type(&self, type_str: &str) -> IndicatorType {
        match type_str.to_lowercase().as_str() {
            "ip" | "ipv4" | "ip_address" => IndicatorType::Ipv4,
            "ipv6" => IndicatorType::Ipv6,
            "domain" | "hostname" => IndicatorType::Domain,
            "url" => IndicatorType::Url,
            "md5" => IndicatorType::Md5,
            "sha1" => IndicatorType::Sha1,
            "sha256" => IndicatorType::Sha256,
            "email" => IndicatorType::Email,
            _ => self.default_type,
        }
    }
}

impl FeedParser for CsvParser {
    fn parse(&self, data: &[u8]) -> TerasResult<Vec<ThreatIndicator>> {
        let text = std::str::from_utf8(data).map_err(|e| TerasError::ThreatFeedParseFailed {
            format: "CSV".to_string(),
            reason: format!("Invalid UTF-8: {e}"),
        })?;

        let mut indicators = Vec::new();
        let now = Utc::now();

        for (line_num, line) in text.lines().enumerate() {
            // Skip header rows
            if line_num < self.skip_rows {
                continue;
            }

            // Skip comments
            if let Some(ref prefix) = self.comment_prefix {
                if line.starts_with(prefix) {
                    continue;
                }
            }

            // Skip empty lines
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Parse CSV
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();

            if fields.len() <= self.value_col {
                continue; // Skip malformed lines
            }

            let value = fields[self.value_col].trim_matches('"').to_string();
            if value.is_empty() {
                continue;
            }

            let indicator_type = if let Some(type_col) = self.type_col {
                if fields.len() > type_col {
                    self.parse_type(fields[type_col])
                } else {
                    self.default_type
                }
            } else {
                self.default_type
            };

            let indicator = ThreatIndicator {
                id: format!("{}-{}", self.source, line_num),
                indicator_type,
                value,
                severity: Severity::Medium,
                confidence: Confidence::medium(),
                source: self.source.clone(),
                first_seen: now,
                last_seen: now,
                fetched_at: now,
                expires_at: None,
                tags: Vec::new(),
                description: None,
                reference_url: None,
                malware_families: Vec::new(),
            };

            indicators.push(indicator);
        }

        Ok(indicators)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_csv() {
        let csv = r#"# Comment line
ip_address,description
1.2.3.4,bad ip
5.6.7.8,another bad ip
"#;

        // skip_rows(2) skips line 0 (comment) and line 1 (header)
        let parser = CsvParser::new("test", 0, IndicatorType::Ipv4).with_skip_rows(2);

        let indicators = parser.parse(csv.as_bytes()).unwrap();

        assert_eq!(indicators.len(), 2);
        assert_eq!(indicators[0].value, "1.2.3.4");
        assert_eq!(indicators[1].value, "5.6.7.8");
    }

    #[test]
    fn test_parse_with_type_column() {
        let csv = r#"value,type
1.2.3.4,ipv4
malware.com,domain
"#;

        let parser = CsvParser::new("test", 0, IndicatorType::Ipv4)
            .with_type_col(1)
            .with_skip_rows(1)
            .with_comment_prefix("#");

        let indicators = parser.parse(csv.as_bytes()).unwrap();

        assert_eq!(indicators.len(), 2);
        assert_eq!(indicators[0].indicator_type, IndicatorType::Ipv4);
        assert_eq!(indicators[1].indicator_type, IndicatorType::Domain);
    }

    #[test]
    fn test_skip_comments_and_empty() {
        let csv = r#"# header
# another comment

1.2.3.4

5.6.7.8
"#;

        let parser = CsvParser::new("test", 0, IndicatorType::Ipv4);
        let indicators = parser.parse(csv.as_bytes()).unwrap();

        assert_eq!(indicators.len(), 2);
    }
}
