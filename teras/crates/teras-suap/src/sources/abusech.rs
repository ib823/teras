//! abuse.ch feed sources.
//!
//! Implements feeds from abuse.ch:
//! - `URLhaus` (malicious URLs)
//! - `ThreatFox` (IOCs)
//! - Feodo Tracker (botnet C2)

use crate::feed::{FeedFormat, FeedMetadata, FeedSource};
use crate::indicator::{Confidence, IndicatorType, Severity, ThreatIndicator};
use crate::parser::csv::CsvParser;
use crate::parser::FeedParser;
use chrono::Utc;
use teras_core::TerasResult;

/// abuse.ch feed source.
pub struct AbuseCh {
    metadata: FeedMetadata,
    parser: CsvParser,
}

impl AbuseCh {
    /// Create `URLhaus` recent URLs feed.
    ///
    /// Source: <https://urlhaus.abuse.ch/>
    #[must_use]
    pub fn urlhaus() -> Self {
        let metadata = FeedMetadata {
            id: "abusech-urlhaus".to_string(),
            name: "URLhaus Recent URLs".to_string(),
            provider: "abuse.ch".to_string(),
            description: "Recent malicious URLs from URLhaus".to_string(),
            url: "https://urlhaus.abuse.ch/downloads/csv_recent/".to_string(),
            format: FeedFormat::Csv,
            is_free: true,
            requires_auth: false,
            update_interval_secs: 300, // 5 minutes
            last_fetch: None,
        };

        // URLhaus CSV format:
        // id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        // Column 2 is the URL
        let parser = CsvParser::new("abusech-urlhaus", 2, IndicatorType::Url)
            .with_skip_rows(9) // Skip header comment block
            .with_comment_prefix("#");

        Self { metadata, parser }
    }

    /// Create Feodo Tracker botnet C2 feed.
    ///
    /// Source: <https://feodotracker.abuse.ch/>
    #[must_use]
    pub fn feodo() -> Self {
        let metadata = FeedMetadata {
            id: "abusech-feodo".to_string(),
            name: "Feodo Tracker".to_string(),
            provider: "abuse.ch".to_string(),
            description: "Botnet C2 servers tracked by Feodo Tracker".to_string(),
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv".to_string(),
            format: FeedFormat::Csv,
            is_free: true,
            requires_auth: false,
            update_interval_secs: 300,
            last_fetch: None,
        };

        // Feodo CSV format: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
        // Column 1 is the IP
        let parser = CsvParser::new("abusech-feodo", 1, IndicatorType::Ipv4)
            .with_skip_rows(9)
            .with_comment_prefix("#");

        Self { metadata, parser }
    }
}

impl FeedSource for AbuseCh {
    fn id(&self) -> &str {
        &self.metadata.id
    }

    fn metadata(&self) -> &FeedMetadata {
        &self.metadata
    }

    fn parse(&self, raw: &[u8]) -> TerasResult<Vec<ThreatIndicator>> {
        let mut indicators = self.parser.parse(raw)?;

        // Enhance with abuse.ch specific metadata
        let now = Utc::now();
        for indicator in &mut indicators {
            indicator.source.clone_from(&self.metadata.id);
            indicator.severity = Severity::High; // abuse.ch feeds are generally high severity
            indicator.confidence = Confidence::high();
            indicator.fetched_at = now;
            indicator.tags.push("abuse.ch".to_string());

            // Add feed-specific tags
            match self.metadata.id.as_str() {
                "abusech-urlhaus" => {
                    indicator.tags.push("malware-distribution".to_string());
                }
                "abusech-feodo" => {
                    indicator.tags.push("botnet".to_string());
                    indicator.tags.push("c2".to_string());
                }
                _ => {}
            }
        }

        Ok(indicators)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlhaus_metadata() {
        let source = AbuseCh::urlhaus();
        assert_eq!(source.id(), "abusech-urlhaus");
        assert!(source.metadata().is_free);
        assert!(!source.metadata().requires_auth);
    }

    #[test]
    fn test_feodo_metadata() {
        let source = AbuseCh::feodo();
        assert_eq!(source.id(), "abusech-feodo");
        assert_eq!(source.metadata().provider, "abuse.ch");
    }

    #[test]
    fn test_parse_urlhaus_sample() {
        let sample = r#"# abuse.ch URLhaus CSV
# Generated: 2024-01-01
#
# Format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
# More headers...
# More headers...
# More headers...
# More headers...
# More headers...
"1234","2024-01-01 12:00:00","http://malware.example.com/bad.exe","online","2024-01-01","malware_download","exe,trojan","https://urlhaus.abuse.ch/url/1234/","reporter1"
"1235","2024-01-01 12:01:00","http://another.bad.com/payload.dll","offline","2024-01-01","malware_download","dll","https://urlhaus.abuse.ch/url/1235/","reporter2"
"#;

        let source = AbuseCh::urlhaus();
        let indicators = source.parse(sample.as_bytes()).unwrap();

        assert_eq!(indicators.len(), 2);
        assert_eq!(indicators[0].indicator_type, IndicatorType::Url);
        assert!(indicators[0].value.contains("malware.example.com"));
        assert!(indicators[0].tags.contains(&"abuse.ch".to_string()));
        assert!(indicators[0]
            .tags
            .contains(&"malware-distribution".to_string()));
    }

    #[test]
    fn test_parse_feodo_sample() {
        let sample = r#"# Feodo Tracker
# IP Blocklist
# Format: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
# Headers...
# Headers...
# Headers...
# Headers...
# Headers...
# Headers...
2024-01-01 00:00:00,1.2.3.4,443,online,2024-01-01,Dridex
2024-01-01 00:00:00,5.6.7.8,8080,offline,2024-01-01,Emotet
"#;

        let source = AbuseCh::feodo();
        let indicators = source.parse(sample.as_bytes()).unwrap();

        assert_eq!(indicators.len(), 2);
        assert_eq!(indicators[0].indicator_type, IndicatorType::Ipv4);
        assert_eq!(indicators[0].value, "1.2.3.4");
        assert!(indicators[0].tags.contains(&"botnet".to_string()));
        assert!(indicators[0].tags.contains(&"c2".to_string()));
    }
}
