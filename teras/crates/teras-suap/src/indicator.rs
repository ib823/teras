//! Threat indicator types.
//!
//! Normalized representation of threat intelligence indicators
//! from various feed sources.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Type of threat indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    /// IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// Domain name.
    Domain,
    /// Full URL.
    Url,
    /// MD5 file hash.
    Md5,
    /// SHA1 file hash.
    Sha1,
    /// SHA256 file hash.
    Sha256,
    /// Email address.
    Email,
    /// CIDR network range.
    Cidr,
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "ipv4"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::Domain => write!(f, "domain"),
            Self::Url => write!(f, "url"),
            Self::Md5 => write!(f, "md5"),
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha256 => write!(f, "sha256"),
            Self::Email => write!(f, "email"),
            Self::Cidr => write!(f, "cidr"),
        }
    }
}

/// Severity level of the threat.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational only.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    #[default]
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

/// Confidence level of the indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Confidence(u8);

impl Confidence {
    /// Create a new confidence value (0-100).
    ///
    /// # Panics
    ///
    /// Panics if value > 100.
    #[must_use]
    pub fn new(value: u8) -> Self {
        assert!(value <= 100, "Confidence must be 0-100");
        Self(value)
    }

    /// Low confidence (25%).
    #[must_use]
    pub const fn low() -> Self {
        Self(25)
    }

    /// Medium confidence (50%).
    #[must_use]
    pub const fn medium() -> Self {
        Self(50)
    }

    /// High confidence (75%).
    #[must_use]
    pub const fn high() -> Self {
        Self(75)
    }

    /// Very high confidence (90%).
    #[must_use]
    pub const fn very_high() -> Self {
        Self(90)
    }

    /// Get the raw value.
    #[must_use]
    pub const fn value(&self) -> u8 {
        self.0
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self::medium()
    }
}

/// A normalized threat indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// Unique identifier (UUID or source-specific).
    pub id: String,

    /// Type of indicator.
    pub indicator_type: IndicatorType,

    /// The actual indicator value (IP, domain, hash, etc.).
    pub value: String,

    /// Severity of the threat.
    pub severity: Severity,

    /// Confidence level (0-100).
    pub confidence: Confidence,

    /// Source feed identifier.
    pub source: String,

    /// When the indicator was first seen.
    pub first_seen: DateTime<Utc>,

    /// When the indicator was last seen.
    pub last_seen: DateTime<Utc>,

    /// When this record was fetched.
    pub fetched_at: DateTime<Utc>,

    /// Expiration time (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Threat tags/categories.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Reference URL for more information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_url: Option<String>,

    /// Related malware families.
    #[serde(default)]
    pub malware_families: Vec<String>,
}

impl ThreatIndicator {
    /// Create a new threat indicator with required fields.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        indicator_type: IndicatorType,
        value: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            indicator_type,
            value: value.into(),
            severity: Severity::default(),
            confidence: Confidence::default(),
            source: source.into(),
            first_seen: now,
            last_seen: now,
            fetched_at: now,
            expires_at: None,
            tags: Vec::new(),
            description: None,
            reference_url: None,
            malware_families: Vec::new(),
        }
    }

    /// Set severity.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set confidence.
    #[must_use]
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Check if the indicator has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| exp < Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    /// Helper to create a `TimeDelta` from hours.
    fn hours(n: i64) -> TimeDelta {
        TimeDelta::try_hours(n).expect("hours value is valid")
    }

    #[test]
    fn test_indicator_creation() {
        let indicator = ThreatIndicator::new(
            "test-001",
            IndicatorType::Ipv4,
            "192.168.1.1",
            "test-source",
        );

        assert_eq!(indicator.id, "test-001");
        assert_eq!(indicator.indicator_type, IndicatorType::Ipv4);
        assert_eq!(indicator.value, "192.168.1.1");
        assert_eq!(indicator.source, "test-source");
    }

    #[test]
    fn test_indicator_with_metadata() {
        let indicator = ThreatIndicator::new(
            "test-002",
            IndicatorType::Domain,
            "malware.example.com",
            "abuse.ch",
        )
        .with_severity(Severity::High)
        .with_confidence(Confidence::high())
        .with_tag("malware")
        .with_tag("c2")
        .with_description("Known C2 domain");

        assert_eq!(indicator.severity, Severity::High);
        assert_eq!(indicator.confidence.value(), 75);
        assert_eq!(indicator.tags, vec!["malware", "c2"]);
        assert_eq!(indicator.description, Some("Known C2 domain".to_string()));
    }

    #[test]
    fn test_indicator_type_display() {
        assert_eq!(format!("{}", IndicatorType::Ipv4), "ipv4");
        assert_eq!(format!("{}", IndicatorType::Sha256), "sha256");
    }

    #[test]
    fn test_confidence_bounds() {
        let c = Confidence::new(100);
        assert_eq!(c.value(), 100);

        let c = Confidence::new(0);
        assert_eq!(c.value(), 0);
    }

    #[test]
    #[should_panic(expected = "Confidence must be 0-100")]
    fn test_confidence_overflow() {
        let _ = Confidence::new(101);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_expired_indicator() {
        let mut indicator = ThreatIndicator::new(
            "exp-001",
            IndicatorType::Url,
            "http://expired.example.com",
            "test",
        );

        // Not expired by default
        assert!(!indicator.is_expired());

        // Set expiration in the past
        indicator.expires_at = Some(Utc::now() - hours(1));
        assert!(indicator.is_expired());

        // Set expiration in the future
        indicator.expires_at = Some(Utc::now() + hours(1));
        assert!(!indicator.is_expired());
    }

    #[test]
    fn test_serialization() {
        let indicator = ThreatIndicator::new(
            "ser-001",
            IndicatorType::Sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "test",
        );

        let json = serde_json::to_string(&indicator).unwrap();
        assert!(json.contains("\"indicator_type\":\"sha256\""));

        let parsed: ThreatIndicator = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, indicator.id);
    }
}
