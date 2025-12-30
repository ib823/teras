//! Indicator validation.
//!
//! Validates that indicators are well-formed before storage.

use crate::indicator::{IndicatorType, ThreatIndicator};
use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::LazyLock;
use teras_core::{TerasError, TerasResult};
use url::Url;

// Compile regexes once
static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

static MD5_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{32}$").unwrap());

static SHA1_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{40}$").unwrap());

static SHA256_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]{64}$").unwrap());

static EMAIL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

/// Validates threat indicators.
pub struct IndicatorValidator {
    /// Minimum confidence to accept.
    min_confidence: u8,
    /// Whether to allow private IPs.
    allow_private_ips: bool,
}

impl IndicatorValidator {
    /// Create a new validator with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_confidence: 0,
            allow_private_ips: false,
        }
    }

    /// Set minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: u8) -> Self {
        self.min_confidence = min;
        self
    }

    /// Allow private IP addresses.
    #[must_use]
    pub const fn with_private_ips(mut self, allow: bool) -> Self {
        self.allow_private_ips = allow;
        self
    }

    /// Validate an indicator.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self, indicator: &ThreatIndicator) -> TerasResult<()> {
        // Check confidence threshold
        if indicator.confidence.value() < self.min_confidence {
            return Err(TerasError::ThreatIndicatorInvalid {
                indicator: indicator.value.clone(),
                reason: format!(
                    "Confidence {} below threshold {}",
                    indicator.confidence.value(),
                    self.min_confidence
                ),
            });
        }

        // Check if expired
        if indicator.is_expired() {
            return Err(TerasError::ThreatIndicatorInvalid {
                indicator: indicator.value.clone(),
                reason: "Indicator has expired".to_string(),
            });
        }

        // Validate value based on type
        self.validate_value(indicator.indicator_type, &indicator.value)
    }

    fn validate_value(&self, ioc_type: IndicatorType, value: &str) -> TerasResult<()> {
        match ioc_type {
            IndicatorType::Ipv4 => self.validate_ipv4(value),
            IndicatorType::Ipv6 => self.validate_ipv6(value),
            IndicatorType::Domain => self.validate_domain(value),
            IndicatorType::Url => self.validate_url(value),
            IndicatorType::Md5 => self.validate_hash(value, 32, "MD5"),
            IndicatorType::Sha1 => self.validate_hash(value, 40, "SHA1"),
            IndicatorType::Sha256 => self.validate_hash(value, 64, "SHA256"),
            IndicatorType::Email => self.validate_email(value),
            IndicatorType::Cidr => self.validate_cidr(value),
        }
    }

    fn validate_ipv4(&self, value: &str) -> TerasResult<()> {
        let ip = Ipv4Addr::from_str(value).map_err(|_| TerasError::ThreatIndicatorInvalid {
            indicator: value.to_string(),
            reason: "Invalid IPv4 address".to_string(),
        })?;

        if !self.allow_private_ips && (ip.is_private() || ip.is_loopback() || ip.is_link_local()) {
            return Err(TerasError::ThreatIndicatorInvalid {
                indicator: value.to_string(),
                reason: "Private/loopback IP not allowed".to_string(),
            });
        }

        Ok(())
    }

    fn validate_ipv6(&self, value: &str) -> TerasResult<()> {
        let ip = Ipv6Addr::from_str(value).map_err(|_| TerasError::ThreatIndicatorInvalid {
            indicator: value.to_string(),
            reason: "Invalid IPv6 address".to_string(),
        })?;

        if !self.allow_private_ips && ip.is_loopback() {
            return Err(TerasError::ThreatIndicatorInvalid {
                indicator: value.to_string(),
                reason: "Loopback IP not allowed".to_string(),
            });
        }

        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn validate_domain(&self, value: &str) -> TerasResult<()> {
        if !DOMAIN_REGEX.is_match(value) {
            return Err(TerasError::ThreatIndicatorInvalid {
                indicator: value.to_string(),
                reason: "Invalid domain format".to_string(),
            });
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn validate_url(&self, value: &str) -> TerasResult<()> {
        Url::parse(value).map_err(|_| TerasError::ThreatIndicatorInvalid {
            indicator: value.to_string(),
            reason: "Invalid URL format".to_string(),
        })?;
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn validate_hash(&self, value: &str, expected_len: usize, name: &str) -> TerasResult<()> {
        let regex = match expected_len {
            32 => &*MD5_REGEX,
            40 => &*SHA1_REGEX,
            64 => &*SHA256_REGEX,
            _ => {
                return Err(TerasError::ThreatIndicatorInvalid {
                    indicator: value.to_string(),
                    reason: format!("Unknown hash length {expected_len}"),
                })
            }
        };

        if !regex.is_match(value) {
            return Err(TerasError::ThreatIndicatorInvalid {
                indicator: value.to_string(),
                reason: format!("Invalid {name} hash format"),
            });
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn validate_email(&self, value: &str) -> TerasResult<()> {
        if !EMAIL_REGEX.is_match(value) {
            return Err(TerasError::ThreatIndicatorInvalid {
                indicator: value.to_string(),
                reason: "Invalid email format".to_string(),
            });
        }
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn validate_cidr(&self, value: &str) -> TerasResult<()> {
        // Try parsing as IPv4 CIDR
        if value.contains('.') {
            ipnet::Ipv4Net::from_str(value).map_err(|_| TerasError::ThreatIndicatorInvalid {
                indicator: value.to_string(),
                reason: "Invalid CIDR notation".to_string(),
            })?;
        } else {
            // Try IPv6 CIDR
            ipnet::Ipv6Net::from_str(value).map_err(|_| TerasError::ThreatIndicatorInvalid {
                indicator: value.to_string(),
                reason: "Invalid CIDR notation".to_string(),
            })?;
        }
        Ok(())
    }
}

impl Default for IndicatorValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::Confidence;

    fn make_indicator(ioc_type: IndicatorType, value: &str) -> ThreatIndicator {
        ThreatIndicator::new("test", ioc_type, value, "test")
    }

    #[test]
    fn test_valid_ipv4() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Ipv4, "8.8.8.8");
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_invalid_ipv4() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Ipv4, "999.999.999.999");
        assert!(validator.validate(&indicator).is_err());
    }

    #[test]
    fn test_private_ipv4_rejected() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Ipv4, "192.168.1.1");
        assert!(validator.validate(&indicator).is_err());
    }

    #[test]
    fn test_private_ipv4_allowed() {
        let validator = IndicatorValidator::new().with_private_ips(true);
        let indicator = make_indicator(IndicatorType::Ipv4, "192.168.1.1");
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_valid_ipv6() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Ipv6, "2001:4860:4860::8888");
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_valid_domain() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Domain, "malware.example.com");
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_invalid_domain() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Domain, "-invalid.com");
        assert!(validator.validate(&indicator).is_err());
    }

    #[test]
    fn test_valid_url() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(
            IndicatorType::Url,
            "https://malware.example.com/payload.exe",
        );
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_valid_md5() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_invalid_md5() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Md5, "invalid");
        assert!(validator.validate(&indicator).is_err());
    }

    #[test]
    fn test_valid_sha1() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(
            IndicatorType::Sha1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        );
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_valid_sha256() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(
            IndicatorType::Sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_valid_email() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Email, "phisher@malware.example.com");
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_valid_cidr() {
        let validator = IndicatorValidator::new();
        let indicator = make_indicator(IndicatorType::Cidr, "10.0.0.0/8");
        assert!(validator.validate(&indicator).is_ok());
    }

    #[test]
    fn test_confidence_threshold() {
        let validator = IndicatorValidator::new().with_min_confidence(50);

        let mut indicator = make_indicator(IndicatorType::Ipv4, "8.8.8.8");
        indicator.confidence = Confidence::new(25);
        assert!(validator.validate(&indicator).is_err());

        indicator.confidence = Confidence::new(75);
        assert!(validator.validate(&indicator).is_ok());
    }
}
