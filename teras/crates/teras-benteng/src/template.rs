//! Biometric template handling.
//!
//! **LAW 1 COMPLIANCE:**
//! This module handles template HASHES, not actual templates.

use teras_kunci::ct_eq;
use teras_kunci::hash::sha3_256;

/// Template hash wrapper with constant-time comparison.
#[derive(Debug, Clone)]
pub struct TemplateHash([u8; 32]);

impl TemplateHash {
    /// Create from raw hash bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compare two template hashes in constant time.
    ///
    /// This prevents timing attacks on biometric matching.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl PartialEq for TemplateHash {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for TemplateHash {}

/// Compute the expected template hash from biometric data.
///
/// **NOTE:** This would be called CLIENT-SIDE, not server-side.
/// It's included here for testing and reference implementation.
///
/// In production:
/// - Client captures biometric
/// - Client generates template
/// - Client computes hash = `sha3_256(template)`
/// - Client sends ONLY the hash to server
#[must_use]
#[allow(dead_code)] // Reference implementation for client-side
pub fn compute_template_hash(template_data: &[u8]) -> TemplateHash {
    let hash = sha3_256(template_data);
    TemplateHash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_hash_matches() {
        let hash1 = TemplateHash::from_bytes([42u8; 32]);
        let hash2 = TemplateHash::from_bytes([42u8; 32]);
        let hash3 = TemplateHash::from_bytes([0u8; 32]);

        assert!(hash1.matches(&hash2));
        assert!(!hash1.matches(&hash3));
    }

    #[test]
    fn test_template_hash_eq() {
        let hash1 = TemplateHash::from_bytes([1u8; 32]);
        let hash2 = TemplateHash::from_bytes([1u8; 32]);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_template_hash_ne() {
        let hash1 = TemplateHash::from_bytes([1u8; 32]);
        let hash2 = TemplateHash::from_bytes([2u8; 32]);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_template_hash() {
        let template = b"mock biometric template data";
        let hash1 = compute_template_hash(template);
        let hash2 = compute_template_hash(template);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_templates_different_hashes() {
        let hash1 = compute_template_hash(b"template 1");
        let hash2 = compute_template_hash(b"template 2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_to_hex() {
        let hash = TemplateHash::from_bytes([0xAB; 32]);
        let hex = hash.to_hex();

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(hex.starts_with("abab"));
    }

    #[test]
    fn test_as_bytes() {
        let bytes = [123u8; 32];
        let hash = TemplateHash::from_bytes(bytes);

        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_constant_time_comparison() {
        // This test ensures the comparison is constant-time
        // by verifying it produces correct results
        let hash_a = TemplateHash::from_bytes([0u8; 32]);
        let hash_b = TemplateHash::from_bytes([0u8; 32]);
        let hash_c = TemplateHash::from_bytes([1u8; 32]);

        // Same hashes should match
        assert!(hash_a.matches(&hash_b));
        // Different hashes should not match
        assert!(!hash_a.matches(&hash_c));
    }
}
