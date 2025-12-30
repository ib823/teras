//! Identity verification.
//!
//! Handles verification of enrolled identities.

use crate::types::{BiometricProof, IdentityId, LivenessProof};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Request to verify an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Identity to verify against.
    pub identity_id: IdentityId,

    /// Biometric proof (hash - LAW 1).
    pub biometric_proof: BiometricProof,

    /// Liveness proof (LAW 6).
    pub liveness_proof: LivenessProof,

    /// Device signature proving request came from bound device (LAW 7).
    pub device_signature: Vec<u8>,
}

impl VerificationRequest {
    /// Create a new verification request.
    #[must_use]
    pub fn new(
        identity_id: IdentityId,
        biometric_proof: BiometricProof,
        liveness_proof: LivenessProof,
        device_signature: Vec<u8>,
    ) -> Self {
        Self {
            identity_id,
            biometric_proof,
            liveness_proof,
            device_signature,
        }
    }
}

/// Status of verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Successfully verified.
    Verified,
    /// Biometric mismatch.
    BiometricMismatch,
    /// Liveness check failed.
    LivenessFailed,
    /// Device binding failed.
    DeviceMismatch,
    /// Identity not found.
    IdentityNotFound,
    /// Identity is not active.
    IdentityInactive,
    /// Multiple failures.
    MultipleFailed,
}

/// Result of verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Intentional: each bool represents a distinct verification step
pub struct VerificationResult {
    /// Verification status.
    pub status: VerificationStatus,

    /// Whether verification succeeded.
    pub verified: bool,

    /// Identity ID that was verified.
    pub identity_id: IdentityId,

    /// When verification occurred.
    pub verified_at: DateTime<Utc>,

    /// Biometric match result.
    pub biometric_matched: bool,

    /// Liveness check result.
    pub liveness_passed: bool,

    /// Device binding check result.
    pub device_bound: bool,

    /// Confidence score (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,

    /// Detailed issues.
    #[serde(default)]
    pub issues: Vec<String>,
}

impl VerificationResult {
    /// Create a successful verification result.
    #[must_use]
    pub fn verified(identity_id: IdentityId) -> Self {
        Self {
            status: VerificationStatus::Verified,
            verified: true,
            identity_id,
            verified_at: Utc::now(),
            biometric_matched: true,
            liveness_passed: true,
            device_bound: true,
            confidence: None,
            issues: Vec::new(),
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn failed(identity_id: IdentityId, status: VerificationStatus) -> Self {
        Self {
            status,
            verified: false,
            identity_id,
            verified_at: Utc::now(),
            biometric_matched: false,
            liveness_passed: false,
            device_bound: false,
            confidence: None,
            issues: Vec::new(),
        }
    }

    /// Set biometric match status.
    #[must_use]
    pub fn with_biometric(mut self, matched: bool) -> Self {
        self.biometric_matched = matched;
        self
    }

    /// Set liveness status.
    #[must_use]
    pub fn with_liveness(mut self, passed: bool) -> Self {
        self.liveness_passed = passed;
        self
    }

    /// Set device binding status.
    #[must_use]
    pub fn with_device_bound(mut self, bound: bool) -> Self {
        self.device_bound = bound;
        self
    }

    /// Add confidence score.
    #[must_use]
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = Some(confidence.min(100));
        self
    }

    /// Add an issue.
    #[must_use]
    pub fn with_issue(mut self, issue: impl Into<String>) -> Self {
        self.issues.push(issue.into());
        self
    }

    /// Check if verified.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BiometricType;

    #[test]
    fn test_verification_request() {
        let request = VerificationRequest::new(
            IdentityId::new("id-1"),
            BiometricProof::new(BiometricType::Face, [0u8; 32]),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]),
            vec![0u8; 64],
        );

        assert_eq!(request.identity_id.as_str(), "id-1");
        assert_eq!(request.device_signature.len(), 64);
    }

    #[test]
    fn test_verification_result_verified() {
        let result = VerificationResult::verified(IdentityId::new("id-1"));

        assert!(result.is_verified());
        assert_eq!(result.status, VerificationStatus::Verified);
        assert!(result.biometric_matched);
        assert!(result.liveness_passed);
        assert!(result.device_bound);
    }

    #[test]
    fn test_verification_result_failed() {
        let result = VerificationResult::failed(
            IdentityId::new("id-1"),
            VerificationStatus::BiometricMismatch,
        );

        assert!(!result.is_verified());
        assert_eq!(result.status, VerificationStatus::BiometricMismatch);
    }

    #[test]
    fn test_verification_result_with_details() {
        let result = VerificationResult::verified(IdentityId::new("id-1"))
            .with_confidence(95)
            .with_biometric(true)
            .with_liveness(true)
            .with_device_bound(true);

        assert_eq!(result.confidence, Some(95));
        assert!(result.biometric_matched);
        assert!(result.liveness_passed);
        assert!(result.device_bound);
    }

    #[test]
    fn test_verification_result_with_issue() {
        let result =
            VerificationResult::failed(IdentityId::new("id-1"), VerificationStatus::LivenessFailed)
                .with_issue("Confidence too low");

        assert!(!result.issues.is_empty());
        assert_eq!(result.issues[0], "Confidence too low");
    }

    #[test]
    fn test_verification_result_multiple_issues() {
        let result =
            VerificationResult::failed(IdentityId::new("id-1"), VerificationStatus::MultipleFailed)
                .with_issue("Issue 1")
                .with_issue("Issue 2");

        assert_eq!(result.issues.len(), 2);
    }

    #[test]
    fn test_verification_status_serialization() {
        assert_eq!(
            serde_json::to_string(&VerificationStatus::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&VerificationStatus::BiometricMismatch).unwrap(),
            "\"biometric_mismatch\""
        );
    }

    #[test]
    fn test_confidence_cap() {
        let result = VerificationResult::verified(IdentityId::new("id-1")).with_confidence(150);

        assert_eq!(result.confidence, Some(100)); // Capped at 100
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult::verified(IdentityId::new("id-1"));
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"verified\":true"));
        assert!(json.contains("\"status\":\"verified\""));
    }
}
