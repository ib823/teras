//! Identity enrollment.
//!
//! Handles the enrollment of new identities with biometric proofs.

use crate::types::{BiometricProof, DeviceInfo, IdentityId, LivenessProof};
use serde::{Deserialize, Serialize};

/// Request to enroll a new identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// External user ID.
    pub user_id: String,

    /// Biometric proof (hash, not raw data - LAW 1).
    pub biometric_proof: BiometricProof,

    /// Liveness proof (LAW 6).
    pub liveness_proof: LivenessProof,

    /// Device information for binding (LAW 7).
    pub device_info: DeviceInfo,
}

impl EnrollmentRequest {
    /// Create a new enrollment request.
    #[must_use]
    pub fn new(
        user_id: impl Into<String>,
        biometric_proof: BiometricProof,
        liveness_proof: LivenessProof,
        device_info: DeviceInfo,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            biometric_proof,
            liveness_proof,
            device_info,
        }
    }
}

/// Result of enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResult {
    /// Whether enrollment succeeded.
    pub success: bool,

    /// The created identity ID (if successful).
    pub identity_id: Option<IdentityId>,

    /// Error message (if failed).
    pub error: Option<String>,

    /// Warnings (non-fatal issues).
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl EnrollmentResult {
    /// Create a successful result.
    #[must_use]
    pub fn success(identity_id: IdentityId) -> Self {
        Self {
            success: true,
            identity_id: Some(identity_id),
            error: None,
            warnings: Vec::new(),
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            identity_id: None,
            error: Some(error.into()),
            warnings: Vec::new(),
        }
    }

    /// Add a warning.
    #[must_use]
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Check if successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.success
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BiometricType;

    #[test]
    fn test_enrollment_request_creation() {
        let request = EnrollmentRequest::new(
            "user-123",
            BiometricProof::new(BiometricType::Face, [0u8; 32]),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]),
            DeviceInfo::new("device-1", [0u8; 32]),
        );

        assert_eq!(request.user_id, "user-123");
        assert_eq!(request.biometric_proof.biometric_type, BiometricType::Face);
    }

    #[test]
    fn test_enrollment_result_success() {
        let id = IdentityId::new("id-1");
        let result = EnrollmentResult::success(id.clone());

        assert!(result.is_success());
        assert_eq!(result.identity_id, Some(id));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_enrollment_result_failure() {
        let result = EnrollmentResult::failure("Liveness check failed");

        assert!(!result.is_success());
        assert!(result.identity_id.is_none());
        assert_eq!(result.error, Some("Liveness check failed".to_string()));
    }

    #[test]
    fn test_enrollment_result_with_warning() {
        let id = IdentityId::new("id-1");
        let result = EnrollmentResult::success(id).with_warning("Low confidence score");

        assert!(result.is_success());
        assert!(!result.warnings.is_empty());
        assert_eq!(result.warnings[0], "Low confidence score");
    }

    #[test]
    fn test_enrollment_result_multiple_warnings() {
        let id = IdentityId::new("id-1");
        let result = EnrollmentResult::success(id)
            .with_warning("Warning 1")
            .with_warning("Warning 2");

        assert_eq!(result.warnings.len(), 2);
    }

    #[test]
    fn test_enrollment_request_serialization() {
        let request = EnrollmentRequest::new(
            "user-123",
            BiometricProof::new(BiometricType::Face, [0u8; 32]),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]),
            DeviceInfo::new("device-1", [0u8; 32]),
        );

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"user_id\":\"user-123\""));
    }

    #[test]
    fn test_enrollment_result_serialization() {
        let result = EnrollmentResult::success(IdentityId::new("id-1"));
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"success\":true"));
    }
}
