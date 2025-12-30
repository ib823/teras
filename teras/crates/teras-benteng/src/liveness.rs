//! Liveness proof verification.
//!
//! **LAW 6 COMPLIANCE:**
//! All biometric captures MUST include liveness detection.

use crate::types::{LivenessMethod, LivenessProof};
use teras_core::error::TerasResult;

/// Minimum confidence score to accept liveness.
pub const MIN_LIVENESS_CONFIDENCE: u8 = 70;

/// Maximum age of liveness proof in seconds.
pub const MAX_LIVENESS_AGE_SECS: i64 = 300; // 5 minutes

/// Liveness proof verifier.
pub struct LivenessVerifier {
    /// Minimum confidence threshold.
    min_confidence: u8,
    /// Maximum proof age in seconds.
    max_age_secs: i64,
}

impl LivenessVerifier {
    /// Create a new verifier with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_confidence: MIN_LIVENESS_CONFIDENCE,
            max_age_secs: MAX_LIVENESS_AGE_SECS,
        }
    }

    /// Set minimum confidence threshold.
    #[must_use]
    pub fn with_min_confidence(mut self, confidence: u8) -> Self {
        self.min_confidence = confidence;
        self
    }

    /// Set maximum proof age.
    #[must_use]
    pub fn with_max_age_secs(mut self, secs: i64) -> Self {
        self.max_age_secs = secs;
        self
    }

    /// Verify a liveness proof.
    ///
    /// # Errors
    ///
    /// Returns error if verification process fails unexpectedly.
    pub fn verify(&self, proof: &LivenessProof) -> TerasResult<LivenessVerificationResult> {
        let mut result = LivenessVerificationResult {
            is_valid: true,
            method: proof.method,
            confidence: proof.confidence,
            issues: Vec::new(),
        };

        // Check confidence threshold
        if proof.confidence < self.min_confidence {
            result.is_valid = false;
            result.issues.push(format!(
                "Confidence {} below minimum {}",
                proof.confidence, self.min_confidence
            ));
        }

        // Check proof age
        let age = chrono::Utc::now()
            .signed_duration_since(proof.checked_at)
            .num_seconds();

        if age > self.max_age_secs {
            result.is_valid = false;
            result.issues.push(format!(
                "Proof too old: {}s (max {}s)",
                age, self.max_age_secs
            ));
        }

        // Check proof signature is present
        if proof.proof_signature.is_empty() {
            result.is_valid = false;
            result.issues.push("Missing proof signature".to_string());
        }

        // For challenge-response, verify challenge ID is present
        if proof.method == LivenessMethod::ChallengeResponse && proof.challenge_id.is_none() {
            result.is_valid = false;
            result
                .issues
                .push("Missing challenge ID for challenge-response".to_string());
        }

        // NOTE: In production, we would verify the proof_signature
        // against the device's public key. This requires the device
        // public key from the identity record.

        Ok(result)
    }

    /// Verify liveness with a specific challenge.
    ///
    /// For challenge-response liveness, verifies the challenge matches.
    ///
    /// # Errors
    ///
    /// Returns error if verification process fails unexpectedly.
    pub fn verify_with_challenge(
        &self,
        proof: &LivenessProof,
        expected_challenge: &str,
    ) -> TerasResult<LivenessVerificationResult> {
        let mut result = self.verify(proof)?;

        if proof.method == LivenessMethod::ChallengeResponse {
            match &proof.challenge_id {
                Some(challenge) if challenge == expected_challenge => {
                    // Challenge matches
                }
                Some(challenge) => {
                    result.is_valid = false;
                    result.issues.push(format!(
                        "Challenge mismatch: expected '{expected_challenge}', got '{challenge}'"
                    ));
                }
                None => {
                    result.is_valid = false;
                    result.issues.push("Missing challenge ID".to_string());
                }
            }
        }

        Ok(result)
    }
}

impl Default for LivenessVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of liveness verification.
#[derive(Debug, Clone)]
pub struct LivenessVerificationResult {
    /// Whether the liveness check passed.
    pub is_valid: bool,
    /// Method that was verified.
    pub method: LivenessMethod,
    /// Confidence score.
    pub confidence: u8,
    /// Any issues found.
    pub issues: Vec<String>,
}

impl LivenessVerificationResult {
    /// Check if valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_proof() -> LivenessProof {
        LivenessProof::new_challenge_response("test-challenge", [0u8; 64]).with_confidence(85)
    }

    #[test]
    fn test_verify_valid_proof() {
        let verifier = LivenessVerifier::new();
        let proof = create_valid_proof();

        let result = verifier.verify(&proof).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.method, LivenessMethod::ChallengeResponse);
        assert_eq!(result.confidence, 85);
    }

    #[test]
    fn test_verify_low_confidence() {
        let verifier = LivenessVerifier::new();
        let proof = LivenessProof::new_challenge_response("test", [0u8; 64]).with_confidence(50);

        let result = verifier.verify(&proof).unwrap();
        assert!(!result.is_valid());
        assert!(result.issues.iter().any(|i| i.contains("Confidence")));
    }

    #[test]
    fn test_verify_missing_signature() {
        let verifier = LivenessVerifier::new();
        let mut proof = create_valid_proof();
        proof.proof_signature = Vec::new();

        let result = verifier.verify(&proof).unwrap();
        assert!(!result.is_valid());
        assert!(result.issues.iter().any(|i| i.contains("signature")));
    }

    #[test]
    fn test_verify_missing_challenge_id() {
        let verifier = LivenessVerifier::new();
        let mut proof = create_valid_proof();
        proof.challenge_id = None;

        let result = verifier.verify(&proof).unwrap();
        assert!(!result.is_valid());
        assert!(result.issues.iter().any(|i| i.contains("challenge ID")));
    }

    #[test]
    fn test_verify_with_challenge() {
        let verifier = LivenessVerifier::new();
        let proof = LivenessProof::new_challenge_response("expected", [0u8; 64]);

        let result = verifier.verify_with_challenge(&proof, "expected").unwrap();
        assert!(result.is_valid());

        let result = verifier.verify_with_challenge(&proof, "different").unwrap();
        assert!(!result.is_valid());
        assert!(result.issues.iter().any(|i| i.contains("mismatch")));
    }

    #[test]
    fn test_custom_thresholds() {
        let verifier = LivenessVerifier::new().with_min_confidence(90);

        let proof = create_valid_proof(); // confidence = 85
        let result = verifier.verify(&proof).unwrap();

        assert!(!result.is_valid()); // Below new threshold
    }

    #[test]
    fn test_custom_max_age() {
        let verifier = LivenessVerifier::new().with_max_age_secs(600);

        let proof = create_valid_proof();
        let result = verifier.verify(&proof).unwrap();

        assert!(result.is_valid()); // Fresh proof
    }

    #[test]
    fn test_combined_method_no_challenge_required() {
        let verifier = LivenessVerifier::new();
        let proof = LivenessProof::new_combined(vec![0u8; 64], 80);

        let result = verifier.verify(&proof).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.method, LivenessMethod::Combined);
    }

    #[test]
    fn test_default_verifier() {
        let verifier = LivenessVerifier::default();
        let proof = create_valid_proof();

        let result = verifier.verify(&proof).unwrap();
        assert!(result.is_valid());
    }

    #[test]
    fn test_multiple_issues() {
        let verifier = LivenessVerifier::new().with_min_confidence(90);
        let mut proof = create_valid_proof();
        proof.confidence = 50;
        proof.proof_signature = Vec::new();

        let result = verifier.verify(&proof).unwrap();
        assert!(!result.is_valid());
        assert!(result.issues.len() >= 2);
    }
}
