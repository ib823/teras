//! Core types for eKYC/identity verification.
//!
//! These types represent PROOFS of biometrics, not raw biometric data.
//! LAW 1 is enforced by design - these structures cannot hold raw biometrics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of biometric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BiometricType {
    /// Face recognition.
    Face,
    /// Fingerprint.
    Fingerprint,
    /// Iris scan.
    Iris,
    /// Voice print.
    Voice,
}

impl std::fmt::Display for BiometricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Face => write!(f, "face"),
            Self::Fingerprint => write!(f, "fingerprint"),
            Self::Iris => write!(f, "iris"),
            Self::Voice => write!(f, "voice"),
        }
    }
}

/// Biometric proof - a hash of the biometric template.
///
/// **LAW 1 COMPLIANCE:**
/// This structure holds a HASH of the biometric template,
/// NOT the template itself. The hash cannot be reversed to
/// reconstruct the original biometric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricProof {
    /// Type of biometric this proof represents.
    pub biometric_type: BiometricType,

    /// SHA3-256 hash of the biometric template.
    ///
    /// This is computed CLIENT-SIDE from the actual biometric.
    /// The server NEVER sees the original template.
    pub template_hash: [u8; 32],

    /// When this proof was generated.
    pub generated_at: DateTime<Utc>,

    /// Optional: Zero-knowledge proof of template validity.
    /// Proves the template meets quality requirements without
    /// revealing the template itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity_proof: Option<Vec<u8>>,
}

impl BiometricProof {
    /// Create a new biometric proof.
    ///
    /// # Arguments
    ///
    /// * `biometric_type` - Type of biometric
    /// * `template_hash` - SHA3-256 hash of the biometric template
    #[must_use]
    pub fn new(biometric_type: BiometricType, template_hash: [u8; 32]) -> Self {
        Self {
            biometric_type,
            template_hash,
            generated_at: Utc::now(),
            validity_proof: None,
        }
    }

    /// Add a validity proof.
    #[must_use]
    pub fn with_validity_proof(mut self, proof: Vec<u8>) -> Self {
        self.validity_proof = Some(proof);
        self
    }

    /// Get the template hash as hex string.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hex::encode(self.template_hash)
    }
}

/// Liveness detection method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessMethod {
    /// Challenge-response (e.g., "blink", "turn head").
    ChallengeResponse,
    /// Texture analysis.
    TextureAnalysis,
    /// 3D depth detection.
    DepthDetection,
    /// Multi-frame temporal analysis.
    TemporalAnalysis,
    /// Combined methods.
    Combined,
}

/// Proof of liveness - proves the biometric was captured from a live person.
///
/// **LAW 6 COMPLIANCE:**
/// All biometric captures MUST include liveness detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessProof {
    /// Method used for liveness detection.
    pub method: LivenessMethod,

    /// Challenge ID (for challenge-response method).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,

    /// Cryptographic proof of liveness.
    /// This is signed by the client's secure element.
    pub proof_signature: Vec<u8>,

    /// When the liveness check was performed.
    pub checked_at: DateTime<Utc>,

    /// Confidence score (0-100).
    pub confidence: u8,
}

impl LivenessProof {
    /// Create a challenge-response liveness proof.
    #[must_use]
    pub fn new_challenge_response(challenge_id: &str, signature: [u8; 64]) -> Self {
        Self {
            method: LivenessMethod::ChallengeResponse,
            challenge_id: Some(challenge_id.to_string()),
            proof_signature: signature.to_vec(),
            checked_at: Utc::now(),
            confidence: 85, // Default confidence
        }
    }

    /// Create a combined liveness proof.
    #[must_use]
    pub fn new_combined(signature: Vec<u8>, confidence: u8) -> Self {
        Self {
            method: LivenessMethod::Combined,
            challenge_id: None,
            proof_signature: signature,
            checked_at: Utc::now(),
            confidence,
        }
    }

    /// Set confidence level.
    #[must_use]
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }
}

/// Device information for device binding (LAW 7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Unique device identifier.
    pub device_id: String,

    /// Device public key (from secure element/TEE).
    pub device_public_key: [u8; 32],

    /// Device attestation (proves key is from secure hardware).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Vec<u8>>,

    /// Device type/model (for audit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
}

impl DeviceInfo {
    /// Create new device info.
    #[must_use]
    pub fn new(device_id: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            device_id: device_id.into(),
            device_public_key: public_key,
            attestation: None,
            device_type: None,
        }
    }

    /// Add attestation.
    #[must_use]
    pub fn with_attestation(mut self, attestation: Vec<u8>) -> Self {
        self.attestation = Some(attestation);
        self
    }

    /// Add device type.
    #[must_use]
    pub fn with_device_type(mut self, device_type: impl Into<String>) -> Self {
        self.device_type = Some(device_type.into());
        self
    }
}

/// Unique identity identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(String);

impl IdentityId {
    /// Create a new identity ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a random identity ID.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get as string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Status of an identity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    /// Active and can be used for verification.
    Active,
    /// Suspended (temporary).
    Suspended,
    /// Revoked (permanent).
    Revoked,
    /// Pending additional verification.
    Pending,
}

/// Stored identity record.
///
/// **LAW 1 COMPLIANCE:**
/// This record stores HASHES of biometric templates,
/// NOT the templates themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// Unique identity ID.
    pub id: IdentityId,

    /// User ID (external reference).
    pub user_id: String,

    /// Biometric type enrolled.
    pub biometric_type: BiometricType,

    /// Hash of the enrolled biometric template.
    /// **NOT THE TEMPLATE - JUST THE HASH.**
    pub template_hash: [u8; 32],

    /// Bound device ID.
    pub device_id: String,

    /// Device public key.
    pub device_public_key: [u8; 32],

    /// Current status.
    pub status: IdentityStatus,

    /// When enrolled.
    pub enrolled_at: DateTime<Utc>,

    /// Last verification time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<DateTime<Utc>>,

    /// Verification count.
    pub verification_count: u64,
}

impl IdentityRecord {
    /// Check if the identity is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == IdentityStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_type_display() {
        assert_eq!(format!("{}", BiometricType::Face), "face");
        assert_eq!(format!("{}", BiometricType::Fingerprint), "fingerprint");
        assert_eq!(format!("{}", BiometricType::Iris), "iris");
        assert_eq!(format!("{}", BiometricType::Voice), "voice");
    }

    #[test]
    fn test_biometric_proof_creation() {
        let hash = [42u8; 32];
        let proof = BiometricProof::new(BiometricType::Face, hash);

        assert_eq!(proof.biometric_type, BiometricType::Face);
        assert_eq!(proof.template_hash, hash);
    }

    #[test]
    fn test_biometric_proof_hash_hex() {
        let hash = [0xABu8; 32];
        let proof = BiometricProof::new(BiometricType::Face, hash);

        assert!(proof.hash_hex().starts_with("abab"));
        assert_eq!(proof.hash_hex().len(), 64);
    }

    #[test]
    fn test_biometric_proof_with_validity() {
        let hash = [0u8; 32];
        let proof =
            BiometricProof::new(BiometricType::Face, hash).with_validity_proof(vec![1, 2, 3]);

        assert!(proof.validity_proof.is_some());
        assert_eq!(proof.validity_proof.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_liveness_proof_challenge_response() {
        let sig = [0u8; 64];
        let proof = LivenessProof::new_challenge_response("challenge-1", sig);

        assert_eq!(proof.method, LivenessMethod::ChallengeResponse);
        assert_eq!(proof.challenge_id, Some("challenge-1".to_string()));
        assert_eq!(proof.confidence, 85);
    }

    #[test]
    fn test_liveness_proof_combined() {
        let proof = LivenessProof::new_combined(vec![0u8; 64], 95);

        assert_eq!(proof.method, LivenessMethod::Combined);
        assert_eq!(proof.confidence, 95);
        assert!(proof.challenge_id.is_none());
    }

    #[test]
    fn test_liveness_proof_confidence_cap() {
        let proof = LivenessProof::new_combined(vec![], 150);
        let proof = proof.with_confidence(200);

        assert_eq!(proof.confidence, 100); // Capped at 100
    }

    #[test]
    fn test_device_info() {
        let pk = [1u8; 32];
        let device = DeviceInfo::new("device-123", pk)
            .with_device_type("iPhone 15 Pro")
            .with_attestation(vec![1, 2, 3]);

        assert_eq!(device.device_id, "device-123");
        assert_eq!(device.device_type, Some("iPhone 15 Pro".to_string()));
        assert!(device.attestation.is_some());
    }

    #[test]
    fn test_identity_id() {
        let id = IdentityId::new("test-id");
        assert_eq!(id.as_str(), "test-id");
        assert_eq!(format!("{}", id), "test-id");

        let generated = IdentityId::generate();
        assert!(!generated.as_str().is_empty());
        assert!(generated.as_str().contains('-')); // UUID format
    }

    #[test]
    fn test_identity_status() {
        assert_eq!(
            serde_json::to_string(&IdentityStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&IdentityStatus::Suspended).unwrap(),
            "\"suspended\""
        );
    }

    #[test]
    fn test_identity_record_is_active() {
        let record = IdentityRecord {
            id: IdentityId::new("test"),
            user_id: "user-1".to_string(),
            biometric_type: BiometricType::Face,
            template_hash: [0u8; 32],
            device_id: "device-1".to_string(),
            device_public_key: [0u8; 32],
            status: IdentityStatus::Active,
            enrolled_at: Utc::now(),
            last_verified_at: None,
            verification_count: 0,
        };

        assert!(record.is_active());

        let suspended = IdentityRecord {
            status: IdentityStatus::Suspended,
            ..record.clone()
        };
        assert!(!suspended.is_active());
    }

    #[test]
    fn test_biometric_proof_serialization() {
        let proof = BiometricProof::new(BiometricType::Face, [0u8; 32]);
        let json = serde_json::to_string(&proof).unwrap();

        assert!(json.contains("\"biometric_type\":\"face\""));
        assert!(json.contains("\"template_hash\""));
    }
}
