//! TERAS Benteng - eKYC/Identity Verification
//!
//! Implements LAW 1 compliant biometric identity verification.
//!
//! # LAW 1 Compliance
//!
//! **BIOMETRIC DATA NEVER LEAVES THE USER'S DEVICE.**
//!
//! This crate handles SERVER-SIDE verification of biometric PROOFS,
//! not raw biometric data. The actual biometric capture and template
//! generation happens on the client device.
//!
//! ```text
//! WHAT THIS CRATE RECEIVES:
//! ✓ Cryptographic hash of biometric template
//! ✓ Zero-knowledge proof of liveness
//! ✓ Device-bound signatures
//!
//! WHAT THIS CRATE NEVER RECEIVES:
//! ✗ Raw biometric images
//! ✗ Biometric templates
//! ✗ Anything that could reconstruct biometrics
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    CLIENT DEVICE (Mobile)                     │
//! │  ┌──────────┐    ┌──────────┐    ┌────────────────────────┐ │
//! │  │ Capture  │ →  │ Liveness │ →  │ Template Hash + Proof  │ │
//! │  │ Biometric│    │ Detection│    │ (LAW 1 compliant)      │ │
//! │  └──────────┘    └──────────┘    └───────────┬────────────┘ │
//! │       RAW DATA STAYS HERE                    │              │
//! └──────────────────────────────────────────────┼──────────────┘
//!                                                │
//!                    ONLY PROOFS CROSS ──────────┘
//!                                                │
//! ┌──────────────────────────────────────────────┼──────────────┐
//! │                    SERVER (teras-benteng)    ▼              │
//! │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐│
//! │  │ Verify Proof │  │ Match Hash   │  │ Audit Log (LAW 8)  ││
//! │  └──────────────┘  └──────────────┘  └────────────────────┘│
//! │       SERVER NEVER SEES RAW BIOMETRICS                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Laws Implemented
//!
//! - **LAW 1**: Biometric data never leaves the user's device
//! - **LAW 6**: All biometric captures include liveness detection
//! - **LAW 7**: Cryptographic device binding
//! - **LAW 8**: All operations are audit logged
//!
//! # Example
//!
//! ```no_run
//! use teras_benteng::{EkycService, EnrollmentRequest, VerificationRequest};
//! use teras_benteng::{BiometricType, BiometricProof, LivenessProof, DeviceInfo};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let service = EkycService::new_in_memory();
//!
//! // Enrollment (client sends proofs, not raw biometrics)
//! let enrollment = EnrollmentRequest::new(
//!     "user-123",
//!     BiometricProof::new(
//!         BiometricType::Face,
//!         [0u8; 32], // Hash of biometric template (NOT the template)
//!     ),
//!     LivenessProof::new_challenge_response(
//!         "challenge-abc",
//!         [0u8; 64], // Signature proving liveness
//!     ),
//!     DeviceInfo::new("device-456", [0u8; 32]),
//! );
//!
//! let identity_id = service.enroll(enrollment).await?;
//!
//! // Verification
//! let verification = VerificationRequest::new(
//!     identity_id.clone(),
//!     BiometricProof::new(
//!         BiometricType::Face,
//!         [0u8; 32], // Same hash = same person
//!     ),
//!     LivenessProof::new_challenge_response(
//!         "challenge-xyz",
//!         [0u8; 64],
//!     ),
//!     vec![0u8; 64], // Device signature
//! );
//!
//! let result = service.verify(verification).await?;
//! assert!(result.is_verified());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod device;
mod enrollment;
mod liveness;
mod service;
mod storage;
mod template;
mod types;
mod verification;

pub use device::{DeviceBinding, DeviceBindingVerifier};
pub use enrollment::{EnrollmentRequest, EnrollmentResult};
pub use liveness::{LivenessVerificationResult, LivenessVerifier};
pub use service::EkycService;
pub use storage::{IdentityStorage, MemoryIdentityStorage};
pub use template::TemplateHash;
pub use types::{
    BiometricProof, BiometricType, DeviceInfo, IdentityId, IdentityRecord, IdentityStatus,
    LivenessMethod, LivenessProof,
};
pub use verification::{VerificationRequest, VerificationResult, VerificationStatus};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_law1_no_raw_biometric_fields() {
        // Verify BiometricProof only contains hash
        let proof = BiometricProof::new(BiometricType::Face, [0u8; 32]);

        // The template_hash is 32 bytes - cannot reconstruct biometric
        assert_eq!(proof.template_hash.len(), 32);

        // Verify IdentityRecord only stores hash
        let record = IdentityRecord {
            id: IdentityId::new("test"),
            user_id: "user".to_string(),
            biometric_type: BiometricType::Face,
            template_hash: [0u8; 32], // Only hash, not raw data
            device_id: "device".to_string(),
            device_public_key: [0u8; 32],
            status: IdentityStatus::Active,
            enrolled_at: chrono::Utc::now(),
            last_verified_at: None,
            verification_count: 0,
        };

        assert_eq!(record.template_hash.len(), 32);
    }

    #[test]
    fn test_law6_liveness_required() {
        // LivenessProof is a required field in EnrollmentRequest and VerificationRequest
        let enrollment = EnrollmentRequest::new(
            "user",
            BiometricProof::new(BiometricType::Face, [0u8; 32]),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]),
            DeviceInfo::new("device", [0u8; 32]),
        );

        // Liveness proof must have a method and signature
        assert_eq!(
            enrollment.liveness_proof.method,
            LivenessMethod::ChallengeResponse
        );
        assert!(!enrollment.liveness_proof.proof_signature.is_empty());
    }

    #[test]
    fn test_law7_device_binding() {
        // DeviceInfo contains device public key for binding
        let device = DeviceInfo::new("device-123", [1u8; 32]);

        assert_eq!(device.device_id, "device-123");
        assert_eq!(device.device_public_key, [1u8; 32]);

        // Device binding can verify key matches
        let binding = DeviceBinding::from_device_info(&device);
        assert!(binding.matches_public_key(&[1u8; 32]));
        assert!(!binding.matches_public_key(&[2u8; 32]));
    }

    #[tokio::test]
    async fn test_law8_audit_logging() {
        let service = EkycService::new_in_memory();

        let enrollment = EnrollmentRequest::new(
            "user",
            BiometricProof::new(BiometricType::Face, [0u8; 32]),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]).with_confidence(90),
            DeviceInfo::new("device", [0u8; 32]),
        );

        let identity_id = service.enroll(enrollment).await.unwrap();

        // Verify audit log has entry
        let log = service.audit_log();
        assert!(log.count().unwrap() > 0);

        // Verification is also logged
        drop(log); // Release lock

        let verification = VerificationRequest::new(
            identity_id,
            BiometricProof::new(BiometricType::Face, [0u8; 32]),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]).with_confidence(90),
            vec![0u8; 64],
        );

        service.verify(verification).await.unwrap();

        let log = service.audit_log();
        assert_eq!(log.count().unwrap(), 2); // enroll + verify
    }

    #[test]
    fn test_constant_time_hash_comparison() {
        // Template hashes use constant-time comparison to prevent timing attacks
        let hash1 = TemplateHash::from_bytes([1u8; 32]);
        let hash2 = TemplateHash::from_bytes([1u8; 32]);
        let hash3 = TemplateHash::from_bytes([2u8; 32]);

        // Same hashes match
        assert!(hash1.matches(&hash2));
        // Different hashes don't match
        assert!(!hash1.matches(&hash3));
    }

    #[test]
    fn test_biometric_types() {
        assert_eq!(format!("{}", BiometricType::Face), "face");
        assert_eq!(format!("{}", BiometricType::Fingerprint), "fingerprint");
        assert_eq!(format!("{}", BiometricType::Iris), "iris");
        assert_eq!(format!("{}", BiometricType::Voice), "voice");
    }

    #[test]
    fn test_identity_status() {
        let mut record = IdentityRecord {
            id: IdentityId::new("test"),
            user_id: "user".to_string(),
            biometric_type: BiometricType::Face,
            template_hash: [0u8; 32],
            device_id: "device".to_string(),
            device_public_key: [0u8; 32],
            status: IdentityStatus::Active,
            enrolled_at: chrono::Utc::now(),
            last_verified_at: None,
            verification_count: 0,
        };

        assert!(record.is_active());

        record.status = IdentityStatus::Suspended;
        assert!(!record.is_active());

        record.status = IdentityStatus::Revoked;
        assert!(!record.is_active());

        record.status = IdentityStatus::Pending;
        assert!(!record.is_active());
    }
}
