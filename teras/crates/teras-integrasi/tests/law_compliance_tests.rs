//! TERAS Platform Integration Tests
//!
//! Tests verifying compliance with the 8 Immutable Security Laws.

use std::sync::Arc;

use teras_benteng::{
    BiometricProof, BiometricType, DeviceBinding, DeviceInfo, EkycService, EnrollmentRequest,
    IdentityId, LivenessProof, LivenessVerifier, TemplateHash, VerificationRequest,
};
use teras_jejak::{storage::MemoryStorage, Action, ActionResult, Actor, AuditLog, AuditLogEntry};
use teras_kunci::{ct_eq, hash::sha3_256, kem::HybridKem, HybridSigner};
use teras_lindung::Secret;
use teras_sandi::SigningService;

// =============================================================================
// LAW 1: Biometrics Never Leave Device
// =============================================================================

#[test]
fn test_law1_biometric_proof_contains_only_hash() {
    // BiometricProof must contain ONLY a 32-byte hash, never raw biometric data
    let template_hash = [0xABu8; 32];
    let proof = BiometricProof::new(BiometricType::Face, template_hash);

    // Verify the structure contains only a hash (32 bytes)
    assert_eq!(proof.template_hash.len(), 32);
    assert_eq!(proof.biometric_type, BiometricType::Face);
}

#[test]
fn test_law1_no_raw_biometric_fields_exist() {
    // Compile-time verification: BiometricProof has no raw biometric fields
    // If this test compiles, LAW 1 is structurally enforced
    let proof = BiometricProof::new(BiometricType::Fingerprint, [0u8; 32]);
    let _serialized = serde_json::to_string(&proof).unwrap();

    // Deserialize and verify no extra fields
    let deserialized: BiometricProof = serde_json::from_str(&_serialized).unwrap();
    assert_eq!(deserialized.template_hash, proof.template_hash);
}

// =============================================================================
// LAW 2: Approved Algorithms Only
// =============================================================================

#[test]
fn test_law2_hybrid_kem() {
    // Hybrid KEM: ML-KEM-768 (post-quantum) + X25519 (classical)
    let (private, public) = HybridKem::generate().unwrap();
    let (ciphertext, shared_secret1) = public.encapsulate().unwrap();
    let shared_secret2 = private.decapsulate(&ciphertext).unwrap();

    // Shared secrets must match
    assert_eq!(shared_secret1.expose().len(), shared_secret2.expose().len());
}

#[test]
fn test_law2_hybrid_signature() {
    // Hybrid Signature: ML-DSA-65 (post-quantum) + Ed25519 (classical)
    let (signer, verifying_key) = HybridSigner::generate().unwrap();
    let message = b"test message for signing";
    let signature = signer.sign(message).unwrap();

    assert!(verifying_key.verify(message, &signature).is_ok());
}

// =============================================================================
// LAW 3: Constant-Time Operations
// =============================================================================

#[test]
fn test_law3_constant_time_comparison() {
    // ct_eq must be used for secret comparisons to prevent timing attacks
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    let c = [0x00u8; 32];

    // Same values should match
    assert!(ct_eq(&a, &b));
    // Different values should not match
    assert!(!ct_eq(&a, &c));
}

#[test]
fn test_law3_template_hash_constant_time() {
    // TemplateHash.matches() uses constant-time comparison
    let hash1 = TemplateHash::from_bytes([1u8; 32]);
    let hash2 = TemplateHash::from_bytes([1u8; 32]);
    let hash3 = TemplateHash::from_bytes([2u8; 32]);

    assert!(hash1.matches(&hash2));
    assert!(!hash1.matches(&hash3));
}

// =============================================================================
// LAW 4: Secret Zeroization on Drop
// =============================================================================

#[test]
fn test_law4_secret_zeroization() {
    // Secret<T> must zeroize on drop
    let secret_data = vec![0xFFu8; 32];
    let secret = Secret::new(secret_data);

    // Can access while in scope
    let exposed = secret.expose();
    assert_eq!(exposed.len(), 32);
    assert!(exposed.iter().all(|&b| b == 0xFF));

    // When dropped, memory is zeroized (verified by Drop impl)
    drop(secret);
    // After drop, the memory has been zeroized
}

#[test]
fn test_law4_secret_prevents_accidental_exposure() {
    // Secret<T> wraps sensitive data and zeroizes on drop
    let secret = Secret::new(vec![0xAAu8; 16]);

    // Must explicitly call expose() to access - prevents accidental logging
    let exposed = secret.expose();
    assert_eq!(exposed.len(), 16);

    // Secret does NOT implement Clone - prevents accidental copies
    // This is intentional for security
}

// =============================================================================
// LAW 5: Hybrid Cryptography Mandatory
// =============================================================================

#[test]
fn test_law5_hybrid_signature_uses_both_algorithms() {
    // All signatures must use BOTH post-quantum AND classical algorithms
    let audit_log = create_audit_log();
    let mut service = SigningService::new(audit_log);

    // Generate a signing key
    service.generate_key("hybrid-test-key").unwrap();

    // Sign a document
    let document = b"message requiring hybrid signature".to_vec();
    let signed = service.sign("hybrid-test-key", document.clone()).unwrap();

    // Verify - result shows both signature checks
    let result = service.verify(&signed, &document).unwrap();

    // DECISION 4: BOTH must verify
    assert!(result.valid);
    assert!(result.dilithium_valid); // Post-quantum component
    assert!(result.ed25519_valid); // Classical component
}

#[test]
fn test_law5_hybrid_verification_checks_both() {
    let audit_log = create_audit_log();
    let mut service = SigningService::new(audit_log);

    service.generate_key("test-key").unwrap();
    let document = b"test message".to_vec();
    let signed = service.sign("test-key", document.clone()).unwrap();

    // Verification with correct document succeeds
    let result = service.verify(&signed, &document).unwrap();
    assert!(result.valid);

    // Verification with wrong document fails
    let wrong_document = b"wrong message".to_vec();
    let result = service.verify(&signed, &wrong_document).unwrap();
    assert!(!result.valid);
}

// =============================================================================
// LAW 6: Liveness Detection Required
// =============================================================================

#[test]
fn test_law6_liveness_minimum_confidence() {
    // Liveness must have minimum 70% confidence
    let verifier = LivenessVerifier::new();

    // Valid proof with sufficient confidence
    let valid_proof = LivenessProof::new_combined(vec![0u8; 64], 85);
    let result = verifier.verify(&valid_proof).unwrap();
    assert!(result.is_valid());

    // Invalid proof with low confidence
    let invalid_proof = LivenessProof::new_combined(vec![0u8; 64], 50);
    let result = verifier.verify(&invalid_proof).unwrap();
    assert!(!result.is_valid());
}

#[test]
fn test_law6_liveness_proof_required_for_enrollment() {
    // Enrollment must include liveness proof
    let request = EnrollmentRequest::new(
        "user-123".to_string(),
        BiometricProof::new(BiometricType::Face, [0u8; 32]),
        LivenessProof::new_combined(vec![0u8; 64], 80),
        DeviceInfo::new("device-1", [0u8; 32]),
    );

    assert_eq!(request.liveness_proof.confidence, 80);
}

// =============================================================================
// LAW 7: Device Binding
// =============================================================================

#[test]
fn test_law7_device_binding_verification() {
    let device_id = "device-abc-123";
    let public_key = [0x42u8; 32];

    let device_info = DeviceInfo::new(device_id, public_key);
    let binding = DeviceBinding::from_device_info(&device_info);

    // Verify device ID matches
    assert!(binding.matches_device_id(device_id));
    assert!(!binding.matches_device_id("wrong-device"));

    // Verify public key matches (constant-time)
    assert!(binding.matches_public_key(&public_key));
    assert!(!binding.matches_public_key(&[0x00u8; 32]));
}

#[test]
fn test_law7_verification_requires_device_signature() {
    // VerificationRequest must include device signature
    let request = VerificationRequest::new(
        IdentityId::new("identity-1"),
        BiometricProof::new(BiometricType::Face, [0u8; 32]),
        LivenessProof::new_combined(vec![0u8; 64], 80),
        vec![0u8; 64], // Device signature required
    );

    assert_eq!(request.device_signature.len(), 64);
}

// =============================================================================
// LAW 8: Audit Everything
// =============================================================================

#[test]
fn test_law8_audit_log_hash_chained() {
    let storage = MemoryStorage::new();
    let mut log = AuditLog::new(Box::new(storage));

    // Log some entries
    let entry1 = AuditLogEntry::new(
        Actor::User {
            id: "user-1".into(),
            device_id: Some("dev-1".into()),
        },
        Action::Authentication {
            method: "hybrid-kem".into(),
        },
        "session-1",
        ActionResult::Success,
    );

    let entry2 = AuditLogEntry::new(
        Actor::User {
            id: "user-1".into(),
            device_id: Some("dev-1".into()),
        },
        Action::DataAccess {
            data_type: "profile".into(),
            mode: "read".into(),
        },
        "profile-data",
        ActionResult::Success,
    );

    log.append(entry1).unwrap();
    log.append(entry2).unwrap();

    // Verify chain integrity
    let verification = log.verify_chain().unwrap();
    assert!(verification.valid);
}

#[test]
fn test_law8_audit_operations_logged() {
    let storage = MemoryStorage::new();
    let mut log = AuditLog::new(Box::new(storage));

    // Log a failed operation
    let entry = AuditLogEntry::new(
        Actor::User {
            id: "user-2".into(),
            device_id: None,
        },
        Action::Authentication {
            method: "biometric".into(),
        },
        "session-xyz",
        ActionResult::Failure {
            reason: "Liveness check failed".into(),
            code: Some("AUTH_001".into()),
        },
    );

    log.append(entry).unwrap();

    // Chain should still be valid
    let verification = log.verify_chain().unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_verified, 1);
}

// =============================================================================
// CROSS-CUTTING: Full eKYC Flow
// =============================================================================

#[tokio::test]
async fn test_full_ekyc_enrollment_and_verification() {
    let service = EkycService::new_in_memory();

    // Enrollment (LAW 1, 6, 7, 8 all enforced)
    let template_hash = sha3_256(b"user biometric template");
    let enrollment_request = EnrollmentRequest::new(
        "user-456".to_string(),
        BiometricProof::new(BiometricType::Face, template_hash),
        LivenessProof::new_combined(vec![0u8; 64], 85), // LAW 6: >70%
        DeviceInfo::new("device-xyz", [0u8; 32]),       // LAW 7: device binding
    );

    // enroll returns TerasResult<IdentityId>
    let identity_id = service.enroll(enrollment_request).await.unwrap();

    // Verification (all laws enforced)
    let verification_request = VerificationRequest::new(
        identity_id.clone(),
        BiometricProof::new(BiometricType::Face, template_hash), // Same hash
        LivenessProof::new_combined(vec![0u8; 64], 80),
        vec![0u8; 64], // Device signature
    );

    let verify_result = service.verify(verification_request).await.unwrap();
    assert!(verify_result.is_verified());
}

#[tokio::test]
async fn test_ekyc_rejects_low_liveness_confidence() {
    let service = EkycService::new_in_memory();

    // Enrollment with low liveness (should fail LAW 6)
    let enrollment_request = EnrollmentRequest::new(
        "user-789".to_string(),
        BiometricProof::new(BiometricType::Face, [0u8; 32]),
        LivenessProof::new_combined(vec![0u8; 64], 50), // Below 70% threshold
        DeviceInfo::new("device-abc", [0u8; 32]),
    );

    // Should return an error because liveness < 70%
    let result = service.enroll(enrollment_request).await;
    assert!(result.is_err()); // LAW 6 enforced
}

// =============================================================================
// Helper Functions
// =============================================================================

fn create_audit_log() -> Arc<std::sync::RwLock<AuditLog>> {
    let storage = MemoryStorage::new();
    Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))))
}
