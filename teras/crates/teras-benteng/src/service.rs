//! High-level eKYC service.
//!
//! Provides audited identity operations.

#![allow(clippy::unused_async)] // Async kept for future extensibility
#![allow(clippy::too_many_lines)] // Complex verification logic is intentionally detailed
#![allow(clippy::manual_let_else)] // Explicit match is clearer for error handling
#![allow(clippy::single_match_else)] // Explicit match is clearer for error handling

use std::sync::Arc;

use chrono::Utc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::storage::MemoryStorage as AuditMemoryStorage;
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};

use crate::device::{DeviceBinding, DeviceBindingVerifier};
use crate::enrollment::EnrollmentRequest;
use crate::liveness::LivenessVerifier;
use crate::storage::{IdentityStorage, MemoryIdentityStorage};
use crate::template::TemplateHash;
use crate::types::{IdentityId, IdentityRecord, IdentityStatus};
use crate::verification::{VerificationRequest, VerificationResult, VerificationStatus};

/// High-level eKYC service with audit logging.
///
/// **LAW 1, 6, 7, 8 COMPLIANCE:**
/// - LAW 1: Only receives biometric hashes, never raw data
/// - LAW 6: Requires liveness proof for all operations
/// - LAW 7: Verifies device binding
/// - LAW 8: All operations are audit logged
pub struct EkycService<S: IdentityStorage = MemoryIdentityStorage> {
    storage: S,
    liveness_verifier: LivenessVerifier,
    device_verifier: DeviceBindingVerifier,
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
}

impl EkycService<MemoryIdentityStorage> {
    /// Create a new service with in-memory storage.
    #[must_use]
    pub fn new_in_memory() -> Self {
        let audit_storage = AuditMemoryStorage::new();
        let audit_log = AuditLog::new(Box::new(audit_storage));

        Self {
            storage: MemoryIdentityStorage::new(),
            liveness_verifier: LivenessVerifier::new(),
            device_verifier: DeviceBindingVerifier::new(),
            audit_log: Arc::new(std::sync::RwLock::new(audit_log)),
        }
    }
}

impl<S: IdentityStorage> EkycService<S> {
    /// Create with custom storage.
    pub fn with_storage(storage: S) -> Self {
        let audit_storage = AuditMemoryStorage::new();
        let audit_log = AuditLog::new(Box::new(audit_storage));

        Self {
            storage,
            liveness_verifier: LivenessVerifier::new(),
            device_verifier: DeviceBindingVerifier::new(),
            audit_log: Arc::new(std::sync::RwLock::new(audit_log)),
        }
    }

    fn log_operation(
        &self,
        operation: &str,
        identity_id: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<()> {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "teras-benteng".to_string(),
            },
            Action::Authentication {
                method: operation.to_string(),
            },
            format!("ekyc:{identity_id}"),
            result,
        )
        .with_context(context.unwrap_or_default());

        let mut log = self
            .audit_log
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        log.append(entry)?;
        Ok(())
    }

    /// Enroll a new identity.
    ///
    /// **LAW 1:** The `biometric_proof` contains a HASH, not raw biometric data.
    ///
    /// # Errors
    ///
    /// Returns error if enrollment fails.
    pub async fn enroll(&self, request: EnrollmentRequest) -> TerasResult<IdentityId> {
        // Verify liveness (LAW 6)
        let liveness_result = self.liveness_verifier.verify(&request.liveness_proof)?;
        if !liveness_result.is_valid() {
            self.log_operation(
                "enroll",
                &request.user_id,
                ActionResult::Failure {
                    reason: "Liveness check failed".to_string(),
                    code: Some("LIVENESS_FAILED".to_string()),
                },
                Some(Context::new().with_extra("issues", liveness_result.issues.join(", "))),
            )?;

            return Err(TerasError::BiometricEnrollmentFailed {
                reason: format!("Liveness check failed: {:?}", liveness_result.issues),
            });
        }

        // Create identity record
        let identity_id = IdentityId::generate();
        let record = IdentityRecord {
            id: identity_id.clone(),
            user_id: request.user_id.clone(),
            biometric_type: request.biometric_proof.biometric_type,
            template_hash: request.biometric_proof.template_hash,
            device_id: request.device_info.device_id.clone(),
            device_public_key: request.device_info.device_public_key,
            status: IdentityStatus::Active,
            enrolled_at: Utc::now(),
            last_verified_at: None,
            verification_count: 0,
        };

        // Store
        self.storage.store(record)?;

        // Log success (LAW 8)
        self.log_operation(
            "enroll",
            identity_id.as_str(),
            ActionResult::Success,
            Some(
                Context::new()
                    .with_extra("user_id", request.user_id)
                    .with_extra(
                        "biometric_type",
                        request.biometric_proof.biometric_type.to_string(),
                    )
                    .with_extra("device_id", request.device_info.device_id),
            ),
        )?;

        Ok(identity_id)
    }

    /// Verify an identity.
    ///
    /// **LAW 1:** Compares biometric HASHES, never sees raw biometrics.
    ///
    /// # Errors
    ///
    /// Returns error if verification process fails.
    pub async fn verify(&self, request: VerificationRequest) -> TerasResult<VerificationResult> {
        // Get stored identity
        let record = match self.storage.get(&request.identity_id)? {
            Some(r) => r,
            None => {
                self.log_operation(
                    "verify",
                    request.identity_id.as_str(),
                    ActionResult::Failure {
                        reason: "Identity not found".to_string(),
                        code: Some("NOT_FOUND".to_string()),
                    },
                    None,
                )?;

                return Ok(VerificationResult::failed(
                    request.identity_id,
                    VerificationStatus::IdentityNotFound,
                ));
            }
        };

        // Check identity is active
        if !record.is_active() {
            self.log_operation(
                "verify",
                request.identity_id.as_str(),
                ActionResult::Failure {
                    reason: "Identity not active".to_string(),
                    code: Some("INACTIVE".to_string()),
                },
                None,
            )?;

            return Ok(VerificationResult::failed(
                request.identity_id,
                VerificationStatus::IdentityInactive,
            ));
        }

        let mut result = VerificationResult::verified(request.identity_id.clone());
        let mut issues = Vec::new();

        // Verify biometric hash (LAW 1 - comparing hashes, not raw data)
        let stored_hash = TemplateHash::from_bytes(record.template_hash);
        let provided_hash = TemplateHash::from_bytes(request.biometric_proof.template_hash);

        let biometric_matched = stored_hash.matches(&provided_hash);
        result = result.with_biometric(biometric_matched);
        if !biometric_matched {
            issues.push("Biometric hash mismatch".to_string());
        }

        // Verify liveness (LAW 6)
        let liveness_result = self.liveness_verifier.verify(&request.liveness_proof)?;
        let liveness_valid = liveness_result.is_valid();
        let liveness_confidence = liveness_result.confidence;
        result = result
            .with_liveness(liveness_valid)
            .with_confidence(liveness_confidence);
        if !liveness_valid {
            issues.extend(liveness_result.issues);
        }

        // Verify device binding (LAW 7)
        let stored_binding = DeviceBinding {
            device_id: record.device_id.clone(),
            public_key: record.device_public_key,
        };

        let device_valid = self.device_verifier.verify_signature(
            &stored_binding,
            &[],
            &request.device_signature,
        )?;
        result = result.with_device_bound(device_valid);
        if !device_valid {
            issues.push("Device signature invalid".to_string());
        }

        // Determine final status
        let verified = biometric_matched && liveness_valid && device_valid;

        if !verified {
            result.verified = false;
            result.status = if !biometric_matched {
                VerificationStatus::BiometricMismatch
            } else if !liveness_valid {
                VerificationStatus::LivenessFailed
            } else if !device_valid {
                VerificationStatus::DeviceMismatch
            } else {
                VerificationStatus::MultipleFailed
            };

            for issue in issues {
                result = result.with_issue(issue);
            }
        }

        // Update verification count
        if verified {
            self.storage.update_verified(&request.identity_id)?;
        }

        // Log result (LAW 8)
        self.log_operation(
            "verify",
            request.identity_id.as_str(),
            if verified {
                ActionResult::Success
            } else {
                ActionResult::Failure {
                    reason: format!("{:?}", result.status),
                    code: None,
                }
            },
            Some(
                Context::new()
                    .with_extra("biometric_matched", biometric_matched.to_string())
                    .with_extra("liveness_passed", liveness_valid.to_string())
                    .with_extra("device_bound", device_valid.to_string()),
            ),
        )?;

        Ok(result)
    }

    /// Revoke an identity.
    ///
    /// # Errors
    ///
    /// Returns error if revocation fails.
    pub async fn revoke(&self, identity_id: &IdentityId, reason: &str) -> TerasResult<bool> {
        let updated = self
            .storage
            .update_status(identity_id, IdentityStatus::Revoked)?;

        self.log_operation(
            "revoke",
            identity_id.as_str(),
            if updated {
                ActionResult::Success
            } else {
                ActionResult::Failure {
                    reason: "Identity not found".to_string(),
                    code: None,
                }
            },
            Some(Context::new().with_extra("reason", reason.to_string())),
        )?;

        Ok(updated)
    }

    /// Suspend an identity (temporary).
    ///
    /// # Errors
    ///
    /// Returns error if suspension fails.
    pub async fn suspend(&self, identity_id: &IdentityId, reason: &str) -> TerasResult<bool> {
        let updated = self
            .storage
            .update_status(identity_id, IdentityStatus::Suspended)?;

        self.log_operation(
            "suspend",
            identity_id.as_str(),
            if updated {
                ActionResult::Success
            } else {
                ActionResult::Failure {
                    reason: "Identity not found".to_string(),
                    code: None,
                }
            },
            Some(Context::new().with_extra("reason", reason.to_string())),
        )?;

        Ok(updated)
    }

    /// Reactivate a suspended identity.
    ///
    /// # Errors
    ///
    /// Returns error if reactivation fails.
    pub async fn reactivate(&self, identity_id: &IdentityId) -> TerasResult<bool> {
        // First check if it exists and is suspended
        let record = self.storage.get(identity_id)?;
        if let Some(r) = record {
            if r.status != IdentityStatus::Suspended {
                return Ok(false); // Can only reactivate suspended identities
            }
        } else {
            return Ok(false);
        }

        let updated = self
            .storage
            .update_status(identity_id, IdentityStatus::Active)?;

        self.log_operation(
            "reactivate",
            identity_id.as_str(),
            if updated {
                ActionResult::Success
            } else {
                ActionResult::Failure {
                    reason: "Identity not found or not suspended".to_string(),
                    code: None,
                }
            },
            None,
        )?;

        Ok(updated)
    }

    /// Get an identity record.
    ///
    /// # Errors
    ///
    /// Returns error if retrieval fails.
    pub fn get_identity(&self, identity_id: &IdentityId) -> TerasResult<Option<IdentityRecord>> {
        self.storage.get(identity_id)
    }

    /// Get identities for a user.
    ///
    /// # Errors
    ///
    /// Returns error if retrieval fails.
    pub fn get_user_identities(&self, user_id: &str) -> TerasResult<Vec<IdentityRecord>> {
        self.storage.get_by_user(user_id)
    }

    /// Get the audit log.
    ///
    /// # Panics
    ///
    /// Panics if the audit log lock is poisoned.
    pub fn audit_log(&self) -> std::sync::RwLockReadGuard<'_, AuditLog> {
        self.audit_log.read().expect("Audit log lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BiometricProof, BiometricType, DeviceInfo, LivenessProof};

    fn create_enrollment_request(user_id: &str, template_hash: [u8; 32]) -> EnrollmentRequest {
        EnrollmentRequest::new(
            user_id,
            BiometricProof::new(BiometricType::Face, template_hash),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]).with_confidence(90),
            DeviceInfo::new("device-1", [1u8; 32]),
        )
    }

    fn create_verification_request(
        identity_id: IdentityId,
        template_hash: [u8; 32],
    ) -> VerificationRequest {
        VerificationRequest::new(
            identity_id,
            BiometricProof::new(BiometricType::Face, template_hash),
            LivenessProof::new_challenge_response("challenge", [0u8; 64]).with_confidence(90),
            vec![0u8; 64], // Device signature
        )
    }

    #[tokio::test]
    async fn test_enroll_success() {
        let service = EkycService::new_in_memory();
        let template_hash = [42u8; 32];

        let enrollment = create_enrollment_request("user-1", template_hash);
        let identity_id = service.enroll(enrollment).await.unwrap();

        assert!(!identity_id.as_str().is_empty());
    }

    #[tokio::test]
    async fn test_enroll_and_verify() {
        let service = EkycService::new_in_memory();
        let template_hash = [42u8; 32];

        // Enroll
        let enrollment = create_enrollment_request("user-1", template_hash);
        let identity_id = service.enroll(enrollment).await.unwrap();

        // Verify with same hash
        let verification = create_verification_request(identity_id.clone(), template_hash);
        let result = service.verify(verification).await.unwrap();

        assert!(result.is_verified());
        assert!(result.biometric_matched);
        assert!(result.liveness_passed);
    }

    #[tokio::test]
    async fn test_verify_wrong_biometric() {
        let service = EkycService::new_in_memory();

        // Enroll with one hash
        let enrollment = create_enrollment_request("user-1", [1u8; 32]);
        let identity_id = service.enroll(enrollment).await.unwrap();

        // Verify with different hash
        let verification = create_verification_request(identity_id, [2u8; 32]);
        let result = service.verify(verification).await.unwrap();

        assert!(!result.is_verified());
        assert!(!result.biometric_matched);
        assert_eq!(result.status, VerificationStatus::BiometricMismatch);
    }

    #[tokio::test]
    async fn test_verify_nonexistent() {
        let service = EkycService::new_in_memory();

        let verification = create_verification_request(IdentityId::new("nonexistent"), [0u8; 32]);
        let result = service.verify(verification).await.unwrap();

        assert!(!result.is_verified());
        assert_eq!(result.status, VerificationStatus::IdentityNotFound);
    }

    #[tokio::test]
    async fn test_revoke_identity() {
        let service = EkycService::new_in_memory();

        let enrollment = create_enrollment_request("user-1", [0u8; 32]);
        let identity_id = service.enroll(enrollment).await.unwrap();

        // Revoke
        let revoked = service
            .revoke(&identity_id, "Fraud detected")
            .await
            .unwrap();
        assert!(revoked);

        // Try to verify - should fail as inactive
        let verification = create_verification_request(identity_id, [0u8; 32]);
        let result = service.verify(verification).await.unwrap();

        assert!(!result.is_verified());
        assert_eq!(result.status, VerificationStatus::IdentityInactive);
    }

    #[tokio::test]
    async fn test_suspend_and_reactivate() {
        let service = EkycService::new_in_memory();

        let enrollment = create_enrollment_request("user-1", [0u8; 32]);
        let identity_id = service.enroll(enrollment).await.unwrap();

        // Suspend
        let suspended = service
            .suspend(&identity_id, "Temporary suspension")
            .await
            .unwrap();
        assert!(suspended);

        // Verify fails
        let verification = create_verification_request(identity_id.clone(), [0u8; 32]);
        let result = service.verify(verification).await.unwrap();
        assert!(!result.is_verified());

        // Reactivate
        let reactivated = service.reactivate(&identity_id).await.unwrap();
        assert!(reactivated);

        // Verify succeeds again
        let verification = create_verification_request(identity_id, [0u8; 32]);
        let result = service.verify(verification).await.unwrap();
        assert!(result.is_verified());
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let service = EkycService::new_in_memory();

        let enrollment = create_enrollment_request("user-1", [0u8; 32]);
        let identity_id = service.enroll(enrollment).await.unwrap();

        let verification = create_verification_request(identity_id, [0u8; 32]);
        service.verify(verification).await.unwrap();

        // Check audit log (LAW 8)
        let log = service.audit_log();
        assert_eq!(log.count().unwrap(), 2); // enroll + verify
        assert!(log.verify_chain().unwrap().valid);
    }

    #[tokio::test]
    async fn test_low_liveness_confidence_fails() {
        let service = EkycService::new_in_memory();

        let mut enrollment = create_enrollment_request("user-1", [0u8; 32]);
        enrollment.liveness_proof =
            LivenessProof::new_challenge_response("challenge", [0u8; 64]).with_confidence(50); // Below threshold

        let result = service.enroll(enrollment).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_identity() {
        let service = EkycService::new_in_memory();

        let enrollment = create_enrollment_request("user-1", [0u8; 32]);
        let identity_id = service.enroll(enrollment).await.unwrap();

        let record = service.get_identity(&identity_id).unwrap().unwrap();
        assert_eq!(record.user_id, "user-1");
    }

    #[tokio::test]
    async fn test_get_user_identities() {
        let service = EkycService::new_in_memory();

        // Enroll multiple identities for same user
        let enrollment1 = create_enrollment_request("user-1", [1u8; 32]);
        service.enroll(enrollment1).await.unwrap();

        let mut enrollment2 = create_enrollment_request("user-1", [2u8; 32]);
        enrollment2.biometric_proof = BiometricProof::new(BiometricType::Fingerprint, [2u8; 32]);
        service.enroll(enrollment2).await.unwrap();

        let identities = service.get_user_identities("user-1").unwrap();
        assert_eq!(identities.len(), 2);
    }

    #[tokio::test]
    async fn test_verification_increments_count() {
        let service = EkycService::new_in_memory();

        let enrollment = create_enrollment_request("user-1", [0u8; 32]);
        let identity_id = service.enroll(enrollment).await.unwrap();

        // Verify multiple times
        for _ in 0..3 {
            let verification = create_verification_request(identity_id.clone(), [0u8; 32]);
            service.verify(verification).await.unwrap();
        }

        let record = service.get_identity(&identity_id).unwrap().unwrap();
        assert_eq!(record.verification_count, 3);
    }

    #[tokio::test]
    async fn test_reactivate_only_suspended() {
        let service = EkycService::new_in_memory();

        let enrollment = create_enrollment_request("user-1", [0u8; 32]);
        let identity_id = service.enroll(enrollment).await.unwrap();

        // Try to reactivate active identity
        let result = service.reactivate(&identity_id).await.unwrap();
        assert!(!result); // Should fail - not suspended
    }
}
