//! Signature verification with hybrid signatures.
//!
//! DECISION 4: BOTH Dilithium3 AND Ed25519 must verify for signature to be valid.
//! LAW 8: All verification operations are logged.

use crate::types::{SignedDocument, VerificationResult};
use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};
use teras_kunci::hash::blake3_hash;
use teras_kunci::sign::{
    Dilithium3Signature, Ed25519Signature, HybridSignature, HybridVerifyingKey,
};

/// Signature verifier for hybrid post-quantum signatures.
///
/// DECISION 4 compliant: Both signatures must verify.
/// All operations are logged per LAW 8.
pub struct SignatureVerifier {
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
}

impl SignatureVerifier {
    /// Create a new signature verifier.
    ///
    /// # Arguments
    ///
    /// * `audit_log` - Audit log for LAW 8 compliance
    #[must_use]
    pub fn new(audit_log: Arc<std::sync::RwLock<AuditLog>>) -> Self {
        Self { audit_log }
    }

    /// Verify a signed document against the original document.
    ///
    /// # Arguments
    ///
    /// * `signed_doc` - The signed document to verify
    /// * `original_document` - The original document bytes
    /// * `verifying_key` - The public key to verify against
    ///
    /// # Returns
    ///
    /// Returns a detailed verification result.
    ///
    /// # Errors
    ///
    /// Returns error if audit logging fails.
    pub fn verify_document(
        &self,
        signed_doc: &SignedDocument,
        original_document: &[u8],
        verifying_key: &HybridVerifyingKey,
    ) -> TerasResult<VerificationResult> {
        let mut result = VerificationResult::success();

        // Step 1: Verify document hash
        let computed_hash = blake3_hash(original_document);
        let hash_matches = computed_hash.as_slice() == signed_doc.document_hash.as_slice();
        result = result.with_hash(hash_matches);

        if !hash_matches {
            self.log_verification(
                &signed_doc.id.to_string(),
                ActionResult::Failure {
                    reason: "Document hash mismatch".to_string(),
                    code: Some("HASH_MISMATCH".to_string()),
                },
                None,
            )?;
            return Ok(result);
        }

        // Step 2: Verify hybrid signature (DECISION 4: both must verify)
        let (dilithium_valid, ed25519_valid) = Self::verify_hybrid_signature_components(
            &signed_doc.document_hash,
            &signed_doc.dilithium_signature,
            &signed_doc.ed25519_signature,
            verifying_key,
        );

        result = result
            .with_dilithium(dilithium_valid)
            .with_ed25519(ed25519_valid);

        // Log verification result (LAW 8)
        let action_result = if result.valid {
            ActionResult::Success
        } else {
            ActionResult::Failure {
                reason: result
                    .error
                    .clone()
                    .unwrap_or_else(|| "Unknown error".to_string()),
                code: None,
            }
        };

        self.log_verification(
            &signed_doc.id.to_string(),
            action_result,
            Some(
                Context::new()
                    .with_extra("dilithium_valid", result.dilithium_valid.to_string())
                    .with_extra("ed25519_valid", result.ed25519_valid.to_string())
                    .with_extra("hash_valid", result.hash_valid.to_string()),
            ),
        )?;

        Ok(result)
    }

    /// Verify a hybrid signature directly.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The hybrid signature
    /// * `verifying_key` - The public key
    ///
    /// # Returns
    ///
    /// Returns verification result.
    ///
    /// # Errors
    ///
    /// Returns error if verification or audit logging fails.
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &HybridSignature,
        verifying_key: &HybridVerifyingKey,
    ) -> TerasResult<VerificationResult> {
        let verify_result = verifying_key.verify(message, signature);

        let result = if verify_result.is_ok() {
            VerificationResult::success()
        } else {
            // Determine which component failed
            let dilithium_ok = verifying_key
                .dilithium_vk()
                .verify(message, signature.dilithium_sig())
                .is_ok();
            let ed25519_ok = verifying_key
                .ed25519_vk()
                .verify(message, signature.ed25519_sig())
                .is_ok();

            VerificationResult::success()
                .with_dilithium(dilithium_ok)
                .with_ed25519(ed25519_ok)
        };

        // Log verification (LAW 8)
        let action_result = if result.valid {
            ActionResult::Success
        } else {
            ActionResult::Failure {
                reason: result
                    .error
                    .clone()
                    .unwrap_or_else(|| "Signature invalid".to_string()),
                code: None,
            }
        };

        self.log_verification(
            "direct",
            action_result,
            Some(Context::new().with_extra("message_size", message.len().to_string())),
        )?;

        Ok(result)
    }

    /// Verify separate signature components.
    fn verify_hybrid_signature_components(
        hash: &[u8],
        dilithium_sig_bytes: &[u8],
        ed25519_sig_bytes: &[u8],
        verifying_key: &HybridVerifyingKey,
    ) -> (bool, bool) {
        // Reconstruct Dilithium signature and verify
        let dilithium_sig = Dilithium3Signature::from_bytes(dilithium_sig_bytes);
        let dilithium_valid = verifying_key
            .dilithium_vk()
            .verify(hash, &dilithium_sig)
            .is_ok();

        // Reconstruct Ed25519 signature and verify
        let ed25519_valid = match Ed25519Signature::from_bytes(ed25519_sig_bytes) {
            Some(ed25519_sig) => verifying_key
                .ed25519_vk()
                .verify(hash, &ed25519_sig)
                .is_ok(),
            None => false,
        };

        (dilithium_valid, ed25519_valid)
    }

    fn log_verification(
        &self,
        document_id: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<u64> {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "teras-sandi".to_string(),
            },
            Action::SecurityEvent {
                event_type: "signature_verification".to_string(),
                severity: match &result {
                    ActionResult::Success => "info".to_string(),
                    ActionResult::Failure { .. }
                    | ActionResult::Denied { .. }
                    | ActionResult::Pending { .. } => "warning".to_string(),
                },
            },
            format!("verifier:{document_id}"),
            result,
        )
        .with_context(context.unwrap_or_default());

        let mut log = self
            .audit_log
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        log.append(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::DocumentSigner;
    use crate::types::SignatureRequest;
    use teras_jejak::storage::MemoryStorage;

    fn create_audit_log() -> Arc<std::sync::RwLock<AuditLog>> {
        let storage = MemoryStorage::new();
        Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))))
    }

    #[test]
    fn test_verify_signature_success() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("verify-key", audit_log.clone()).unwrap();
        let verifier = SignatureVerifier::new(audit_log);

        let message = b"test message";
        let signature = signer.sign_bytes(message).unwrap();

        let result = verifier
            .verify_signature(message, &signature, signer.verifying_key())
            .unwrap();

        assert!(result.valid);
        assert!(result.dilithium_valid);
        assert!(result.ed25519_valid);
    }

    #[test]
    fn test_verify_signature_wrong_message() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("wrong-msg-key", audit_log.clone()).unwrap();
        let verifier = SignatureVerifier::new(audit_log);

        let signature = signer.sign_bytes(b"message1").unwrap();

        let result = verifier
            .verify_signature(b"message2", &signature, signer.verifying_key())
            .unwrap();

        // DECISION 4: Both must verify
        assert!(!result.valid);
    }

    #[test]
    fn test_verify_document_success() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("doc-key", audit_log.clone()).unwrap();
        let verifier = SignatureVerifier::new(audit_log);

        let document = b"important document content";
        let request = SignatureRequest::new("doc-key", document.to_vec());
        let signed = signer.sign(&request).unwrap();

        let result = verifier
            .verify_document(&signed, document, signer.verifying_key())
            .unwrap();

        assert!(result.valid);
        assert!(result.hash_valid);
        assert!(result.dilithium_valid);
        assert!(result.ed25519_valid);
    }

    #[test]
    fn test_verify_document_tampered() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("tamper-key", audit_log.clone()).unwrap();
        let verifier = SignatureVerifier::new(audit_log);

        let original = b"original document";
        let request = SignatureRequest::new("tamper-key", original.to_vec());
        let signed = signer.sign(&request).unwrap();

        // Verify with tampered document
        let tampered = b"tampered document";
        let result = verifier
            .verify_document(&signed, tampered, signer.verifying_key())
            .unwrap();

        assert!(!result.valid);
        assert!(!result.hash_valid);
    }

    #[test]
    fn test_verify_wrong_key() {
        let audit_log = create_audit_log();
        let signer1 = DocumentSigner::new("signer1", audit_log.clone()).unwrap();
        let signer2 = DocumentSigner::new("signer2", audit_log.clone()).unwrap();
        let verifier = SignatureVerifier::new(audit_log);

        let document = b"test document";
        let request = SignatureRequest::new("signer1", document.to_vec());
        let signed = signer1.sign(&request).unwrap();

        // Verify with wrong key
        let result = verifier
            .verify_document(&signed, document, signer2.verifying_key())
            .unwrap();

        assert!(!result.valid);
    }
}
