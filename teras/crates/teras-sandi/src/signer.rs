//! Document signing with hybrid signatures.
//!
//! DECISION 4: Hybrid signatures (Dilithium3 + Ed25519) are MANDATORY.
//! LAW 8: All signing operations are logged.

use crate::types::{
    SignatureMetadata, SignatureRequest, SignatureRequestId, SignedDocument, SignedDocumentId,
};
use chrono::Utc;
use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};
use teras_kunci::hash::blake3_hash;
use teras_kunci::sign::{HybridSignature, HybridSigner, HybridVerifyingKey};

/// Document signer with hybrid post-quantum signatures.
///
/// All operations are logged per LAW 8.
pub struct DocumentSigner {
    key_id: String,
    signer: HybridSigner,
    verifying_key: HybridVerifyingKey,
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
}

impl DocumentSigner {
    /// Create a new document signer with a new keypair.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Identifier for this signing key
    /// * `audit_log` - Audit log for LAW 8 compliance
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails.
    pub fn new(key_id: impl Into<String>, audit_log: Arc<std::sync::RwLock<AuditLog>>) -> TerasResult<Self> {
        let key_id = key_id.into();
        let (signer, verifying_key) = HybridSigner::generate()?;

        // Log key generation (LAW 8)
        Self::log_operation_static(
            &audit_log,
            "key_generate",
            &key_id,
            ActionResult::Success,
            Some(Context::new().with_extra("algorithm", "ML-DSA-65+Ed25519".to_string())),
        )?;

        Ok(Self {
            key_id,
            signer,
            verifying_key,
            audit_log,
        })
    }

    /// Create a document signer from an existing keypair.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Identifier for this signing key
    /// * `signer` - The hybrid signer (private key)
    /// * `verifying_key` - The hybrid verifying key (public key)
    /// * `audit_log` - Audit log for LAW 8 compliance
    pub fn from_keypair(
        key_id: impl Into<String>,
        signer: HybridSigner,
        verifying_key: HybridVerifyingKey,
        audit_log: Arc<std::sync::RwLock<AuditLog>>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            signer,
            verifying_key,
            audit_log,
        }
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the verifying key (public key).
    #[must_use]
    pub fn verifying_key(&self) -> &HybridVerifyingKey {
        &self.verifying_key
    }

    /// Sign a document from a signature request.
    ///
    /// # Arguments
    ///
    /// * `request` - The signature request containing the document
    ///
    /// # Returns
    ///
    /// Returns a signed document with hybrid signature.
    ///
    /// # Errors
    ///
    /// Returns error if signing fails or key ID mismatch.
    pub fn sign(&self, request: &SignatureRequest) -> TerasResult<SignedDocument> {
        // Verify key ID matches
        if request.key_id != self.key_id {
            self.log_operation(
                "sign",
                ActionResult::Failure {
                    reason: format!("Key ID mismatch: expected {}, got {}", self.key_id, request.key_id),
                    code: None,
                },
                Some(Context::new().with_extra("request_id", request.id.to_string())),
            )?;
            return Err(TerasError::KeyNotFound {
                key_id: request.key_id.clone(),
            });
        }

        // Hash the document (BLAKE3)
        let document_hash = blake3_hash(&request.document);

        // Sign the hash with hybrid signature
        let signature = self.signer.sign(&document_hash)?;

        // Extract signature components
        let dilithium_sig = signature.dilithium_sig().as_bytes().to_vec();
        let ed25519_sig = signature.ed25519_sig().as_bytes().to_vec();

        let signed_doc = SignedDocument {
            id: SignedDocumentId::new(),
            request_id: request.id.clone(),
            key_id: self.key_id.clone(),
            document_hash: document_hash.to_vec(),
            dilithium_signature: dilithium_sig,
            ed25519_signature: ed25519_sig,
            signed_at: Utc::now(),
            timestamp_token: None,
            document_name: request.document_name.clone(),
            content_type: request.content_type.clone(),
            metadata: request.metadata.clone(),
            algorithm: "ML-DSA-65+Ed25519".to_string(),
        };

        // Log successful signing (LAW 8)
        self.log_operation(
            "sign",
            ActionResult::Success,
            Some(
                Context::new()
                    .with_extra("request_id", request.id.to_string())
                    .with_extra("document_id", signed_doc.id.to_string())
                    .with_extra("document_size", request.document.len().to_string()),
            ),
        )?;

        Ok(signed_doc)
    }

    /// Sign raw bytes directly.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes to sign
    ///
    /// # Returns
    ///
    /// Returns the hybrid signature.
    ///
    /// # Errors
    ///
    /// Returns error if signing fails.
    pub fn sign_bytes(&self, data: &[u8]) -> TerasResult<HybridSignature> {
        let signature = self.signer.sign(data)?;

        // Log signing (LAW 8)
        self.log_operation(
            "sign_bytes",
            ActionResult::Success,
            Some(Context::new().with_extra("data_size", data.len().to_string())),
        )?;

        Ok(signature)
    }

    /// Sign a hash directly (pre-hashed data).
    ///
    /// # Arguments
    ///
    /// * `hash` - 32-byte hash to sign
    ///
    /// # Returns
    ///
    /// Returns the hybrid signature.
    ///
    /// # Errors
    ///
    /// Returns error if signing fails.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> TerasResult<HybridSignature> {
        let signature = self.signer.sign(hash)?;

        // Log signing (LAW 8)
        self.log_operation(
            "sign_hash",
            ActionResult::Success,
            Some(Context::new().with_extra("hash_algorithm", "pre-hashed".to_string())),
        )?;

        Ok(signature)
    }

    fn log_operation(
        &self,
        operation: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<u64> {
        Self::log_operation_static(&self.audit_log, operation, &self.key_id, result, context)
    }

    fn log_operation_static(
        audit_log: &Arc<std::sync::RwLock<AuditLog>>,
        operation: &str,
        key_id: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<u64> {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "teras-sandi".to_string(),
            },
            Action::KeyOperation {
                operation: format!("sign:{operation}"),
                key_id: key_id.to_string(),
            },
            format!("signer:{key_id}"),
            result,
        )
        .with_context(context.unwrap_or_default());

        let mut log = audit_log
            .write()
            .map_err(|_| TerasError::AuditLogFull)?;
        log.append(entry)
    }
}

/// Builder for creating signature requests.
pub struct SignatureRequestBuilder {
    key_id: String,
    document: Vec<u8>,
    document_name: Option<String>,
    content_type: Option<String>,
    metadata: Option<SignatureMetadata>,
}

impl SignatureRequestBuilder {
    /// Create a new signature request builder.
    #[must_use]
    pub fn new(key_id: impl Into<String>, document: Vec<u8>) -> Self {
        Self {
            key_id: key_id.into(),
            document,
            document_name: None,
            content_type: None,
            metadata: None,
        }
    }

    /// Set the document name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.document_name = Some(name.into());
        self
    }

    /// Set the content type.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set metadata.
    #[must_use]
    pub fn metadata(mut self, metadata: SignatureMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Build the signature request.
    #[must_use]
    pub fn build(self) -> SignatureRequest {
        SignatureRequest {
            id: SignatureRequestId::new(),
            key_id: self.key_id,
            document: self.document,
            document_name: self.document_name,
            content_type: self.content_type,
            created_at: Utc::now(),
            metadata: self.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use teras_jejak::storage::MemoryStorage;

    fn create_audit_log() -> Arc<std::sync::RwLock<AuditLog>> {
        let storage = MemoryStorage::new();
        Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))))
    }

    #[test]
    fn test_document_signer_creation() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("test-key", audit_log.clone()).unwrap();

        assert_eq!(signer.key_id(), "test-key");

        // Verify key generation was logged
        let log = audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 1);
    }

    #[test]
    fn test_sign_document() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("sign-key-1", audit_log.clone()).unwrap();

        let request = SignatureRequest::new("sign-key-1", b"test document content".to_vec())
            .with_name("test.txt");

        let signed = signer.sign(&request).unwrap();

        assert_eq!(signed.key_id, "sign-key-1");
        assert!(!signed.dilithium_signature.is_empty());
        assert!(!signed.ed25519_signature.is_empty());
        assert_eq!(signed.document_hash.len(), 32);
        assert_eq!(signed.algorithm, "ML-DSA-65+Ed25519");

        // Verify signing was logged (key gen + sign = 2 entries)
        let log = audit_log.read().unwrap();
        assert_eq!(log.count().unwrap(), 2);
    }

    #[test]
    fn test_sign_wrong_key_fails() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("key-a", audit_log).unwrap();

        let request = SignatureRequest::new("key-b", b"test".to_vec());

        let result = signer.sign(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_bytes() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("bytes-key", audit_log).unwrap();

        let data = b"raw bytes to sign";
        let signature = signer.sign_bytes(data).unwrap();

        // Signature should be verifiable
        assert!(signer.verifying_key().verify(data, &signature).is_ok());
    }

    #[test]
    fn test_sign_hash() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("hash-key", audit_log).unwrap();

        let hash = blake3_hash(b"document");
        let signature = signer.sign_hash(&hash).unwrap();

        // Signature should be verifiable
        assert!(signer.verifying_key().verify(&hash, &signature).is_ok());
    }

    #[test]
    fn test_signature_request_builder() {
        let metadata = SignatureMetadata::new().with_signer("Test User");

        let request = SignatureRequestBuilder::new("key-1", b"doc".to_vec())
            .name("document.pdf")
            .content_type("application/pdf")
            .metadata(metadata)
            .build();

        assert_eq!(request.key_id, "key-1");
        assert_eq!(request.document_name, Some("document.pdf".to_string()));
        assert_eq!(request.content_type, Some("application/pdf".to_string()));
        assert!(request.metadata.is_some());
    }
}
