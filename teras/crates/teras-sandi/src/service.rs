//! High-level signing service API.
//!
//! Provides a unified interface for document signing operations.
//! Implements DECISION 4 (hybrid signatures) and LAW 8 (audit logging).

use crate::format::{export_signature, import_signature, ExportFormat};
use crate::keystore::{AuditedKeyStore, MemoryKeyStore};
use crate::timestamp::TimestampAuthority;
use crate::types::{
    SignatureMetadata, SignatureRequest, SignedDocument, SigningKeyInfo, VerificationResult,
};
use crate::verifier::SignatureVerifier;
use std::collections::HashMap;
use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};
use teras_kunci::sign::HybridVerifyingKey;

/// High-level signing service.
///
/// Provides a unified API for:
/// - Key management
/// - Document signing
/// - Signature verification
/// - Timestamping
/// - Import/export of signatures
pub struct SigningService {
    keystore: AuditedKeyStore<MemoryKeyStore>,
    verifier: SignatureVerifier,
    tsa: Option<TimestampAuthority>,
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
    /// Signed documents storage.
    documents: HashMap<String, SignedDocument>,
}

impl SigningService {
    /// Create a new signing service.
    ///
    /// # Arguments
    ///
    /// * `audit_log` - Audit log for LAW 8 compliance
    #[must_use]
    pub fn new(audit_log: Arc<std::sync::RwLock<AuditLog>>) -> Self {
        let keystore = AuditedKeyStore::new(MemoryKeyStore::new(), audit_log.clone());
        let verifier = SignatureVerifier::new(audit_log.clone());

        Self {
            keystore,
            verifier,
            tsa: None,
            audit_log,
            documents: HashMap::new(),
        }
    }

    /// Create a signing service with a timestamp authority.
    ///
    /// # Arguments
    ///
    /// * `audit_log` - Audit log for LAW 8 compliance
    /// * `tsa_id` - Identifier for the timestamp authority
    #[must_use]
    pub fn with_timestamp_authority(
        audit_log: Arc<std::sync::RwLock<AuditLog>>,
        tsa_id: impl Into<String>,
    ) -> Self {
        let keystore = AuditedKeyStore::new(MemoryKeyStore::new(), audit_log.clone());
        let verifier = SignatureVerifier::new(audit_log.clone());
        let tsa = TimestampAuthority::new(tsa_id, audit_log.clone());

        Self {
            keystore,
            verifier,
            tsa: Some(tsa),
            audit_log,
            documents: HashMap::new(),
        }
    }

    // ==================== Key Management ====================

    /// Generate a new signing keypair.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Identifier for the new key
    ///
    /// # Errors
    ///
    /// Returns error if key generation fails.
    pub fn generate_key(&mut self, key_id: impl Into<String>) -> TerasResult<SigningKeyInfo> {
        let key_id = key_id.into();
        self.keystore.generate(&key_id)
    }

    /// List all key IDs.
    ///
    /// # Errors
    ///
    /// Returns error if listing fails.
    pub fn list_keys(&self) -> TerasResult<Vec<String>> {
        self.keystore.list_keys()
    }

    /// Check if a key exists.
    #[must_use]
    pub fn has_key(&self, key_id: &str) -> bool {
        self.keystore.contains(key_id)
    }

    /// Remove a key.
    ///
    /// # Errors
    ///
    /// Returns error if removal fails.
    pub fn remove_key(&mut self, key_id: &str) -> TerasResult<bool> {
        self.keystore.remove(key_id)
    }

    /// Get key info.
    #[must_use]
    pub fn get_key_info(&self, key_id: &str) -> Option<&SigningKeyInfo> {
        self.keystore.inner().get_info(key_id)
    }

    // ==================== Signing ====================

    /// Sign a document.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Key to use for signing
    /// * `document` - Document bytes to sign
    ///
    /// # Errors
    ///
    /// Returns error if signing fails.
    pub fn sign(&mut self, key_id: &str, document: Vec<u8>) -> TerasResult<SignedDocument> {
        self.sign_with_options(key_id, document, None, None, None)
    }

    /// Sign a document with options.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Key to use for signing
    /// * `document` - Document bytes to sign
    /// * `name` - Optional document name
    /// * `content_type` - Optional content type
    /// * `metadata` - Optional signature metadata
    ///
    /// # Errors
    ///
    /// Returns error if signing fails.
    pub fn sign_with_options(
        &mut self,
        key_id: &str,
        document: Vec<u8>,
        name: Option<String>,
        content_type: Option<String>,
        metadata: Option<SignatureMetadata>,
    ) -> TerasResult<SignedDocument> {
        // Get signer from keystore
        let signer_key = self.keystore.get_signer(key_id)?;
        let doc_size = document.len();

        // Build request
        let mut request = SignatureRequest::new(key_id, document);
        if let Some(n) = name {
            request = request.with_name(n);
        }
        if let Some(ct) = content_type {
            request = request.with_content_type(ct);
        }
        if let Some(meta) = metadata {
            request = request.with_metadata(meta);
        }

        // Hash the document
        let document_hash = teras_kunci::hash::blake3_hash(&request.document);

        // Sign the hash
        let signature = signer_key.sign(&document_hash)?;

        // Create signed document
        let mut signed = SignedDocument {
            id: crate::types::SignedDocumentId::new(),
            request_id: request.id.clone(),
            key_id: key_id.to_string(),
            document_hash: document_hash.to_vec(),
            dilithium_signature: signature.dilithium_sig().as_bytes().to_vec(),
            ed25519_signature: signature.ed25519_sig().as_bytes().to_vec(),
            signed_at: chrono::Utc::now(),
            timestamp_token: None,
            document_name: request.document_name,
            content_type: request.content_type,
            metadata: request.metadata,
            algorithm: "ML-DSA-65+Ed25519".to_string(),
        };

        // Add timestamp if TSA is configured
        if let Some(ref tsa) = self.tsa {
            tsa.add_timestamp(&mut signed)?;
        }

        // Store the signed document
        self.documents.insert(signed.id.to_string(), signed.clone());

        // Log operation
        self.log_operation(
            "sign",
            &signed.id.to_string(),
            ActionResult::Success,
            Some(
                Context::new()
                    .with_extra("key_id", key_id.to_string())
                    .with_extra("document_size", doc_size.to_string()),
            ),
        )?;

        Ok(signed)
    }

    // ==================== Verification ====================

    /// Verify a signed document.
    ///
    /// # Arguments
    ///
    /// * `signed_doc` - The signed document
    /// * `original_document` - The original document bytes
    ///
    /// # Errors
    ///
    /// Returns error if verification fails.
    pub fn verify(
        &self,
        signed_doc: &SignedDocument,
        original_document: &[u8],
    ) -> TerasResult<VerificationResult> {
        let vk = self.keystore.get_verifying_key(&signed_doc.key_id)?;
        self.verifier
            .verify_document(signed_doc, original_document, vk)
    }

    /// Verify a signed document with an external verifying key.
    ///
    /// # Arguments
    ///
    /// * `signed_doc` - The signed document
    /// * `original_document` - The original document bytes
    /// * `verifying_key` - The public key to verify against
    ///
    /// # Errors
    ///
    /// Returns error if verification fails.
    pub fn verify_with_key(
        &self,
        signed_doc: &SignedDocument,
        original_document: &[u8],
        verifying_key: &HybridVerifyingKey,
    ) -> TerasResult<VerificationResult> {
        self.verifier
            .verify_document(signed_doc, original_document, verifying_key)
    }

    // ==================== Document Management ====================

    /// Get a stored signed document by ID.
    #[must_use]
    pub fn get_document(&self, document_id: &str) -> Option<&SignedDocument> {
        self.documents.get(document_id)
    }

    /// List all signed document IDs.
    #[must_use]
    pub fn list_documents(&self) -> Vec<String> {
        self.documents.keys().cloned().collect()
    }

    /// Get document count.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }

    // ==================== Import/Export ====================

    /// Export a signed document to portable format.
    ///
    /// # Arguments
    ///
    /// * `document_id` - ID of the document to export
    /// * `format` - Export format
    ///
    /// # Errors
    ///
    /// Returns error if document not found or export fails.
    pub fn export(&self, document_id: &str, format: ExportFormat) -> TerasResult<String> {
        let doc = self
            .documents
            .get(document_id)
            .ok_or_else(|| TerasError::DocumentNotFound {
                document_id: document_id.to_string(),
            })?;

        export_signature(doc, format)
    }

    /// Import a signed document from portable format.
    ///
    /// # Arguments
    ///
    /// * `data` - Portable signature data
    ///
    /// # Errors
    ///
    /// Returns error if import fails.
    pub fn import(&mut self, data: &str) -> TerasResult<SignedDocument> {
        let doc = import_signature(data)?;
        self.documents.insert(doc.id.to_string(), doc.clone());

        self.log_operation("import", &doc.id.to_string(), ActionResult::Success, None)?;

        Ok(doc)
    }

    // ==================== Audit ====================

    /// Get the audit log.
    #[must_use]
    pub fn audit_log(&self) -> &Arc<std::sync::RwLock<AuditLog>> {
        &self.audit_log
    }

    fn log_operation(
        &self,
        operation: &str,
        resource: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<u64> {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "teras-sandi-service".to_string(),
            },
            Action::SecurityEvent {
                event_type: format!("signing_service:{operation}"),
                severity: "info".to_string(),
            },
            format!("service:{resource}"),
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
    use teras_jejak::storage::MemoryStorage;

    fn create_audit_log() -> Arc<std::sync::RwLock<AuditLog>> {
        let storage = MemoryStorage::new();
        Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))))
    }

    #[test]
    fn test_signing_service_basic() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        // Generate key
        let info = service.generate_key("service-key").unwrap();
        assert_eq!(info.key_id, "service-key");

        // Sign document
        let signed = service
            .sign("service-key", b"hello world".to_vec())
            .unwrap();
        assert_eq!(signed.key_id, "service-key");

        // Verify
        let result = service.verify(&signed, b"hello world").unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_signing_service_with_timestamp() {
        let audit_log = create_audit_log();
        let mut service = SigningService::with_timestamp_authority(audit_log, "test-tsa");

        service.generate_key("ts-key").unwrap();
        let signed = service.sign("ts-key", b"timestamped".to_vec()).unwrap();

        assert!(signed.timestamp_token.is_some());
        let ts = signed.timestamp_token.as_ref().unwrap();
        assert_eq!(ts.tsa_id, "test-tsa");
    }

    #[test]
    fn test_signing_service_key_management() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        // Generate multiple keys
        service.generate_key("key-1").unwrap();
        service.generate_key("key-2").unwrap();
        service.generate_key("key-3").unwrap();

        let keys = service.list_keys().unwrap();
        assert_eq!(keys.len(), 3);

        assert!(service.has_key("key-1"));
        assert!(!service.has_key("key-4"));

        // Remove key
        assert!(service.remove_key("key-2").unwrap());
        assert!(!service.has_key("key-2"));
    }

    #[test]
    fn test_signing_service_with_metadata() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        service.generate_key("meta-key").unwrap();

        let metadata = SignatureMetadata::new()
            .with_signer("Test Signer")
            .with_reason("Testing");

        let signed = service
            .sign_with_options(
                "meta-key",
                b"document with metadata".to_vec(),
                Some("test.pdf".to_string()),
                Some("application/pdf".to_string()),
                Some(metadata),
            )
            .unwrap();

        assert_eq!(signed.document_name, Some("test.pdf".to_string()));
        assert!(signed.metadata.is_some());
    }

    #[test]
    fn test_signing_service_export_import() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        service.generate_key("export-key").unwrap();
        let signed = service.sign("export-key", b"export test".to_vec()).unwrap();
        let doc_id = signed.id.to_string();

        // Export
        let exported = service.export(&doc_id, ExportFormat::JsonPretty).unwrap();

        // Create new service and import
        let audit_log2 = create_audit_log();
        let mut service2 = SigningService::new(audit_log2);

        let imported = service2.import(&exported).unwrap();
        assert_eq!(imported.id.to_string(), doc_id);
    }

    #[test]
    fn test_signing_service_document_storage() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        service.generate_key("store-key").unwrap();

        for i in 0..5 {
            service
                .sign("store-key", format!("document {i}").into_bytes())
                .unwrap();
        }

        assert_eq!(service.document_count(), 5);
        assert_eq!(service.list_documents().len(), 5);
    }

    #[test]
    fn test_signing_service_verify_tampered() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        service.generate_key("tamper-key").unwrap();
        let signed = service.sign("tamper-key", b"original".to_vec()).unwrap();

        let result = service.verify(&signed, b"tampered").unwrap();
        assert!(!result.valid);
        assert!(!result.hash_valid);
    }
}
