//! TERAS Digital Signatures Product
//!
//! Provides hybrid post-quantum digital signature capabilities.
//!
//! # DECISION 4: Hybrid Signatures MANDATORY
//!
//! All signatures use both Dilithium3 (ML-DSA-65) AND Ed25519.
//! BOTH signatures must verify for a signature to be valid.
//!
//! # LAW 8: Audit Logging
//!
//! All signature operations are logged to the audit chain.
//!
//! # Example
//!
//! ```no_run
//! use teras_sandi::SigningService;
//! use teras_jejak::{AuditLog, storage::MemoryStorage};
//! use std::sync::Arc;
//!
//! // Create audit log
//! let storage = MemoryStorage::new();
//! let audit_log = Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))));
//!
//! // Create signing service
//! let mut service = SigningService::new(audit_log);
//!
//! // Generate a signing key
//! let key_info = service.generate_key("my-signing-key").unwrap();
//!
//! // Sign a document
//! let document = b"Important document content".to_vec();
//! let signed = service.sign("my-signing-key", document.clone()).unwrap();
//!
//! // Verify the signature
//! let result = service.verify(&signed, &document).unwrap();
//! assert!(result.valid);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod format;
mod keystore;
mod service;
mod signer;
mod timestamp;
mod types;
mod verifier;

// Re-export main types
pub use format::{
    export_signature, import_signature, ExportFormat, PortableMetadata, PortableSignature,
    PortableTimestamp,
};
pub use keystore::{AuditedKeyStore, KeyStore, MemoryKeyStore};
pub use service::SigningService;
pub use signer::{DocumentSigner, SignatureRequestBuilder};
pub use timestamp::{TimestampAuthority, TimestampPolicy};
pub use types::{
    SignatureAlgorithm, SignatureMetadata, SignatureRequest, SignatureRequestId, SignedDocument,
    SignedDocumentId, SigningKeyInfo, TimestampToken, VerificationResult,
};
pub use verifier::SignatureVerifier;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use teras_jejak::{storage::MemoryStorage, AuditLog};

    fn create_audit_log() -> Arc<std::sync::RwLock<AuditLog>> {
        let storage = MemoryStorage::new();
        Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))))
    }

    #[test]
    fn test_integration_sign_and_verify() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        // Generate key
        service.generate_key("integration-key").unwrap();

        // Sign
        let document = b"Integration test document".to_vec();
        let signed = service.sign("integration-key", document.clone()).unwrap();

        // Verify
        let result = service.verify(&signed, &document).unwrap();

        // DECISION 4: Both signatures must verify
        assert!(result.valid);
        assert!(result.dilithium_valid);
        assert!(result.ed25519_valid);
        assert!(result.hash_valid);
    }

    #[test]
    fn test_integration_with_timestamp() {
        let audit_log = create_audit_log();
        let mut service = SigningService::with_timestamp_authority(audit_log, "integration-tsa");

        service.generate_key("ts-integration-key").unwrap();

        let signed = service
            .sign("ts-integration-key", b"timestamped doc".to_vec())
            .unwrap();

        assert!(signed.timestamp_token.is_some());
    }

    #[test]
    fn test_integration_export_import() {
        let audit_log = create_audit_log();
        let mut service = SigningService::new(audit_log);

        service.generate_key("export-key").unwrap();
        let signed = service.sign("export-key", b"export test".to_vec()).unwrap();

        // Export
        let json = export_signature(&signed, ExportFormat::JsonPretty).unwrap();

        // Import
        let imported = import_signature(&json).unwrap();

        assert_eq!(imported.key_id, signed.key_id);
        assert_eq!(imported.document_hash, signed.document_hash);
    }

    #[test]
    fn test_integration_document_signer_direct() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("direct-key", audit_log.clone()).unwrap();
        let verifier = SignatureVerifier::new(audit_log);

        let request =
            SignatureRequest::new("direct-key", b"direct signing".to_vec()).with_name("test.txt");

        let signed = signer.sign(&request).unwrap();

        let result = verifier
            .verify_document(&signed, b"direct signing", signer.verifying_key())
            .unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_integration_keystore_operations() {
        let audit_log = create_audit_log();
        let store = MemoryKeyStore::new();
        let mut keystore = AuditedKeyStore::new(store, audit_log);

        // Generate multiple keys
        keystore.generate("ks-key-1").unwrap();
        keystore.generate("ks-key-2").unwrap();

        assert!(keystore.contains("ks-key-1"));
        assert!(keystore.contains("ks-key-2"));

        let keys = keystore.list_keys().unwrap();
        assert_eq!(keys.len(), 2);

        // Remove one
        keystore.remove("ks-key-1").unwrap();
        assert!(!keystore.contains("ks-key-1"));
        assert!(keystore.contains("ks-key-2"));
    }
}
