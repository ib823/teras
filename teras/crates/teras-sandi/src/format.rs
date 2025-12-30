//! Portable signature format for document exchange.
//!
//! Provides serialization/deserialization for signed documents.

use crate::types::{
    SignatureMetadata, SignatureRequestId, SignedDocument, SignedDocumentId, TimestampToken,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use teras_core::error::{TerasError, TerasResult};

/// Magic bytes for TERAS signature format.
const TERAS_SIG_MAGIC: &[u8] = b"TERASSIG";

/// Current format version.
const FORMAT_VERSION: u16 = 1;

/// Portable signature format for exchange.
///
/// This format is designed to be:
/// - Self-contained (includes all verification data)
/// - Portable (JSON-based, base64 encoded binaries)
/// - Versioned (for future compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSignature {
    /// Format magic identifier.
    pub magic: String,
    /// Format version.
    pub version: u16,
    /// Document ID.
    pub document_id: String,
    /// Request ID.
    pub request_id: String,
    /// Key ID used for signing.
    pub key_id: String,
    /// Signature algorithm identifier.
    pub algorithm: String,
    /// Document hash (base64).
    pub document_hash: String,
    /// Dilithium signature (base64).
    pub dilithium_signature: String,
    /// Ed25519 signature (base64).
    pub ed25519_signature: String,
    /// Signing timestamp (RFC 3339).
    pub signed_at: String,
    /// Optional document name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_name: Option<String>,
    /// Optional content type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Optional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PortableMetadata>,
    /// Optional timestamp token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<PortableTimestamp>,
}

/// Portable metadata format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableMetadata {
    /// Signer name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
    /// Organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Reason for signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Signing location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Custom fields.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub custom: std::collections::HashMap<String, String>,
}

/// Portable timestamp format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableTimestamp {
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// TSA identifier.
    pub tsa_id: String,
    /// Serial number.
    pub serial: String,
    /// Hash algorithm.
    pub hash_algorithm: String,
    /// Timestamp signature (base64).
    pub signature: String,
}

impl PortableSignature {
    /// Create a portable signature from a signed document.
    #[must_use]
    pub fn from_signed_document(doc: &SignedDocument) -> Self {
        Self {
            magic: String::from_utf8_lossy(TERAS_SIG_MAGIC).to_string(),
            version: FORMAT_VERSION,
            document_id: doc.id.to_string(),
            request_id: doc.request_id.to_string(),
            key_id: doc.key_id.clone(),
            algorithm: doc.algorithm.clone(),
            document_hash: STANDARD.encode(&doc.document_hash),
            dilithium_signature: STANDARD.encode(&doc.dilithium_signature),
            ed25519_signature: STANDARD.encode(&doc.ed25519_signature),
            signed_at: doc.signed_at.to_rfc3339(),
            document_name: doc.document_name.clone(),
            content_type: doc.content_type.clone(),
            metadata: doc.metadata.as_ref().map(PortableMetadata::from),
            timestamp: doc.timestamp_token.as_ref().map(PortableTimestamp::from),
        }
    }

    /// Convert to a signed document.
    ///
    /// # Errors
    ///
    /// Returns error if deserialization fails.
    pub fn to_signed_document(&self) -> TerasResult<SignedDocument> {
        // Validate magic
        if self.magic != String::from_utf8_lossy(TERAS_SIG_MAGIC) {
            return Err(TerasError::InvalidFormat(format!(
                "Invalid magic: expected {}, got {}",
                String::from_utf8_lossy(TERAS_SIG_MAGIC),
                self.magic
            )));
        }

        // Validate version
        if self.version != FORMAT_VERSION {
            return Err(TerasError::InvalidVersion {
                expected: FORMAT_VERSION,
                actual: self.version,
            });
        }

        // Decode base64 fields
        let document_hash = STANDARD.decode(&self.document_hash).map_err(|e| {
            TerasError::DeserializationFailed {
                type_name: "document_hash".to_string(),
                reason: e.to_string(),
            }
        })?;

        let dilithium_signature = STANDARD.decode(&self.dilithium_signature).map_err(|e| {
            TerasError::DeserializationFailed {
                type_name: "dilithium_signature".to_string(),
                reason: e.to_string(),
            }
        })?;

        let ed25519_signature = STANDARD.decode(&self.ed25519_signature).map_err(|e| {
            TerasError::DeserializationFailed {
                type_name: "ed25519_signature".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Parse timestamp
        let signed_at: DateTime<Utc> = DateTime::parse_from_rfc3339(&self.signed_at)
            .map_err(|e| TerasError::DeserializationFailed {
                type_name: "signed_at".to_string(),
                reason: e.to_string(),
            })?
            .with_timezone(&Utc);

        // Parse document ID
        let document_id = uuid::Uuid::parse_str(&self.document_id).map_err(|e| {
            TerasError::DeserializationFailed {
                type_name: "document_id".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Parse request ID
        let request_id = uuid::Uuid::parse_str(&self.request_id).map_err(|e| {
            TerasError::DeserializationFailed {
                type_name: "request_id".to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(SignedDocument {
            id: SignedDocumentId::from_uuid(document_id),
            request_id: SignatureRequestId::from_uuid(request_id),
            key_id: self.key_id.clone(),
            document_hash,
            dilithium_signature,
            ed25519_signature,
            signed_at,
            timestamp_token: self
                .timestamp
                .as_ref()
                .map(PortableTimestamp::to_timestamp_token)
                .transpose()?,
            document_name: self.document_name.clone(),
            content_type: self.content_type.clone(),
            metadata: self.metadata.as_ref().map(SignatureMetadata::from),
            algorithm: self.algorithm.clone(),
        })
    }

    /// Serialize to JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if serialization fails.
    pub fn to_json(&self) -> TerasResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| TerasError::SerializationFailed {
            type_name: "PortableSignature".to_string(),
            reason: e.to_string(),
        })
    }

    /// Deserialize from JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if deserialization fails.
    pub fn from_json(json: &str) -> TerasResult<Self> {
        serde_json::from_str(json).map_err(|e| TerasError::DeserializationFailed {
            type_name: "PortableSignature".to_string(),
            reason: e.to_string(),
        })
    }

    /// Serialize to compact JSON (no pretty print).
    ///
    /// # Errors
    ///
    /// Returns error if serialization fails.
    pub fn to_json_compact(&self) -> TerasResult<String> {
        serde_json::to_string(self).map_err(|e| TerasError::SerializationFailed {
            type_name: "PortableSignature".to_string(),
            reason: e.to_string(),
        })
    }
}

impl From<&SignatureMetadata> for PortableMetadata {
    fn from(meta: &SignatureMetadata) -> Self {
        Self {
            signer_name: meta.signer_name.clone(),
            organization: meta.organization.clone(),
            reason: meta.reason.clone(),
            location: meta.location.clone(),
            custom: meta.custom.clone(),
        }
    }
}

impl From<&PortableMetadata> for SignatureMetadata {
    fn from(meta: &PortableMetadata) -> Self {
        Self {
            signer_name: meta.signer_name.clone(),
            organization: meta.organization.clone(),
            reason: meta.reason.clone(),
            location: meta.location.clone(),
            custom: meta.custom.clone(),
        }
    }
}

impl From<&TimestampToken> for PortableTimestamp {
    fn from(token: &TimestampToken) -> Self {
        Self {
            timestamp: token.timestamp.to_rfc3339(),
            tsa_id: token.tsa_id.clone(),
            serial: token.serial.clone(),
            hash_algorithm: token.hash_algorithm.clone(),
            signature: STANDARD.encode(&token.signature),
        }
    }
}

impl PortableTimestamp {
    /// Convert to timestamp token.
    ///
    /// # Errors
    ///
    /// Returns error if conversion fails.
    pub fn to_timestamp_token(&self) -> TerasResult<TimestampToken> {
        let timestamp: DateTime<Utc> = DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|e| TerasError::DeserializationFailed {
                type_name: "timestamp".to_string(),
                reason: e.to_string(),
            })?
            .with_timezone(&Utc);

        let signature =
            STANDARD
                .decode(&self.signature)
                .map_err(|e| TerasError::DeserializationFailed {
                    type_name: "timestamp_signature".to_string(),
                    reason: e.to_string(),
                })?;

        Ok(TimestampToken {
            timestamp,
            tsa_id: self.tsa_id.clone(),
            serial: self.serial.clone(),
            hash_algorithm: self.hash_algorithm.clone(),
            signature,
        })
    }
}

/// Export format options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExportFormat {
    /// Pretty-printed JSON.
    #[default]
    JsonPretty,
    /// Compact JSON.
    JsonCompact,
}

/// Export a signed document to the specified format.
///
/// # Errors
///
/// Returns error if serialization fails.
pub fn export_signature(doc: &SignedDocument, format: ExportFormat) -> TerasResult<String> {
    let portable = PortableSignature::from_signed_document(doc);
    match format {
        ExportFormat::JsonPretty => portable.to_json(),
        ExportFormat::JsonCompact => portable.to_json_compact(),
    }
}

/// Import a signed document from a portable format string.
///
/// # Errors
///
/// Returns error if deserialization fails.
pub fn import_signature(data: &str) -> TerasResult<SignedDocument> {
    let portable = PortableSignature::from_json(data)?;
    portable.to_signed_document()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::DocumentSigner;
    use crate::timestamp::TimestampAuthority;
    use crate::types::SignatureRequest;
    use std::sync::Arc;
    use teras_jejak::{storage::MemoryStorage, AuditLog};

    fn create_audit_log() -> Arc<std::sync::RwLock<AuditLog>> {
        let storage = MemoryStorage::new();
        Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))))
    }

    #[test]
    fn test_portable_signature_roundtrip() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("format-key", audit_log).unwrap();

        let request = SignatureRequest::new("format-key", b"test document".to_vec())
            .with_name("test.txt")
            .with_content_type("text/plain");

        let signed = signer.sign(&request).unwrap();

        // Convert to portable format
        let portable = PortableSignature::from_signed_document(&signed);

        // Serialize to JSON
        let json = portable.to_json().unwrap();
        assert!(json.contains("TERASSIG"));

        // Parse back
        let parsed = PortableSignature::from_json(&json).unwrap();
        assert_eq!(parsed.document_id, signed.id.to_string());
        assert_eq!(parsed.key_id, "format-key");

        // Convert back to signed document
        let restored = parsed.to_signed_document().unwrap();
        assert_eq!(restored.key_id, signed.key_id);
        assert_eq!(restored.document_hash, signed.document_hash);
        assert_eq!(restored.dilithium_signature, signed.dilithium_signature);
        assert_eq!(restored.ed25519_signature, signed.ed25519_signature);
    }

    #[test]
    fn test_portable_signature_with_metadata() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("meta-key", audit_log).unwrap();

        let metadata = SignatureMetadata::new()
            .with_signer("John Doe")
            .with_organization("TERAS")
            .with_reason("Approval");

        let request =
            SignatureRequest::new("meta-key", b"doc with meta".to_vec()).with_metadata(metadata);

        let signed = signer.sign(&request).unwrap();
        let portable = PortableSignature::from_signed_document(&signed);

        assert!(portable.metadata.is_some());
        let meta = portable.metadata.as_ref().unwrap();
        assert_eq!(meta.signer_name, Some("John Doe".to_string()));
        assert_eq!(meta.organization, Some("TERAS".to_string()));
    }

    #[test]
    fn test_portable_signature_with_timestamp() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("ts-format-key", audit_log.clone()).unwrap();
        let tsa = TimestampAuthority::new("test-tsa", audit_log);

        let request = SignatureRequest::new("ts-format-key", b"timestamped doc".to_vec());
        let mut signed = signer.sign(&request).unwrap();
        tsa.add_timestamp(&mut signed).unwrap();

        let portable = PortableSignature::from_signed_document(&signed);
        assert!(portable.timestamp.is_some());

        let ts = portable.timestamp.as_ref().unwrap();
        assert_eq!(ts.tsa_id, "test-tsa");

        // Roundtrip
        let json = portable.to_json().unwrap();
        let restored = import_signature(&json).unwrap();
        assert!(restored.timestamp_token.is_some());
    }

    #[test]
    fn test_export_import_functions() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("export-key", audit_log).unwrap();

        let request = SignatureRequest::new("export-key", b"export test".to_vec());
        let signed = signer.sign(&request).unwrap();

        // Export
        let json = export_signature(&signed, ExportFormat::JsonPretty).unwrap();

        // Import
        let imported = import_signature(&json).unwrap();
        assert_eq!(imported.key_id, signed.key_id);
    }

    #[test]
    fn test_compact_format() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("compact-key", audit_log).unwrap();

        let request = SignatureRequest::new("compact-key", b"compact test".to_vec());
        let signed = signer.sign(&request).unwrap();

        let pretty = export_signature(&signed, ExportFormat::JsonPretty).unwrap();
        let compact = export_signature(&signed, ExportFormat::JsonCompact).unwrap();

        // Compact should be shorter
        assert!(compact.len() < pretty.len());

        // Both should be valid
        let from_pretty = import_signature(&pretty).unwrap();
        let from_compact = import_signature(&compact).unwrap();
        assert_eq!(from_pretty.key_id, from_compact.key_id);
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let json = r#"{
            "magic": "INVALID",
            "version": 1,
            "document_id": "test",
            "request_id": "test",
            "key_id": "test",
            "algorithm": "test",
            "document_hash": "dGVzdA==",
            "dilithium_signature": "dGVzdA==",
            "ed25519_signature": "dGVzdA==",
            "signed_at": "2025-01-01T00:00:00Z"
        }"#;

        let portable = PortableSignature::from_json(json).unwrap();
        let result = portable.to_signed_document();
        assert!(result.is_err());
    }
}
