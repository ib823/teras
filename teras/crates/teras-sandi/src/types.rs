//! Core types for digital signature operations.
//!
//! All types implement DECISION 4 (hybrid signatures mandatory).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a signature request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignatureRequestId(pub Uuid);

impl SignatureRequestId {
    /// Create a new random signature request ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for SignatureRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SignatureRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a signed document.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedDocumentId(pub Uuid);

impl SignedDocumentId {
    /// Create a new random signed document ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for SignedDocumentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SignedDocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A request to sign a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRequest {
    /// Unique request identifier.
    pub id: SignatureRequestId,
    /// Key ID to use for signing.
    pub key_id: String,
    /// Document content to sign (raw bytes).
    #[serde(with = "base64_serde")]
    pub document: Vec<u8>,
    /// Optional document name/filename.
    pub document_name: Option<String>,
    /// Optional document MIME type.
    pub content_type: Option<String>,
    /// Timestamp of request creation.
    pub created_at: DateTime<Utc>,
    /// Optional metadata.
    pub metadata: Option<SignatureMetadata>,
}

impl SignatureRequest {
    /// Create a new signature request.
    #[must_use]
    pub fn new(key_id: impl Into<String>, document: Vec<u8>) -> Self {
        Self {
            id: SignatureRequestId::new(),
            key_id: key_id.into(),
            document,
            document_name: None,
            content_type: None,
            created_at: Utc::now(),
            metadata: None,
        }
    }

    /// Set the document name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.document_name = Some(name.into());
        self
    }

    /// Set the content type.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Set metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: SignatureMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Optional metadata for a signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureMetadata {
    /// Signer name or identifier.
    pub signer_name: Option<String>,
    /// Signer organization.
    pub organization: Option<String>,
    /// Reason for signing.
    pub reason: Option<String>,
    /// Location where signing occurred.
    pub location: Option<String>,
    /// Additional custom fields.
    #[serde(default)]
    pub custom: std::collections::HashMap<String, String>,
}

impl SignatureMetadata {
    /// Create new empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set signer name.
    #[must_use]
    pub fn with_signer(mut self, name: impl Into<String>) -> Self {
        self.signer_name = Some(name.into());
        self
    }

    /// Set organization.
    #[must_use]
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    /// Set reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Set location.
    #[must_use]
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// Add custom field.
    #[must_use]
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

/// A signed document with hybrid signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDocument {
    /// Unique document identifier.
    pub id: SignedDocumentId,
    /// Original signature request ID.
    pub request_id: SignatureRequestId,
    /// Key ID used for signing.
    pub key_id: String,
    /// Original document hash (BLAKE3).
    #[serde(with = "base64_serde")]
    pub document_hash: Vec<u8>,
    /// Dilithium3 signature component.
    #[serde(with = "base64_serde")]
    pub dilithium_signature: Vec<u8>,
    /// Ed25519 signature component.
    #[serde(with = "base64_serde")]
    pub ed25519_signature: Vec<u8>,
    /// Timestamp when document was signed.
    pub signed_at: DateTime<Utc>,
    /// Optional timestamp token from TSA.
    pub timestamp_token: Option<TimestampToken>,
    /// Document name if provided.
    pub document_name: Option<String>,
    /// Content type if provided.
    pub content_type: Option<String>,
    /// Metadata if provided.
    pub metadata: Option<SignatureMetadata>,
    /// Signature algorithm identifier.
    pub algorithm: String,
}

impl SignedDocument {
    /// Get the document ID as a string.
    #[must_use]
    pub fn id_string(&self) -> String {
        self.id.to_string()
    }
}

/// Timestamp token from a trusted timestamp authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampToken {
    /// Timestamp from the TSA.
    pub timestamp: DateTime<Utc>,
    /// TSA identifier.
    pub tsa_id: String,
    /// Token serial number.
    pub serial: String,
    /// Hash algorithm used.
    pub hash_algorithm: String,
    /// Signature over timestamp data.
    #[serde(with = "base64_serde")]
    pub signature: Vec<u8>,
}

/// Result of signature verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the signature is valid.
    pub valid: bool,
    /// Whether Dilithium3 signature verified.
    pub dilithium_valid: bool,
    /// Whether Ed25519 signature verified.
    pub ed25519_valid: bool,
    /// Document hash matches.
    pub hash_valid: bool,
    /// Timestamp is valid (if present).
    pub timestamp_valid: Option<bool>,
    /// Time of verification.
    pub verified_at: DateTime<Utc>,
    /// Error description if invalid.
    pub error: Option<String>,
}

impl VerificationResult {
    /// Create a successful verification result.
    #[must_use]
    pub fn success() -> Self {
        Self {
            valid: true,
            dilithium_valid: true,
            ed25519_valid: true,
            hash_valid: true,
            timestamp_valid: None,
            verified_at: Utc::now(),
            error: None,
        }
    }

    /// Create a failed verification result.
    #[must_use]
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            dilithium_valid: false,
            ed25519_valid: false,
            hash_valid: false,
            timestamp_valid: None,
            verified_at: Utc::now(),
            error: Some(error.into()),
        }
    }

    /// Set Dilithium verification status.
    #[must_use]
    pub fn with_dilithium(mut self, valid: bool) -> Self {
        self.dilithium_valid = valid;
        self.update_valid();
        self
    }

    /// Set Ed25519 verification status.
    #[must_use]
    pub fn with_ed25519(mut self, valid: bool) -> Self {
        self.ed25519_valid = valid;
        self.update_valid();
        self
    }

    /// Set hash verification status.
    #[must_use]
    pub fn with_hash(mut self, valid: bool) -> Self {
        self.hash_valid = valid;
        self.update_valid();
        self
    }

    /// Set timestamp verification status.
    #[must_use]
    pub fn with_timestamp(mut self, valid: bool) -> Self {
        self.timestamp_valid = Some(valid);
        self.update_valid();
        self
    }

    fn update_valid(&mut self) {
        // All components must be valid for overall validity
        // DECISION 4: BOTH signatures must verify
        self.valid = self.dilithium_valid
            && self.ed25519_valid
            && self.hash_valid
            && self.timestamp_valid.unwrap_or(true);

        if !self.valid && self.error.is_none() {
            let mut errors = Vec::new();
            if !self.dilithium_valid {
                errors.push("Dilithium signature invalid");
            }
            if !self.ed25519_valid {
                errors.push("Ed25519 signature invalid");
            }
            if !self.hash_valid {
                errors.push("Document hash mismatch");
            }
            if self.timestamp_valid == Some(false) {
                errors.push("Timestamp invalid");
            }
            self.error = Some(errors.join(", "));
        }
    }
}

/// Key algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Hybrid: ML-DSA-65 (Dilithium3) + Ed25519.
    /// DECISION 4: This is the ONLY allowed algorithm.
    #[serde(rename = "ML-DSA-65+Ed25519")]
    HybridDilithiumEd25519,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::HybridDilithiumEd25519
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HybridDilithiumEd25519 => write!(f, "ML-DSA-65+Ed25519"),
        }
    }
}

/// Signing key metadata (public information).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyInfo {
    /// Key identifier.
    pub key_id: String,
    /// Algorithm.
    pub algorithm: SignatureAlgorithm,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (if set).
    pub expires_at: Option<DateTime<Utc>>,
    /// Key owner/subject.
    pub subject: Option<String>,
    /// Dilithium public key size in bytes.
    pub dilithium_pk_size: usize,
    /// Ed25519 public key size in bytes.
    pub ed25519_pk_size: usize,
}

/// Base64 serialization helper module.
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_request_creation() {
        let req = SignatureRequest::new("key-1", b"test document".to_vec())
            .with_name("test.txt")
            .with_content_type("text/plain");

        assert_eq!(req.key_id, "key-1");
        assert_eq!(req.document, b"test document");
        assert_eq!(req.document_name, Some("test.txt".to_string()));
        assert_eq!(req.content_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_signature_metadata() {
        let meta = SignatureMetadata::new()
            .with_signer("John Doe")
            .with_organization("TERAS")
            .with_reason("Approval")
            .with_custom("dept", "Engineering");

        assert_eq!(meta.signer_name, Some("John Doe".to_string()));
        assert_eq!(meta.organization, Some("TERAS".to_string()));
        assert_eq!(meta.reason, Some("Approval".to_string()));
        assert_eq!(meta.custom.get("dept"), Some(&"Engineering".to_string()));
    }

    #[test]
    fn test_verification_result_success() {
        let result = VerificationResult::success();
        assert!(result.valid);
        assert!(result.dilithium_valid);
        assert!(result.ed25519_valid);
        assert!(result.hash_valid);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_verification_result_failure() {
        let result = VerificationResult::failure("Test error");
        assert!(!result.valid);
        assert_eq!(result.error, Some("Test error".to_string()));
    }

    #[test]
    fn test_verification_result_partial_failure() {
        let result = VerificationResult::success()
            .with_dilithium(true)
            .with_ed25519(false)
            .with_hash(true);

        // DECISION 4: BOTH must verify
        assert!(!result.valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_signature_algorithm_default() {
        let algo = SignatureAlgorithm::default();
        assert_eq!(algo, SignatureAlgorithm::HybridDilithiumEd25519);
        assert_eq!(algo.to_string(), "ML-DSA-65+Ed25519");
    }

    #[test]
    fn test_signature_request_serialization() {
        let req = SignatureRequest::new("key-1", b"test".to_vec());
        let json = serde_json::to_string(&req).unwrap();
        let parsed: SignatureRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.key_id, req.key_id);
        assert_eq!(parsed.document, req.document);
    }

    #[test]
    fn test_request_id_display() {
        let id = SignatureRequestId::new();
        let display = format!("{id}");
        assert!(!display.is_empty());
        // Should be a valid UUID format
        assert!(uuid::Uuid::parse_str(&display).is_ok());
    }
}
