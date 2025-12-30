//! Timestamping for digital signatures.
//!
//! Provides trusted timestamp tokens for signature non-repudiation.
//! LAW 8: All timestamp operations are logged.

use crate::types::{SignedDocument, TimestampToken};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use teras_core::error::{TerasError, TerasResult};
use teras_jejak::{Action, ActionResult, Actor, AuditLog, AuditLogEntry, Context};
use teras_kunci::hash::blake3_hash;
use uuid::Uuid;

/// Timestamp authority for creating trusted timestamps.
///
/// In production, this would connect to an external TSA (RFC 3161).
/// This implementation provides a local timestamp service for testing/development.
pub struct TimestampAuthority {
    /// TSA identifier.
    tsa_id: String,
    /// Audit log for LAW 8 compliance.
    audit_log: Arc<std::sync::RwLock<AuditLog>>,
}

impl TimestampAuthority {
    /// Create a new local timestamp authority.
    ///
    /// # Arguments
    ///
    /// * `tsa_id` - Identifier for this TSA
    /// * `audit_log` - Audit log for LAW 8 compliance
    #[must_use]
    pub fn new(tsa_id: impl Into<String>, audit_log: Arc<std::sync::RwLock<AuditLog>>) -> Self {
        Self {
            tsa_id: tsa_id.into(),
            audit_log,
        }
    }

    /// Create a timestamp token for a signed document.
    ///
    /// # Arguments
    ///
    /// * `signed_doc` - The signed document to timestamp
    ///
    /// # Returns
    ///
    /// Returns a timestamp token with the current time.
    ///
    /// # Errors
    ///
    /// Returns error if audit logging fails.
    pub fn timestamp(&self, signed_doc: &SignedDocument) -> TerasResult<TimestampToken> {
        let now = Utc::now();
        let serial = Uuid::new_v4().to_string();

        // Create timestamp data to sign
        let timestamp_data = self.create_timestamp_data(signed_doc, now, &serial);

        // Hash the timestamp data
        let signature = blake3_hash(&timestamp_data).to_vec();

        let token = TimestampToken {
            timestamp: now,
            tsa_id: self.tsa_id.clone(),
            serial: serial.clone(),
            hash_algorithm: "BLAKE3".to_string(),
            signature,
        };

        // Log timestamp creation (LAW 8)
        self.log_operation(
            "create_timestamp",
            &signed_doc.id.to_string(),
            ActionResult::Success,
            Some(
                Context::new()
                    .with_extra("serial", serial)
                    .with_extra("timestamp", now.to_rfc3339()),
            ),
        )?;

        Ok(token)
    }

    /// Verify a timestamp token.
    ///
    /// # Arguments
    ///
    /// * `signed_doc` - The signed document
    /// * `token` - The timestamp token to verify
    ///
    /// # Returns
    ///
    /// Returns true if the timestamp is valid.
    ///
    /// # Errors
    ///
    /// Returns error if verification or audit logging fails.
    pub fn verify(&self, signed_doc: &SignedDocument, token: &TimestampToken) -> TerasResult<bool> {
        // Recreate timestamp data
        let timestamp_data =
            self.create_timestamp_data(signed_doc, token.timestamp, &token.serial);

        // Verify hash
        let expected_sig = blake3_hash(&timestamp_data).to_vec();
        let valid = expected_sig == token.signature;

        // Log verification (LAW 8)
        let action_result = if valid {
            ActionResult::Success
        } else {
            ActionResult::Failure {
                reason: "Timestamp signature mismatch".to_string(),
                code: None,
            }
        };

        self.log_operation(
            "verify_timestamp",
            &signed_doc.id.to_string(),
            action_result,
            Some(
                Context::new()
                    .with_extra("serial", token.serial.clone())
                    .with_extra("valid", valid.to_string()),
            ),
        )?;

        Ok(valid)
    }

    /// Add timestamp to a signed document.
    ///
    /// # Arguments
    ///
    /// * `signed_doc` - The signed document to timestamp (mutably)
    ///
    /// # Errors
    ///
    /// Returns error if timestamping fails.
    pub fn add_timestamp(&self, signed_doc: &mut SignedDocument) -> TerasResult<()> {
        let token = self.timestamp(signed_doc)?;
        signed_doc.timestamp_token = Some(token);
        Ok(())
    }

    fn create_timestamp_data(
        &self,
        signed_doc: &SignedDocument,
        timestamp: DateTime<Utc>,
        serial: &str,
    ) -> Vec<u8> {
        // Combine relevant data for timestamp binding
        let mut data = Vec::new();
        data.extend_from_slice(&signed_doc.document_hash);
        data.extend_from_slice(&signed_doc.dilithium_signature);
        data.extend_from_slice(&signed_doc.ed25519_signature);
        data.extend_from_slice(timestamp.to_rfc3339().as_bytes());
        data.extend_from_slice(serial.as_bytes());
        data.extend_from_slice(self.tsa_id.as_bytes());
        data
    }

    fn log_operation(
        &self,
        operation: &str,
        document_id: &str,
        result: ActionResult,
        context: Option<Context>,
    ) -> TerasResult<u64> {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "teras-sandi-tsa".to_string(),
            },
            Action::SecurityEvent {
                event_type: format!("timestamp:{operation}"),
                severity: "info".to_string(),
            },
            format!("tsa:{document_id}"),
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

/// Timestamp policy configuration.
#[derive(Debug, Clone)]
pub struct TimestampPolicy {
    /// Maximum age of timestamp for validity (in seconds).
    pub max_age_seconds: u64,
    /// Required hash algorithm.
    pub required_hash_algorithm: String,
    /// Allowed TSA identifiers (empty = allow all).
    pub allowed_tsas: Vec<String>,
}

impl Default for TimestampPolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: 365 * 24 * 60 * 60, // 1 year
            required_hash_algorithm: "BLAKE3".to_string(),
            allowed_tsas: Vec::new(),
        }
    }
}

impl TimestampPolicy {
    /// Create a new timestamp policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum age in seconds.
    #[must_use]
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = seconds;
        self
    }

    /// Add an allowed TSA.
    #[must_use]
    pub fn with_allowed_tsa(mut self, tsa_id: impl Into<String>) -> Self {
        self.allowed_tsas.push(tsa_id.into());
        self
    }

    /// Check if a timestamp token satisfies this policy.
    #[must_use]
    pub fn check(&self, token: &TimestampToken) -> bool {
        // Check hash algorithm
        if token.hash_algorithm != self.required_hash_algorithm {
            return false;
        }

        // Check TSA if restricted
        if !self.allowed_tsas.is_empty() && !self.allowed_tsas.contains(&token.tsa_id) {
            return false;
        }

        // Check age
        let age = Utc::now().signed_duration_since(token.timestamp);
        if age.num_seconds() < 0 {
            // Timestamp in the future
            return false;
        }

        #[allow(clippy::cast_sign_loss)]
        let age_seconds = age.num_seconds() as u64;
        age_seconds <= self.max_age_seconds
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
    fn test_timestamp_creation() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("ts-key", audit_log.clone()).unwrap();
        let tsa = TimestampAuthority::new("test-tsa", audit_log);

        let request = SignatureRequest::new("ts-key", b"document".to_vec());
        let signed = signer.sign(&request).unwrap();

        let token = tsa.timestamp(&signed).unwrap();

        assert_eq!(token.tsa_id, "test-tsa");
        assert_eq!(token.hash_algorithm, "BLAKE3");
        assert!(!token.serial.is_empty());
        assert!(!token.signature.is_empty());
    }

    #[test]
    fn test_timestamp_verification() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("verify-ts-key", audit_log.clone()).unwrap();
        let tsa = TimestampAuthority::new("verify-tsa", audit_log);

        let request = SignatureRequest::new("verify-ts-key", b"doc".to_vec());
        let signed = signer.sign(&request).unwrap();
        let token = tsa.timestamp(&signed).unwrap();

        let valid = tsa.verify(&signed, &token).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_add_timestamp() {
        let audit_log = create_audit_log();
        let signer = DocumentSigner::new("add-ts-key", audit_log.clone()).unwrap();
        let tsa = TimestampAuthority::new("add-tsa", audit_log);

        let request = SignatureRequest::new("add-ts-key", b"content".to_vec());
        let mut signed = signer.sign(&request).unwrap();

        assert!(signed.timestamp_token.is_none());

        tsa.add_timestamp(&mut signed).unwrap();

        assert!(signed.timestamp_token.is_some());
        let token = signed.timestamp_token.as_ref().unwrap();
        assert_eq!(token.tsa_id, "add-tsa");
    }

    #[test]
    fn test_timestamp_policy_default() {
        let policy = TimestampPolicy::default();
        assert_eq!(policy.max_age_seconds, 365 * 24 * 60 * 60);
        assert_eq!(policy.required_hash_algorithm, "BLAKE3");
        assert!(policy.allowed_tsas.is_empty());
    }

    #[test]
    fn test_timestamp_policy_check() {
        let policy = TimestampPolicy::new()
            .with_max_age(3600)
            .with_allowed_tsa("trusted-tsa");

        let valid_token = TimestampToken {
            timestamp: Utc::now(),
            tsa_id: "trusted-tsa".to_string(),
            serial: "123".to_string(),
            hash_algorithm: "BLAKE3".to_string(),
            signature: vec![],
        };

        assert!(policy.check(&valid_token));

        let wrong_tsa_token = TimestampToken {
            timestamp: Utc::now(),
            tsa_id: "untrusted-tsa".to_string(),
            serial: "456".to_string(),
            hash_algorithm: "BLAKE3".to_string(),
            signature: vec![],
        };

        assert!(!policy.check(&wrong_tsa_token));

        let wrong_algo_token = TimestampToken {
            timestamp: Utc::now(),
            tsa_id: "trusted-tsa".to_string(),
            serial: "789".to_string(),
            hash_algorithm: "SHA256".to_string(),
            signature: vec![],
        };

        assert!(!policy.check(&wrong_algo_token));
    }
}
