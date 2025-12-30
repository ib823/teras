//! Chain verification for audit logs.
//!
//! Provides tamper detection per LAW 8.

use crate::storage::AuditStorage;

/// Result of chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerificationResult {
    /// Whether the chain is valid.
    pub valid: bool,
    /// Total entries verified.
    pub entries_verified: u64,
    /// First entry with an error (if any).
    pub first_error_at: Option<u64>,
    /// Description of the error (if any).
    pub error_description: Option<String>,
}

impl ChainVerificationResult {
    /// Create a successful verification result.
    #[must_use]
    pub fn success(entries_verified: u64) -> Self {
        Self {
            valid: true,
            entries_verified,
            first_error_at: None,
            error_description: None,
        }
    }

    /// Create a failed verification result.
    #[must_use]
    pub fn failure(entries_verified: u64, error_at: u64, description: impl Into<String>) -> Self {
        Self {
            valid: false,
            entries_verified,
            first_error_at: Some(error_at),
            error_description: Some(description.into()),
        }
    }
}

/// Verification errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Entry hash doesn't match computed hash.
    HashMismatch {
        /// Event ID of the entry with mismatched hash.
        event_id: u64,
    },
    /// Chain link is broken (`previous_hash` doesn't match).
    ChainBroken {
        /// Event ID where chain is broken.
        event_id: u64,
        /// Expected hash (from previous entry).
        expected: [u8; 32],
        /// Actual hash (in current entry's `previous_hash`).
        actual: [u8; 32],
    },
    /// Missing hash on entry.
    MissingHash {
        /// Event ID of the entry missing hash.
        event_id: u64,
    },
    /// Event IDs are not sequential.
    NonSequentialId {
        /// Expected event ID.
        expected: u64,
        /// Actual event ID.
        actual: u64,
    },
    /// Genesis entry has `previous_hash` set.
    InvalidGenesis,
    /// Storage error during verification.
    StorageError(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashMismatch { event_id } => {
                write!(f, "hash mismatch at event {event_id}")
            }
            Self::ChainBroken { event_id, .. } => {
                write!(f, "chain broken at event {event_id}")
            }
            Self::MissingHash { event_id } => {
                write!(f, "missing hash at event {event_id}")
            }
            Self::NonSequentialId { expected, actual } => {
                write!(f, "expected event ID {expected}, got {actual}")
            }
            Self::InvalidGenesis => {
                write!(f, "genesis entry has previous_hash set")
            }
            Self::StorageError(msg) => {
                write!(f, "storage error: {msg}")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

/// Verify the integrity of an audit log chain.
///
/// # Errors
///
/// Returns `VerificationError` if any integrity check fails.
pub fn verify_chain(
    storage: &dyn AuditStorage,
) -> Result<ChainVerificationResult, VerificationError> {
    let count = storage
        .count()
        .map_err(|e| VerificationError::StorageError(e.to_string()))?;

    if count == 0 {
        return Ok(ChainVerificationResult::success(0));
    }

    let mut previous_hash: Option<[u8; 32]> = None;
    let mut verified = 0u64;

    for entry in storage
        .all_entries()
        .map_err(|e| VerificationError::StorageError(e.to_string()))?
    {
        verified += 1;
        let event_id = entry.event_id;

        // Check sequential IDs
        if event_id != verified {
            return Err(VerificationError::NonSequentialId {
                expected: verified,
                actual: event_id,
            });
        }

        // Check genesis entry
        if event_id == 1 && entry.previous_hash.is_some() {
            return Err(VerificationError::InvalidGenesis);
        }

        // Check chain link
        if event_id > 1 {
            match (&previous_hash, &entry.previous_hash) {
                (Some(expected), Some(actual)) => {
                    if !teras_kunci::ct_eq(expected, actual) {
                        return Err(VerificationError::ChainBroken {
                            event_id,
                            expected: *expected,
                            actual: *actual,
                        });
                    }
                }
                (Some(_), None) => {
                    return Err(VerificationError::MissingHash { event_id });
                }
                (None, _) => {
                    // First entry after genesis, previous should have been set
                }
            }
        }

        // Verify entry hash
        if !entry.verify_hash() {
            return Err(VerificationError::HashMismatch { event_id });
        }

        previous_hash = entry.entry_hash;
    }

    Ok(ChainVerificationResult::success(verified))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_success() {
        let result = ChainVerificationResult::success(100);
        assert!(result.valid);
        assert_eq!(result.entries_verified, 100);
        assert!(result.first_error_at.is_none());
    }

    #[test]
    fn test_verification_result_failure() {
        let result = ChainVerificationResult::failure(50, 51, "hash mismatch");
        assert!(!result.valid);
        assert_eq!(result.entries_verified, 50);
        assert_eq!(result.first_error_at, Some(51));
        assert_eq!(result.error_description, Some("hash mismatch".into()));
    }

    #[test]
    fn test_verification_error_display() {
        let err = VerificationError::HashMismatch { event_id: 42 };
        assert_eq!(err.to_string(), "hash mismatch at event 42");

        let err = VerificationError::ChainBroken {
            event_id: 10,
            expected: [0u8; 32],
            actual: [1u8; 32],
        };
        assert_eq!(err.to_string(), "chain broken at event 10");
    }
}
