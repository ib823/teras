//! Audit log entry structure.
//!
//! Implements the mandatory fields from LAW 8.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Actor who performed the action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Actor {
    /// A human user.
    User {
        /// User identifier.
        id: String,
        /// Device identifier (if known).
        device_id: Option<String>,
    },
    /// A device acting autonomously.
    Device {
        /// Device identifier.
        id: String,
        /// Device type.
        device_type: String,
    },
    /// The system itself.
    System {
        /// Component name.
        component: String,
    },
    /// Unknown actor (should be rare).
    Unknown,
}

/// Action that was attempted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Action {
    /// Authentication attempt.
    Authentication {
        /// Method used (e.g., "hybrid-kem", "biometric").
        method: String,
    },
    /// Authorization check.
    Authorization {
        /// Permission being checked.
        permission: String,
        /// Resource being accessed.
        resource: String,
    },
    /// Key operation.
    KeyOperation {
        /// Operation type (generate, derive, encrypt, decrypt, sign, verify).
        operation: String,
        /// Key identifier (NOT the key itself).
        key_id: String,
    },
    /// Configuration change.
    ConfigChange {
        /// What was changed.
        setting: String,
        /// Old value (redacted if sensitive).
        old_value: Option<String>,
        /// New value (redacted if sensitive).
        new_value: Option<String>,
    },
    /// Data access.
    DataAccess {
        /// Type of data accessed.
        data_type: String,
        /// Access mode (read, write, delete).
        mode: String,
    },
    /// Security event.
    SecurityEvent {
        /// Event type (`intrusion_attempt`, `policy_violation`, etc.).
        event_type: String,
        /// Severity (low, medium, high, critical).
        severity: String,
    },
    /// Audit log operation.
    AuditOperation {
        /// Operation type (`chain_verify`, `export`, `retention_check`).
        operation: String,
    },
    /// Custom action.
    Custom {
        /// Action name.
        name: String,
        /// Additional details.
        details: Option<String>,
    },
}

/// Result of the action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status")]
pub enum ActionResult {
    /// Action succeeded.
    Success,
    /// Action failed.
    Failure {
        /// Reason for failure.
        reason: String,
        /// Error code (if applicable).
        code: Option<String>,
    },
    /// Action was denied.
    Denied {
        /// Reason for denial.
        reason: String,
    },
    /// Action is pending.
    Pending {
        /// Additional info.
        info: Option<String>,
    },
}

/// Additional context for the log entry.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Context {
    /// IP address (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,

    /// User agent (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Request identifier for tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Geographic location (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_location: Option<String>,

    /// Additional custom fields.
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

impl Context {
    /// Create empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set session ID.
    #[must_use]
    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session_id = Some(session.into());
        self
    }

    /// Set request ID.
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Add custom field.
    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}

/// A single audit log entry.
///
/// Contains all mandatory fields per LAW 8.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique, monotonically increasing event ID.
    pub event_id: u64,

    /// Timestamp in UTC with nanosecond precision.
    pub timestamp: DateTime<Utc>,

    /// Who performed the action.
    pub actor: Actor,

    /// What action was attempted.
    pub action: Action,

    /// What object was affected.
    pub object: String,

    /// Result of the action.
    pub result: ActionResult,

    /// Additional context.
    pub context: Context,

    /// Hash of the previous entry (chain link).
    /// None for the first entry (genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<[u8; 32]>,

    /// Hash of this entry (computed over all fields except this one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<[u8; 32]>,
}

impl AuditLogEntry {
    /// Create a new audit log entry.
    ///
    /// The `event_id`, `previous_hash`, and `entry_hash` are set when
    /// the entry is appended to the log.
    #[must_use]
    pub fn new(
        actor: Actor,
        action: Action,
        object: impl Into<String>,
        result: ActionResult,
    ) -> Self {
        Self {
            event_id: 0, // Set by AuditLog::append
            timestamp: Utc::now(),
            actor,
            action,
            object: object.into(),
            result,
            context: Context::default(),
            previous_hash: None,
            entry_hash: None,
        }
    }

    /// Add context to the entry.
    #[must_use]
    pub fn with_context(mut self, context: Context) -> Self {
        self.context = context;
        self
    }

    /// Compute the hash of this entry.
    ///
    /// The hash covers all fields EXCEPT `entry_hash` itself.
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();

        // Hash all fields in deterministic order
        hasher.update(&self.event_id.to_le_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(&serde_json::to_vec(&self.actor).unwrap_or_default());
        hasher.update(&serde_json::to_vec(&self.action).unwrap_or_default());
        hasher.update(self.object.as_bytes());
        hasher.update(&serde_json::to_vec(&self.result).unwrap_or_default());
        hasher.update(&serde_json::to_vec(&self.context).unwrap_or_default());

        if let Some(prev) = &self.previous_hash {
            hasher.update(prev);
        }

        *hasher.finalize().as_bytes()
    }

    /// Verify the entry's hash is correct.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        match &self.entry_hash {
            Some(stored) => {
                let computed = self.compute_hash();
                // Use constant-time comparison
                teras_kunci::ct_eq(stored, &computed)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_creation() {
        let entry = AuditLogEntry::new(
            Actor::User {
                id: "user1".into(),
                device_id: None,
            },
            Action::Authentication {
                method: "password".into(),
            },
            "session-123",
            ActionResult::Success,
        );

        assert_eq!(entry.object, "session-123");
    }

    #[test]
    fn test_entry_with_context() {
        let ctx = Context::new()
            .with_ip("192.168.1.1")
            .with_session("sess-001");

        let entry = AuditLogEntry::new(
            Actor::System {
                component: "auth".into(),
            },
            Action::SecurityEvent {
                event_type: "login_attempt".into(),
                severity: "low".into(),
            },
            "auth-system",
            ActionResult::Success,
        )
        .with_context(ctx);

        assert_eq!(entry.context.ip_address, Some("192.168.1.1".into()));
    }

    #[test]
    fn test_hash_computation() {
        let entry = AuditLogEntry::new(
            Actor::User {
                id: "test".into(),
                device_id: None,
            },
            Action::DataAccess {
                data_type: "file".into(),
                mode: "read".into(),
            },
            "document.pdf",
            ActionResult::Success,
        );

        let hash1 = entry.compute_hash();
        let hash2 = entry.compute_hash();

        // Same entry should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_changes_with_content() {
        let entry1 = AuditLogEntry::new(
            Actor::User {
                id: "user1".into(),
                device_id: None,
            },
            Action::Authentication {
                method: "password".into(),
            },
            "session-1",
            ActionResult::Success,
        );

        let entry2 = AuditLogEntry::new(
            Actor::User {
                id: "user2".into(),
                device_id: None,
            },
            Action::Authentication {
                method: "password".into(),
            },
            "session-1",
            ActionResult::Success,
        );

        // Different content should produce different hash
        assert_ne!(entry1.compute_hash(), entry2.compute_hash());
    }

    #[test]
    fn test_actor_serialization() {
        let actor = Actor::User {
            id: "u1".into(),
            device_id: Some("d1".into()),
        };
        let json = serde_json::to_string(&actor).unwrap();
        assert!(json.contains("\"type\":\"User\""));
        assert!(json.contains("\"id\":\"u1\""));
    }

    #[test]
    fn test_action_result_serialization() {
        let result = ActionResult::Failure {
            reason: "invalid token".into(),
            code: Some("AUTH_001".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"Failure\""));
    }
}
