//! TERAS Jejak - Audit Logging System
//!
//! Implements LAW 8: ALL security-relevant events MUST be logged.
//!
//! # Security Properties
//!
//! - **Append-only**: Entries cannot be deleted or modified
//! - **Cryptographically chained**: Each entry includes hash of previous
//! - **Tamper-evident**: Any modification breaks the chain
//! - **Retention**: 7-year minimum retention enforced
//!
//! # Log Entry Structure
//!
//! Every entry contains:
//! - Timestamp (UTC, nanosecond precision)
//! - Event ID (monotonic, unique)
//! - Level (severity indicator)
//! - Actor (who performed the action)
//! - Action (what was attempted)
//! - Object (what was affected)
//! - Message (human-readable description)
//! - Result (success/failure with reason)
//! - Context (additional structured data)
//! - Previous hash (chain link)
//! - Entry hash (integrity)
//!
//! # Example (Manual API)
//!
//! ```
//! use teras_jejak::{AuditLog, AuditLogEntry, Actor, Action, ActionResult};
//! use teras_jejak::storage::MemoryStorage;
//!
//! let storage = MemoryStorage::new();
//! let mut log = AuditLog::new(Box::new(storage));
//!
//! let entry = AuditLogEntry::new(
//!     Actor::User { id: "user123".into(), device_id: Some("dev456".into()) },
//!     Action::Authentication { method: "hybrid-kem".into() },
//!     "session-789",
//!     ActionResult::Success,
//! );
//!
//! log.append(entry).unwrap();
//! assert!(log.verify_chain().is_ok());
//! ```
//!
//! # Example (Macro API)
//!
//! ```
//! use teras_jejak::{audit_log, Level, Actor};
//!
//! // Simple usage (note the semicolon before the message)
//! audit_log!(action = "user_login"; "User logged in successfully");
//!
//! // With context fields
//! audit_log!(
//!     action = "threat_detected",
//!     threat_id = "THR-001",
//!     severity = 85;
//!     "Threat detected and blocked"
//! );
//!
//! // With explicit level and actor
//! audit_log!(
//!     level = Level::Critical,
//!     action = "security_event",
//!     actor = Actor::System { component: "detector".into() };
//!     "Critical security event"
//! );
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod chain;
mod entry;
pub mod macros;
mod retention;
pub mod storage;
mod verification;

pub use chain::AuditLog;
pub use entry::{Action, ActionResult, Actor, AuditLogEntry, AuditLogEntryBuilder, Context, Level};
pub use macros::{append_to_global_log, init_global_audit_log, now_utc, GLOBAL_AUDIT_LOG};
pub use retention::RetentionPolicy;
pub use verification::ChainVerificationResult;
