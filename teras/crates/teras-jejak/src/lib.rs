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
//! - Actor (who performed the action)
//! - Action (what was attempted)
//! - Object (what was affected)
//! - Result (success/failure with reason)
//! - Context (additional structured data)
//! - Previous hash (chain link)
//! - Entry hash (integrity)
//!
//! # Example
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

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod chain;
mod entry;
mod retention;
pub mod storage;
mod verification;

pub use chain::AuditLog;
pub use entry::{Action, ActionResult, Actor, AuditLogEntry, Context};
pub use retention::RetentionPolicy;
pub use verification::ChainVerificationResult;
