//! Audit logging macros for ergonomic, consistent logging across TERAS.
//!
//! The `audit_log!` macro provides a structured way to log security-relevant
//! events with consistent formatting and automatic context capture.
//!
//! # Usage
//!
//! ```rust
//! use teras_jejak::{audit_log, Level, Actor};
//!
//! // Simple usage
//! audit_log!(action = "user_login", "User logged in successfully");
//!
//! // With context fields
//! audit_log!(
//!     action = "threat_detected",
//!     threat_id = "THR-001",
//!     severity = 85,
//!     "Threat detected and blocked"
//! );
//!
//! // With explicit level and actor
//! audit_log!(
//!     level = Level::Critical,
//!     action = "key_compromise",
//!     actor = Actor::System { component: "teras-kunci".into() },
//!     key_id = "KEY-123",
//!     "Potential key compromise detected"
//! );
//! ```

use crate::entry::{AuditLogEntry, Context};
use crate::storage::MemoryStorage;
use crate::AuditLog;
use once_cell::sync::Lazy;
use std::sync::RwLock;

/// Returns the current UTC timestamp.
///
/// This is a convenience function for use with the audit logging system.
#[must_use]
pub fn now_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// Global audit log instance.
///
/// Thread-safe, append-only, cryptographically chained.
/// Initialized lazily on first use with in-memory storage.
///
/// For production use, replace with file-based storage via
/// `init_global_audit_log()`.
#[allow(clippy::non_std_lazy_statics)]
pub static GLOBAL_AUDIT_LOG: Lazy<RwLock<AuditLog>> = Lazy::new(|| {
    let storage = MemoryStorage::new();
    RwLock::new(AuditLog::new(Box::new(storage)))
});

/// Initialize the global audit log with custom storage.
///
/// This should be called once at application startup before any
/// audit logging occurs. If not called, a default in-memory
/// storage will be used.
///
/// # Errors
///
/// Returns error if the global log has already been initialized.
///
/// # Example
///
/// ```no_run
/// use teras_jejak::{init_global_audit_log, storage::MemoryStorage};
///
/// let storage = MemoryStorage::new();
/// init_global_audit_log(Box::new(storage)).expect("Failed to init");
/// ```
pub fn init_global_audit_log(
    storage: Box<dyn crate::storage::AuditStorage>,
) -> Result<(), &'static str> {
    // Check if already initialized
    if Lazy::get(&GLOBAL_AUDIT_LOG).is_some() {
        return Err("Global audit log already initialized");
    }

    // Force initialization with provided storage
    let log = AuditLog::new(storage);
    *GLOBAL_AUDIT_LOG.write().map_err(|_| "Lock poisoned")? = log;

    Ok(())
}

/// Append an entry to the global audit log.
///
/// Returns the event ID on success, or an error message on failure.
///
/// # Errors
///
/// Returns an error if the write lock cannot be acquired or if the
/// append operation fails.
pub fn append_to_global_log(entry: AuditLogEntry) -> Result<u64, String> {
    GLOBAL_AUDIT_LOG
        .write()
        .map_err(|e| format!("Failed to acquire write lock: {e}"))?
        .append(entry)
        .map_err(|e| format!("Failed to append entry: {e}"))
}

/// Build context from key-value pairs.
///
/// Used internally by the `audit_log!` macro.
#[doc(hidden)]
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn build_context_from_map(map: std::collections::HashMap<String, String>) -> Context {
    let mut ctx = Context::new();
    ctx.extra = map;
    ctx
}

/// Structured audit logging macro.
///
/// # Syntax
///
/// ```text
/// audit_log!(
///     level = Level::Info,           // Optional, defaults to Info
///     action = "action_name",        // Required
///     actor = Actor::System(...),    // Optional, defaults to current module
///     field1 = value1,               // Optional context fields (Display format)
///     field2 = %debug_value,         // Use % for Debug formatting
///     ; "Human readable message"     // Required message (note the semicolon)
/// );
/// ```
///
/// # Examples
///
/// ```rust
/// use teras_jejak::{audit_log, Level, Actor};
///
/// // Simple usage
/// audit_log!(action = "user_login"; "User logged in successfully");
///
/// // With context
/// audit_log!(
///     action = "threat_detected",
///     threat_id = "THR-001",
///     severity = 85;
///     "Threat detected and blocked"
/// );
///
/// // With explicit level and actor
/// audit_log!(
///     level = Level::Critical,
///     action = "key_compromise",
///     actor = Actor::System { component: "teras-kunci".into() },
///     key_id = "KEY-123";
///     "Potential key compromise detected"
/// );
/// ```
#[macro_export]
macro_rules! audit_log {
    // Full form with level, action, actor, context fields, and message
    (
        level = $level:expr,
        action = $action:expr,
        actor = $actor:expr
        $(, $key:ident = $value:expr)*
        ; $msg:expr
    ) => {{
        let mut context_map = ::std::collections::HashMap::new();
        $(
            context_map.insert(stringify!($key).to_string(), $value.to_string());
        )*

        let context = $crate::macros::build_context_from_map(context_map);

        let entry = $crate::AuditLogEntry::builder()
            .level($level)
            .action($crate::Action::Custom {
                name: $action.into(),
                details: None,
            })
            .actor($actor)
            .message($msg)
            .context(context)
            .timestamp($crate::macros::now_utc())
            .build();

        let _ = $crate::macros::append_to_global_log(entry);
    }};

    // With level and action, no explicit actor
    (
        level = $level:expr,
        action = $action:expr
        $(, $key:ident = $value:expr)*
        ; $msg:expr
    ) => {{
        $crate::audit_log!(
            level = $level,
            action = $action,
            actor = $crate::Actor::System { component: module_path!().into() }
            $(, $key = $value)*
            ; $msg
        )
    }};

    // With action and actor, default level (Info)
    (
        action = $action:expr,
        actor = $actor:expr
        $(, $key:ident = $value:expr)*
        ; $msg:expr
    ) => {{
        $crate::audit_log!(
            level = $crate::Level::Info,
            action = $action,
            actor = $actor
            $(, $key = $value)*
            ; $msg
        )
    }};

    // Minimal form: just action and message (with optional context fields)
    (
        action = $action:expr
        $(, $key:ident = $value:expr)*
        ; $msg:expr
    ) => {{
        $crate::audit_log!(
            level = $crate::Level::Info,
            action = $action,
            actor = $crate::Actor::System { component: module_path!().into() }
            $(, $key = $value)*
            ; $msg
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Action, ActionResult, Actor, Level};

    #[test]
    fn test_now_utc() {
        let now = now_utc();
        // Should be close to current time
        let diff = chrono::Utc::now() - now;
        assert!(diff.num_seconds().abs() < 1);
    }

    #[test]
    fn test_global_log_exists() {
        // Just accessing the global log should not panic
        let _count = GLOBAL_AUDIT_LOG.read().unwrap().count().unwrap();
    }

    #[test]
    fn test_append_to_global_log() {
        let entry = AuditLogEntry::new(
            Actor::System {
                component: "test".into(),
            },
            Action::Custom {
                name: "test_action".into(),
                details: None,
            },
            "test_object",
            ActionResult::Success,
        );

        let result = append_to_global_log(entry);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_log_macro_simple() {
        audit_log!(action = "test_simple"; "Simple test message");

        // Verify entry was logged
        let count = GLOBAL_AUDIT_LOG.read().unwrap().count().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_macro_with_context() {
        audit_log!(
            action = "test_context",
            user_id = "user123",
            request_id = "req456";
            "Test with context"
        );

        let count = GLOBAL_AUDIT_LOG.read().unwrap().count().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_macro_with_level() {
        audit_log!(
            level = Level::Critical,
            action = "test_critical";
            "Critical test message"
        );

        let count = GLOBAL_AUDIT_LOG.read().unwrap().count().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_macro_with_actor() {
        audit_log!(
            action = "test_actor",
            actor = Actor::User {
                id: "alice".into(),
                device_id: None
            };
            "Test with explicit actor"
        );

        let count = GLOBAL_AUDIT_LOG.read().unwrap().count().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_macro_with_debug_format() {
        let data = vec![1, 2, 3];
        audit_log!(
            action = "test_debug",
            data = ?data;
            "Test with debug format"
        );

        let count = GLOBAL_AUDIT_LOG.read().unwrap().count().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_audit_log_macro_full() {
        audit_log!(
            level = Level::Warn,
            action = "test_full",
            actor = Actor::Device {
                id: "dev001".into(),
                device_type: "mobile".into()
            },
            threat_id = "THR-001",
            severity = 75,
            source = ?"network";
            "Full test with all options"
        );

        let count = GLOBAL_AUDIT_LOG.read().unwrap().count().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_build_context_from_map() {
        let mut map = std::collections::HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        let ctx = build_context_from_map(map);
        assert_eq!(ctx.extra.get("key1"), Some(&"value1".to_string()));
        assert_eq!(ctx.extra.get("key2"), Some(&"value2".to_string()));
    }
}
