//! Retention policy enforcement for audit logs.
//!
//! Implements the 7-year minimum retention requirement from LAW 8.

use chrono::{DateTime, TimeDelta, Utc};

/// Minimum retention period in years (per LAW 8).
pub const MINIMUM_RETENTION_YEARS: i32 = 7;

/// Retention policy for audit logs.
///
/// Enforces the LAW 8 requirement that logs be retained for a minimum
/// of 7 years. Attempting to delete logs before this period will panic.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Minimum retention period.
    minimum_retention: TimeDelta,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RetentionPolicy {
    /// Create a new retention policy with the 7-year minimum.
    ///
    /// # Panics
    ///
    /// Panics if the retention period cannot be represented (should never happen).
    #[must_use]
    pub fn new() -> Self {
        Self {
            // 7 years = 7 * 365 days (approximation, ignoring leap years)
            minimum_retention: TimeDelta::try_days(i64::from(MINIMUM_RETENTION_YEARS) * 365)
                .expect("7 years in days is valid"),
        }
    }

    /// Check if a log entry can be deleted based on its timestamp.
    ///
    /// # Panics
    ///
    /// **INTENTIONALLY PANICS** if the entry is younger than 7 years.
    /// This is a security control per LAW 8 - audit logs MUST be retained.
    ///
    /// Deletion attempts on logs younger than 7 years indicate either:
    /// 1. A bug in the system
    /// 2. An attempted security violation
    ///
    /// Both cases warrant immediate program termination.
    #[must_use]
    pub fn can_delete(&self, entry_timestamp: DateTime<Utc>) -> bool {
        let age = Utc::now().signed_duration_since(entry_timestamp);

        // LAW 8: PANIC on retention violation
        // This is intentional - attempting to delete logs before 7 years
        // is a critical security violation that must halt the system.
        assert!(
            age >= self.minimum_retention,
            "SECURITY VIOLATION: Attempted to delete audit log entry \
             before minimum retention period (7 years). Entry age: {} days, \
             Required minimum: {} days. This incident has been logged.",
            age.num_days(),
            self.minimum_retention.num_days()
        );

        true
    }

    /// Check if an entry is within the retention period (without panicking).
    ///
    /// Use this for informational queries only, NOT for deletion decisions.
    #[must_use]
    pub fn is_within_retention(&self, entry_timestamp: DateTime<Utc>) -> bool {
        let age = Utc::now().signed_duration_since(entry_timestamp);
        age < self.minimum_retention
    }

    /// Get the retention period in days.
    #[must_use]
    pub fn retention_days(&self) -> i64 {
        self.minimum_retention.num_days()
    }

    /// Calculate the earliest date an entry can be deleted.
    #[must_use]
    pub fn earliest_deletion_date(&self, entry_timestamp: DateTime<Utc>) -> DateTime<Utc> {
        entry_timestamp + self.minimum_retention
    }

    /// Calculate how many days until an entry can be deleted.
    ///
    /// Returns 0 if the entry can already be deleted.
    #[must_use]
    pub fn days_until_deletable(&self, entry_timestamp: DateTime<Utc>) -> i64 {
        let earliest = self.earliest_deletion_date(entry_timestamp);
        let remaining = earliest.signed_duration_since(Utc::now());

        if remaining.num_days() < 0 {
            0
        } else {
            remaining.num_days()
        }
    }
}

/// Audit the retention status of the log.
#[derive(Debug, Clone)]
pub struct RetentionAudit {
    /// Total entries in the log.
    pub total_entries: u64,
    /// Entries within retention period.
    pub entries_in_retention: u64,
    /// Entries past retention period (eligible for archival).
    pub entries_past_retention: u64,
    /// Oldest entry timestamp.
    pub oldest_entry: Option<DateTime<Utc>>,
    /// Newest entry timestamp.
    pub newest_entry: Option<DateTime<Utc>>,
}

impl RetentionAudit {
    /// Create an empty audit result.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            total_entries: 0,
            entries_in_retention: 0,
            entries_past_retention: 0,
            oldest_entry: None,
            newest_entry: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a `TimeDelta` from days.
    fn days(n: i64) -> TimeDelta {
        TimeDelta::try_days(n).expect("days value is valid")
    }

    #[test]
    fn test_retention_policy_defaults() {
        let policy = RetentionPolicy::new();
        // 7 years * 365 days
        assert_eq!(policy.retention_days(), 7 * 365);
    }

    #[test]
    fn test_is_within_retention_recent() {
        let policy = RetentionPolicy::new();
        let recent = Utc::now() - days(30);
        assert!(policy.is_within_retention(recent));
    }

    #[test]
    fn test_is_within_retention_old() {
        let policy = RetentionPolicy::new();
        // 8 years ago
        let old = Utc::now() - days(8 * 365);
        assert!(!policy.is_within_retention(old));
    }

    #[test]
    fn test_earliest_deletion_date() {
        let policy = RetentionPolicy::new();
        let entry_time = Utc::now();
        let earliest = policy.earliest_deletion_date(entry_time);

        let expected = entry_time + days(7 * 365);
        assert_eq!(earliest, expected);
    }

    #[test]
    fn test_days_until_deletable_recent() {
        let policy = RetentionPolicy::new();
        let recent = Utc::now() - days(30);
        let remaining = policy.days_until_deletable(recent);

        // Should be approximately 7*365 - 30 days
        assert!(remaining > 7 * 365 - 35);
        assert!(remaining < 7 * 365 - 25);
    }

    #[test]
    fn test_days_until_deletable_old() {
        let policy = RetentionPolicy::new();
        let old = Utc::now() - days(8 * 365);
        let remaining = policy.days_until_deletable(old);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_can_delete_old_entry() {
        let policy = RetentionPolicy::new();
        let old = Utc::now() - days(8 * 365);
        // Should not panic
        assert!(policy.can_delete(old));
    }

    #[test]
    #[should_panic(expected = "SECURITY VIOLATION")]
    fn test_can_delete_recent_entry_panics() {
        let policy = RetentionPolicy::new();
        let recent = Utc::now() - days(30);
        // Should panic - this is intentional security behavior
        let _ = policy.can_delete(recent);
    }

    #[test]
    fn test_retention_audit_empty() {
        let audit = RetentionAudit::empty();
        assert_eq!(audit.total_entries, 0);
        assert_eq!(audit.entries_in_retention, 0);
        assert!(audit.oldest_entry.is_none());
    }
}
