//! NADI Congestion Control (NADI-CC).
//!
//! Custom congestion control optimized for threat intelligence:
//! - 8 priority lanes with bandwidth quotas
//! - Critical alerts bypass congestion control
//! - Stealth mode with timing jitter (optional)
//!
//! # Priority Bandwidth Allocation
//!
//! - Critical (7): 40% of bandwidth
//! - VeryHigh (6): 25% of bandwidth
//! - High (5): 15% of bandwidth
//! - Others (0-4): Share remaining 20%

use crate::error::{NadiError, NadiResult};
use crate::packet::{Packet, Priority};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Number of priority levels.
pub const PRIORITY_LEVELS: usize = 8;

/// Initial congestion window in bytes.
pub const INITIAL_CWND: u32 = 14720; // ~10 packets

/// Minimum congestion window.
pub const MIN_CWND: u32 = 1472; // 1 packet

/// Maximum congestion window.
pub const MAX_CWND: u32 = 1_000_000; // ~1MB

/// Slow start threshold initial value.
pub const INITIAL_SSTHRESH: u32 = u32::MAX;

/// Congestion control state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Slow start phase.
    SlowStart,
    /// Congestion avoidance phase.
    CongestionAvoidance,
    /// Fast recovery after loss.
    FastRecovery,
}

/// NADI Congestion Controller.
pub struct NadiCongestionControl {
    /// Congestion window in bytes.
    #[doc(hidden)]
    pub cwnd: u32,
    /// Slow start threshold.
    #[doc(hidden)]
    pub ssthresh: u32,
    /// Current congestion state.
    state: CongestionState,
    /// Priority queues.
    queues: [VecDeque<Packet>; PRIORITY_LEVELS],
    /// Bytes in flight per priority.
    in_flight: [u32; PRIORITY_LEVELS],
    /// Total bytes in flight.
    #[doc(hidden)]
    pub total_in_flight: u32,
    /// Stealth mode enabled.
    stealth_mode: bool,
    /// Jitter range for stealth mode (microseconds).
    stealth_jitter_us: (u64, u64),
    /// Last packet send time (for stealth pacing).
    last_send: Option<Instant>,
    /// Packets acked since last increase.
    acked_bytes: u32,
    /// Duplicate ACK count (for fast retransmit).
    dup_ack_count: u32,
}

impl Default for NadiCongestionControl {
    fn default() -> Self {
        Self::new()
    }
}

impl NadiCongestionControl {
    /// Create a new congestion controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            state: CongestionState::SlowStart,
            queues: Default::default(),
            in_flight: [0; PRIORITY_LEVELS],
            total_in_flight: 0,
            stealth_mode: false,
            stealth_jitter_us: (0, 1000), // 0-1ms default
            last_send: None,
            acked_bytes: 0,
            dup_ack_count: 0,
        }
    }

    /// Enable stealth mode with specified jitter range.
    pub fn enable_stealth(&mut self, min_jitter_us: u64, max_jitter_us: u64) {
        self.stealth_mode = true;
        self.stealth_jitter_us = (min_jitter_us, max_jitter_us);
    }

    /// Disable stealth mode.
    pub fn disable_stealth(&mut self) {
        self.stealth_mode = false;
    }

    /// Check if stealth mode is enabled.
    #[must_use]
    pub fn is_stealth(&self) -> bool {
        self.stealth_mode
    }

    /// Get the stealth jitter duration.
    #[must_use]
    pub fn stealth_jitter(&self) -> Duration {
        use rand::Rng;

        if !self.stealth_mode {
            return Duration::ZERO;
        }

        let jitter = rand::thread_rng().gen_range(self.stealth_jitter_us.0..=self.stealth_jitter_us.1);
        Duration::from_micros(jitter)
    }

    /// Enqueue a packet for sending.
    pub fn enqueue(&mut self, packet: Packet) -> NadiResult<()> {
        let priority = Priority::from_raw(packet.header.priority) as usize;

        if priority >= PRIORITY_LEVELS {
            return Err(NadiError::Internal("invalid priority level".into()));
        }

        self.queues[priority].push_back(packet);
        Ok(())
    }

    /// Get the next packet to send based on priority and quotas.
    ///
    /// Returns `None` if no packets can be sent (either queues empty
    /// or congestion window exhausted).
    pub fn next_packet(&mut self) -> Option<Packet> {
        // Critical alerts (priority 7) always go first, bypassing congestion
        if let Some(pkt) = self.queues[Priority::Critical as usize].pop_front() {
            return Some(pkt);
        }

        // Check if we have room in congestion window
        if self.total_in_flight >= self.cwnd {
            return None;
        }

        // Try each priority level from high to low, respecting quotas
        for priority in (0..PRIORITY_LEVELS).rev() {
            if priority == Priority::Critical as usize {
                continue; // Already handled
            }

            let quota = self.priority_quota(priority as u8);
            if self.in_flight[priority] < quota {
                if let Some(pkt) = self.queues[priority].pop_front() {
                    return Some(pkt);
                }
            }
        }

        // If quotas prevent sending, try any non-empty queue
        for priority in (0..PRIORITY_LEVELS).rev() {
            if let Some(pkt) = self.queues[priority].pop_front() {
                return Some(pkt);
            }
        }

        None
    }

    /// Calculate bandwidth quota for a priority level.
    fn priority_quota(&self, priority: u8) -> u32 {
        let pct = match priority {
            7 => 40,  // Critical: 40%
            6 => 25,  // VeryHigh: 25%
            5 => 15,  // High: 15%
            4 => 5,   // AboveNormal
            3 => 5,   // Normal
            2 => 4,   // BelowNormal
            1 => 3,   // Low
            0 => 3,   // Background
            _ => 0,
        };

        (self.cwnd as u64 * pct / 100) as u32
    }

    /// Record that a packet was sent.
    pub fn on_packet_sent(&mut self, priority: Priority, size: u32) {
        let idx = priority as usize;
        self.in_flight[idx] = self.in_flight[idx].saturating_add(size);
        self.total_in_flight = self.total_in_flight.saturating_add(size);
        self.last_send = Some(Instant::now());
    }

    /// Record that a packet was acknowledged.
    pub fn on_packet_acked(&mut self, priority: Priority, size: u32) {
        let idx = priority as usize;
        self.in_flight[idx] = self.in_flight[idx].saturating_sub(size);
        self.total_in_flight = self.total_in_flight.saturating_sub(size);
        self.acked_bytes = self.acked_bytes.saturating_add(size);
        self.dup_ack_count = 0;

        // Increase congestion window
        match self.state {
            CongestionState::SlowStart => {
                // Exponential increase
                self.cwnd = (self.cwnd + size).min(MAX_CWND);

                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                }
            }
            CongestionState::CongestionAvoidance => {
                // Linear increase (AIMD)
                if self.acked_bytes >= self.cwnd {
                    self.cwnd = (self.cwnd + MIN_CWND).min(MAX_CWND);
                    self.acked_bytes = 0;
                }
            }
            CongestionState::FastRecovery => {
                // Exit fast recovery on new ACK
                self.state = CongestionState::CongestionAvoidance;
                self.cwnd = self.ssthresh;
            }
        }
    }

    /// Record that a packet was lost.
    pub fn on_packet_lost(&mut self, priority: Priority, size: u32) {
        let idx = priority as usize;
        self.in_flight[idx] = self.in_flight[idx].saturating_sub(size);
        self.total_in_flight = self.total_in_flight.saturating_sub(size);

        // Multiplicative decrease
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND * 2);
        self.cwnd = self.ssthresh;
        self.state = CongestionState::CongestionAvoidance;
    }

    /// Record a duplicate ACK (for fast retransmit).
    pub fn on_dup_ack(&mut self) {
        self.dup_ack_count += 1;

        if self.dup_ack_count == 3 && self.state != CongestionState::FastRecovery {
            // Enter fast recovery
            self.ssthresh = (self.cwnd / 2).max(MIN_CWND * 2);
            self.cwnd = self.ssthresh + 3 * MIN_CWND;
            self.state = CongestionState::FastRecovery;
        } else if self.state == CongestionState::FastRecovery {
            // Inflate window during fast recovery
            self.cwnd = (self.cwnd + MIN_CWND).min(MAX_CWND);
        }
    }

    /// Get current congestion window.
    #[must_use]
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Get slow start threshold.
    #[must_use]
    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Get current congestion state.
    #[must_use]
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// Get total bytes in flight.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.total_in_flight
    }

    /// Get bytes in flight for a specific priority.
    #[must_use]
    pub fn priority_in_flight(&self, priority: Priority) -> u32 {
        self.in_flight[priority as usize]
    }

    /// Get queue length for a specific priority.
    #[must_use]
    pub fn queue_len(&self, priority: Priority) -> usize {
        self.queues[priority as usize].len()
    }

    /// Get total queued packet count.
    #[must_use]
    pub fn total_queued(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// Check if sending is allowed (congestion window has room).
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.total_in_flight < self.cwnd || !self.queues[Priority::Critical as usize].is_empty()
    }

    /// Reset congestion state (e.g., after connection reset).
    pub fn reset(&mut self) {
        self.cwnd = INITIAL_CWND;
        self.ssthresh = INITIAL_SSTHRESH;
        self.state = CongestionState::SlowStart;
        self.in_flight = [0; PRIORITY_LEVELS];
        self.total_in_flight = 0;
        self.acked_bytes = 0;
        self.dup_ack_count = 0;
    }
}

/// Pacing controller for smooth packet transmission.
pub struct PacingController {
    /// Target rate in bytes per second.
    target_rate: u64,
    /// Tokens available (in bytes).
    tokens: u64,
    /// Last refill time.
    last_refill: Instant,
    /// Maximum burst size.
    max_burst: u64,
}

impl PacingController {
    /// Create a new pacing controller.
    #[must_use]
    pub fn new(rate_bps: u64) -> Self {
        Self {
            target_rate: rate_bps,
            tokens: rate_bps / 10, // Start with 100ms worth of tokens
            last_refill: Instant::now(),
            max_burst: rate_bps / 5, // Allow 200ms burst
        }
    }

    /// Refill tokens based on elapsed time.
    pub fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = (elapsed.as_secs_f64() * self.target_rate as f64) as u64;

        self.tokens = (self.tokens + new_tokens).min(self.max_burst);
        self.last_refill = now;
    }

    /// Check if a packet can be sent.
    #[must_use]
    pub fn can_send(&self, size: u32) -> bool {
        self.tokens >= size as u64
    }

    /// Consume tokens for a packet.
    pub fn consume(&mut self, size: u32) {
        self.tokens = self.tokens.saturating_sub(size as u64);
    }

    /// Time until next packet can be sent.
    #[must_use]
    pub fn time_until_send(&self, size: u32) -> Duration {
        if self.tokens >= size as u64 {
            Duration::ZERO
        } else {
            let needed = size as u64 - self.tokens;
            let secs = needed as f64 / self.target_rate as f64;
            Duration::from_secs_f64(secs)
        }
    }

    /// Update target rate.
    pub fn set_rate(&mut self, rate_bps: u64) {
        self.target_rate = rate_bps;
        self.max_burst = rate_bps / 5;
    }

    /// Get current rate.
    #[must_use]
    pub fn rate(&self) -> u64 {
        self.target_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketHeader, PacketType};
    use bytes::Bytes;

    fn make_packet(priority: u8) -> Packet {
        let mut header = PacketHeader::new(PacketType::Data);
        header.priority = priority;
        header.payload_length = 100;
        Packet {
            header,
            payload: Bytes::from(vec![0u8; 100]),
        }
    }

    #[test]
    fn test_initial_state() {
        let cc = NadiCongestionControl::new();
        assert_eq!(cc.cwnd(), INITIAL_CWND);
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.in_flight(), 0);
    }

    #[test]
    fn test_priority_queuing() {
        let mut cc = NadiCongestionControl::new();

        // Enqueue packets at different priorities
        cc.enqueue(make_packet(0)).unwrap();   // Background
        cc.enqueue(make_packet(128)).unwrap(); // AboveNormal
        cc.enqueue(make_packet(255)).unwrap(); // Critical

        // Critical should come first
        let pkt = cc.next_packet().unwrap();
        assert_eq!(Priority::from_raw(pkt.header.priority), Priority::Critical);

        // Then AboveNormal
        let pkt = cc.next_packet().unwrap();
        assert_eq!(Priority::from_raw(pkt.header.priority), Priority::AboveNormal);

        // Then Background
        let pkt = cc.next_packet().unwrap();
        assert_eq!(Priority::from_raw(pkt.header.priority), Priority::Background);
    }

    #[test]
    fn test_critical_bypasses_congestion() {
        let mut cc = NadiCongestionControl::new();

        // Fill the congestion window
        cc.total_in_flight = cc.cwnd;

        // Normal packets should be blocked
        cc.enqueue(make_packet(64)).unwrap();
        assert!(cc.next_packet().is_none());

        // Critical packets should still go through
        cc.enqueue(make_packet(255)).unwrap();
        let pkt = cc.next_packet().unwrap();
        assert_eq!(Priority::from_raw(pkt.header.priority), Priority::Critical);
    }

    #[test]
    fn test_slow_start() {
        let mut cc = NadiCongestionControl::new();
        let initial = cc.cwnd();

        // ACK a packet
        cc.on_packet_acked(Priority::Normal, 1000);

        // Window should grow exponentially
        assert!(cc.cwnd() > initial);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_congestion_avoidance() {
        let mut cc = NadiCongestionControl::new();
        cc.ssthresh = 20000;
        cc.cwnd = 20000;
        cc.state = CongestionState::CongestionAvoidance;

        let initial = cc.cwnd();

        // ACK one window's worth (need to ack >= cwnd bytes for 1 MSS increase)
        for _ in 0..25 {
            cc.on_packet_acked(Priority::Normal, 1000);
        }

        // Window should grow by ~1 MSS
        assert!(cc.cwnd() > initial);
        assert!(cc.cwnd() <= initial + 2 * MIN_CWND);
    }

    #[test]
    fn test_packet_loss() {
        let mut cc = NadiCongestionControl::new();
        cc.cwnd = 50000;

        let initial = cc.cwnd();
        cc.on_packet_lost(Priority::Normal, 1000);

        // Window should halve
        assert!(cc.cwnd() < initial);
        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_fast_recovery() {
        let mut cc = NadiCongestionControl::new();
        cc.cwnd = 50000;

        // 3 duplicate ACKs trigger fast recovery
        cc.on_dup_ack();
        cc.on_dup_ack();
        cc.on_dup_ack();

        assert_eq!(cc.state(), CongestionState::FastRecovery);

        // New ACK exits fast recovery
        cc.on_packet_acked(Priority::Normal, 1000);
        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_stealth_mode() {
        let mut cc = NadiCongestionControl::new();
        assert!(!cc.is_stealth());

        cc.enable_stealth(100, 1000);
        assert!(cc.is_stealth());

        let jitter = cc.stealth_jitter();
        assert!(jitter <= Duration::from_micros(1000));

        cc.disable_stealth();
        assert!(!cc.is_stealth());
        assert_eq!(cc.stealth_jitter(), Duration::ZERO);
    }

    #[test]
    fn test_pacing_controller() {
        let mut pacing = PacingController::new(1_000_000); // 1 MB/s

        // Should start with some tokens
        assert!(pacing.can_send(1000));

        // Consume tokens
        for _ in 0..100 {
            pacing.consume(1000);
        }

        // Eventually should run out
        assert!(!pacing.can_send(1_000_000));

        // Time to send should be positive
        let wait = pacing.time_until_send(1000);
        assert!(wait > Duration::ZERO);
    }

    #[test]
    fn test_priority_quota() {
        let cc = NadiCongestionControl::new();

        let critical_quota = cc.priority_quota(7);
        let high_quota = cc.priority_quota(5);
        let low_quota = cc.priority_quota(1);

        // Critical should have highest quota
        assert!(critical_quota > high_quota);
        assert!(high_quota > low_quota);

        // Total quotas should roughly equal cwnd
        let total: u32 = (0..8).map(|p| cc.priority_quota(p)).sum();
        assert!(total > cc.cwnd() * 95 / 100); // At least 95% allocated
    }

    #[test]
    fn test_reset() {
        let mut cc = NadiCongestionControl::new();

        // Modify state
        cc.cwnd = 100000;
        cc.state = CongestionState::FastRecovery;
        cc.on_packet_sent(Priority::High, 1000);

        // Reset
        cc.reset();

        assert_eq!(cc.cwnd(), INITIAL_CWND);
        assert_eq!(cc.state(), CongestionState::SlowStart);
        assert_eq!(cc.in_flight(), 0);
    }
}
