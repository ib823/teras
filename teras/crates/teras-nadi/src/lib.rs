//! TERAS NADI - Custom Transport Protocol
//!
//! NADI (نادي - "pulse" in Malay) is TERAS's proprietary transport protocol,
//! purpose-built for threat intelligence sharing.
//!
//! # Features
//!
//! - **Hybrid Post-Quantum Cryptography**: ML-KEM-768 + X25519 key exchange
//! - **8 Priority Lanes**: Critical alerts bypass congestion control
//! - **Forward Error Correction**: Reed-Solomon for critical packets
//! - **Selective ACK**: Efficient out-of-order packet handling
//! - **Stealth Mode**: Optional timing jitter for DPI evasion
//! - **Onion Routing**: Optional anonymous threat sharing (feature-gated)
//!
//! # Protocol Overview
//!
//! ## Handshake (3-RTT initial, 0-RTT resumption)
//!
//! ```text
//! Client                                   Server
//!    │  HANDSHAKE_INIT                        │
//!    │  (ephemeral keys, certificate)         │
//!    │───────────────────────────────────────>│
//!    │                      HANDSHAKE_RESP    │
//!    │  (ephemeral keys, ciphertext, sig)     │
//!    │<───────────────────────────────────────│
//!    │  HANDSHAKE_DONE                        │
//!    │  (client sig, early data)              │
//!    │───────────────────────────────────────>│
//!    │       ═══ SECURE CHANNEL ═══           │
//! ```
//!
//! ## Packet Structure
//!
//! ```text
//! ┌────────────────────────────────────────┐
//! │ Header (32 bytes)                      │
//! │ - Version/Type (1 byte)                │
//! │ - Flags (1 byte)                       │
//! │ - Sequence (4 bytes)                   │
//! │ - ACK (4 bytes)                        │
//! │ - Session ID (8 bytes)                 │
//! │ - Payload Length (2 bytes)             │
//! │ - Priority (1 byte)                    │
//! │ - Reserved (3 bytes)                   │
//! │ - Header MAC (8 bytes)                 │
//! ├────────────────────────────────────────┤
//! │ Payload (0-65503 bytes, encrypted)     │
//! └────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use teras_nadi::{NadiConnection, NadiConfig};
//!
//! // Create connection
//! let config = NadiConfig::default();
//! let mut conn = NadiConnection::connect("127.0.0.1:4433", config).await?;
//!
//! // Send threat alert (priority 7, bypasses congestion)
//! conn.send_threat_alert(&threat_data).await?;
//!
//! // Send normal data
//! conn.send(&data, Priority::Normal).await?;
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unused_async)]
#![allow(clippy::non_std_lazy_statics)]
#![allow(clippy::cloned_instead_of_copied)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::if_not_else)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::range_plus_one)]
#![allow(clippy::single_match_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_assert)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::needless_borrows_for_generic_args)]

pub mod congestion;
pub mod crypto;
pub mod error;
pub mod fec;
pub mod handshake;
pub mod packet;
pub mod reliability;

#[cfg(feature = "onion")]
pub mod onion;

// Re-exports for convenience
pub use congestion::{CongestionState, NadiCongestionControl, PacingController};
pub use crypto::{PacketCrypto, SessionKeys};
pub use error::{NadiError, NadiResult};
pub use fec::{FecConfig, ReedSolomonDecoder, ReedSolomonEncoder};
pub use handshake::{ClientFinished, ClientHello, HandshakeContext, HandshakeState, ServerHello};
pub use packet::{
    Packet, PacketFlags, PacketHeader, PacketType, Priority, HEADER_SIZE, MAX_PACKET_SIZE,
    MAX_PAYLOAD_SIZE, MIN_PACKET_SIZE, NADI_VERSION,
};
pub use reliability::{
    ReliabilityManager, RttEstimator, SackBlock, SentPacket, MAX_RETRANSMITS,
};

/// NADI configuration.
#[derive(Debug, Clone)]
pub struct NadiConfig {
    /// Maximum retransmission attempts.
    pub max_retransmits: u8,
    /// Initial congestion window (bytes).
    pub initial_cwnd: u32,
    /// Maximum window size.
    pub max_window: u32,
    /// Enable stealth mode.
    pub stealth_mode: bool,
    /// Stealth jitter range (min, max) in microseconds.
    pub stealth_jitter: (u64, u64),
    /// FEC threshold priority (packets at or above this priority get FEC).
    pub fec_threshold: Priority,
    /// Connection timeout.
    pub connect_timeout: std::time::Duration,
    /// Idle timeout.
    pub idle_timeout: std::time::Duration,
}

impl Default for NadiConfig {
    fn default() -> Self {
        Self {
            max_retransmits: reliability::MAX_RETRANSMITS,
            initial_cwnd: congestion::INITIAL_CWND,
            max_window: congestion::MAX_CWND,
            stealth_mode: false,
            stealth_jitter: (0, 1000),
            fec_threshold: Priority::High,
            connect_timeout: std::time::Duration::from_secs(30),
            idle_timeout: std::time::Duration::from_secs(60),
        }
    }
}

/// Connection statistics.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Bytes sent (payload only).
    pub bytes_sent: u64,
    /// Bytes received (payload only).
    pub bytes_received: u64,
    /// Packets retransmitted.
    pub retransmits: u64,
    /// Packets lost.
    pub packets_lost: u64,
    /// Current congestion window.
    pub cwnd: u32,
    /// Current smoothed RTT.
    pub srtt_ms: Option<u64>,
    /// Packets in flight.
    pub in_flight: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = NadiConfig::default();
        assert_eq!(config.max_retransmits, 5);
        assert!(!config.stealth_mode);
    }

    #[test]
    fn test_version() {
        assert_eq!(NADI_VERSION, 1);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::VeryHigh);
        assert!(Priority::VeryHigh > Priority::High);
        assert!(Priority::High > Priority::Normal);
        assert!(Priority::Normal > Priority::Low);
        assert!(Priority::Low > Priority::Background);
    }

    #[test]
    fn test_packet_sizes() {
        assert_eq!(HEADER_SIZE, 32);
        assert_eq!(MIN_PACKET_SIZE, HEADER_SIZE);
        assert_eq!(MAX_PACKET_SIZE, HEADER_SIZE + MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }
}
