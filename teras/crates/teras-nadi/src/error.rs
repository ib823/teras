//! NADI protocol error types.

use thiserror::Error;

/// NADI protocol errors.
#[derive(Error, Debug)]
pub enum NadiError {
    /// Invalid packet format.
    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    /// Packet too short.
    #[error("packet too short: expected at least {expected} bytes, got {actual}")]
    PacketTooShort {
        /// Expected minimum size.
        expected: usize,
        /// Actual size received.
        actual: usize,
    },

    /// Packet too large.
    #[error("packet too large: maximum {max} bytes, got {actual}")]
    PacketTooLarge {
        /// Maximum allowed size.
        max: usize,
        /// Actual size.
        actual: usize,
    },

    /// Invalid packet type.
    #[error("invalid packet type: {0}")]
    InvalidPacketType(u8),

    /// Invalid protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Header MAC verification failed.
    #[error("header MAC verification failed")]
    HeaderMacInvalid,

    /// Payload authentication failed.
    #[error("payload authentication failed")]
    PayloadAuthFailed,

    /// Decryption failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Handshake error.
    #[error("handshake error: {0}")]
    HandshakeError(String),

    /// Invalid handshake state.
    #[error("invalid handshake state: expected {expected}, got {actual}")]
    InvalidHandshakeState {
        /// Expected state.
        expected: String,
        /// Actual state.
        actual: String,
    },

    /// Certificate verification failed.
    #[error("certificate verification failed: {0}")]
    CertificateInvalid(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Connection closed.
    #[error("connection closed: {0}")]
    ConnectionClosed(String),

    /// Connection reset.
    #[error("connection reset by peer")]
    ConnectionReset,

    /// Connection timeout.
    #[error("connection timeout")]
    ConnectionTimeout,

    /// Session not found.
    #[error("session not found: {0:016x}")]
    SessionNotFound(u64),

    /// Session expired.
    #[error("session expired")]
    SessionExpired,

    /// Retransmit limit exceeded.
    #[error("retransmit limit exceeded for sequence {0}")]
    RetransmitLimitExceeded(u32),

    /// Congestion window exhausted.
    #[error("congestion window exhausted")]
    CongestionWindowExhausted,

    /// Priority queue full.
    #[error("priority queue {priority} is full")]
    PriorityQueueFull {
        /// Priority level.
        priority: u8,
    },

    /// FEC decode failed.
    #[error("FEC decode failed: insufficient fragments ({received}/{required})")]
    FecDecodeFailed {
        /// Fragments received.
        received: usize,
        /// Fragments required.
        required: usize,
    },

    /// Invalid FEC parameters.
    #[error("invalid FEC parameters: {0}")]
    InvalidFecParams(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Feature not enabled.
    #[error("feature not enabled: {0}")]
    FeatureNotEnabled(String),

    /// Circuit not found (onion routing).
    #[cfg(feature = "onion")]
    #[error("circuit not found: {0:016x}")]
    CircuitNotFound(u64),

    /// Relay selection failed (onion routing).
    #[cfg(feature = "onion")]
    #[error("relay selection failed: {0}")]
    RelaySelectionFailed(String),
}

/// Result type for NADI operations.
pub type NadiResult<T> = Result<T, NadiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = NadiError::PacketTooShort {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            err.to_string(),
            "packet too short: expected at least 32 bytes, got 16"
        );
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let nadi_err: NadiError = io_err.into();
        assert!(matches!(nadi_err, NadiError::Io(_)));
    }

    #[test]
    fn test_invalid_packet_type() {
        let err = NadiError::InvalidPacketType(0xFF);
        assert_eq!(err.to_string(), "invalid packet type: 255");
    }

    #[test]
    fn test_session_not_found() {
        let err = NadiError::SessionNotFound(0x1234567890ABCDEF);
        assert_eq!(err.to_string(), "session not found: 1234567890abcdef");
    }
}
