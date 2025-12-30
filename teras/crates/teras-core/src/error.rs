// crates/teras-core/src/error.rs
// COMPLETE IMPLEMENTATION FROM ARCHITECTURE DOC - USE EXACTLY AS IS

use std::fmt;

/// All TERAS errors.
///
/// Every function that can fail MUST return Result<T, TerasError>.
/// NEVER use unwrap(), expect(), or panic!() on user input.
#[derive(Debug)]
pub enum TerasError {
    // Cryptographic errors
    InvalidKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidSignature,
    DecryptionFailed,
    KeyDerivationFailed,
    RandomGenerationFailed,
    HybridCryptoFailed {
        classical_ok: bool,
        pq_ok: bool,
    },

    // Memory errors
    MemoryLockFailed,
    MemoryUnlockFailed,
    ZeroizationFailed,

    // Format errors
    InvalidMagic {
        expected: u32,
        actual: u32,
    },
    InvalidVersion {
        expected: u16,
        actual: u16,
    },
    InvalidChecksum,
    InvalidFormat(String),

    // Validation errors
    ExpiredKey,
    InvalidAttestation,
    ReplayDetected,
    TimestampOutOfRange,

    // Biometric errors (v3.1)
    LivenessCheckFailed {
        score: u8,
    },
    DeepfakeDetected {
        score: u8,
    },
    InsufficientSignals {
        required: u8,
        provided: u8,
    },

    // Device binding errors (v3.1)
    DeviceNotBound,
    DeviceMismatch,

    // Audit errors (v3.1)
    AuditChainBroken {
        entry_index: u64,
    },
    AuditLogFull,

    // Threat feed errors (v3.1)
    /// Threat feed fetch failed.
    ThreatFeedFetchFailed {
        /// Source identifier.
        source: String,
        /// Reason for failure.
        reason: String,
    },
    /// Threat feed parse failed.
    ThreatFeedParseFailed {
        /// Format that failed to parse.
        format: String,
        /// Reason for failure.
        reason: String,
    },
    /// Threat indicator invalid.
    ThreatIndicatorInvalid {
        /// The invalid indicator value.
        indicator: String,
        /// Reason for invalidity.
        reason: String,
    },

    // IO errors
    IoError(std::io::Error),
    NetworkError(String),

    // Platform errors
    PlatformNotSupported(String),

    // Configuration errors
    /// Configuration error.
    ConfigurationError {
        /// Component with error.
        component: String,
        /// Error message.
        message: String,
    },

    // Serialization errors
    /// Serialization failed.
    SerializationFailed {
        /// The type that failed to serialize.
        type_name: String,
        /// Reason for failure.
        reason: String,
    },
    /// Deserialization failed.
    DeserializationFailed {
        /// The type that failed to deserialize.
        type_name: String,
        /// Reason for failure.
        reason: String,
    },

    // Signature errors
    /// Key not found in keystore.
    KeyNotFound {
        /// The key ID that was not found.
        key_id: String,
    },
    /// Document not found.
    DocumentNotFound {
        /// The document ID that was not found.
        document_id: String,
    },

    // Biometric enrollment/verification errors (v3.1 - Phase 7)
    /// Biometric enrollment failed.
    BiometricEnrollmentFailed {
        /// Reason for failure.
        reason: String,
    },
    /// Biometric verification failed.
    BiometricVerificationFailed {
        /// Reason for failure.
        reason: String,
    },
}

impl fmt::Display for TerasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid key length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Self::RandomGenerationFailed => write!(f, "Random generation failed"),
            Self::HybridCryptoFailed {
                classical_ok,
                pq_ok,
            } => {
                write!(
                    f,
                    "Hybrid crypto failed: classical={}, pq={}",
                    classical_ok, pq_ok
                )
            }
            Self::MemoryLockFailed => write!(f, "Memory lock (mlock) failed"),
            Self::MemoryUnlockFailed => write!(f, "Memory unlock (munlock) failed"),
            Self::ZeroizationFailed => write!(f, "Zeroization verification failed"),
            Self::InvalidMagic { expected, actual } => {
                write!(
                    f,
                    "Invalid magic: expected 0x{:08X}, got 0x{:08X}",
                    expected, actual
                )
            }
            Self::InvalidVersion { expected, actual } => {
                write!(f, "Invalid version: expected {}, got {}", expected, actual)
            }
            Self::InvalidChecksum => write!(f, "Invalid checksum"),
            Self::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            Self::ExpiredKey => write!(f, "Key has expired"),
            Self::InvalidAttestation => write!(f, "Invalid attestation"),
            Self::ReplayDetected => write!(f, "Replay attack detected"),
            Self::TimestampOutOfRange => write!(f, "Timestamp out of acceptable range"),
            Self::LivenessCheckFailed { score } => {
                write!(f, "Liveness check failed: score {} < 80", score)
            }
            Self::DeepfakeDetected { score } => {
                write!(f, "Deepfake detected: score {} > 20", score)
            }
            Self::InsufficientSignals { required, provided } => {
                write!(
                    f,
                    "Insufficient liveness signals: {} required, {} provided",
                    required, provided
                )
            }
            Self::DeviceNotBound => write!(f, "Device not bound to identity"),
            Self::DeviceMismatch => write!(f, "Device does not match registered device"),
            Self::AuditChainBroken { entry_index } => {
                write!(f, "Audit chain broken at entry {}", entry_index)
            }
            Self::AuditLogFull => write!(f, "Audit log storage full"),
            Self::ThreatFeedFetchFailed { source, reason } => {
                write!(f, "Threat feed fetch failed for {}: {}", source, reason)
            }
            Self::ThreatFeedParseFailed { format, reason } => {
                write!(f, "Threat feed parse failed for {}: {}", format, reason)
            }
            Self::ThreatIndicatorInvalid { indicator, reason } => {
                write!(f, "Invalid threat indicator '{}': {}", indicator, reason)
            }
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::PlatformNotSupported(platform) => {
                write!(f, "Platform not supported: {}", platform)
            }
            Self::ConfigurationError { component, message } => {
                write!(f, "Configuration error in {}: {}", component, message)
            }
            Self::SerializationFailed { type_name, reason } => {
                write!(f, "Failed to serialize {}: {}", type_name, reason)
            }
            Self::DeserializationFailed { type_name, reason } => {
                write!(f, "Failed to deserialize {}: {}", type_name, reason)
            }
            Self::KeyNotFound { key_id } => {
                write!(f, "Key not found: {}", key_id)
            }
            Self::DocumentNotFound { document_id } => {
                write!(f, "Document not found: {}", document_id)
            }
            Self::BiometricEnrollmentFailed { reason } => {
                write!(f, "Biometric enrollment failed: {}", reason)
            }
            Self::BiometricVerificationFailed { reason } => {
                write!(f, "Biometric verification failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for TerasError {}

impl From<std::io::Error> for TerasError {
    fn from(e: std::io::Error) -> Self {
        TerasError::IoError(e)
    }
}

/// Result type for all TERAS operations.
pub type TerasResult<T> = Result<T, TerasError>;
