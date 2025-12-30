//! Common types used across TERAS crates.
//!
//! This module defines shared types that don't belong to a specific crate.

/// Magic number for TERAS secret keys: "TERS" in ASCII
pub const SECRET_KEY_MAGIC: u32 = 0x54455253;

/// Magic number for encrypted keys: "ENCR" in ASCII
pub const ENCRYPTED_KEY_MAGIC: u32 = 0x454E4352;

/// Magic number for attestations: "ATST" in ASCII
pub const ATTESTATION_MAGIC: u32 = 0x41545354;

/// Magic number for network protocol: "TERP" in ASCII
pub const PROTOCOL_MAGIC: u32 = 0x54455250;

/// Magic number for audit log entries: "LOGE" in ASCII
pub const LOG_ENTRY_MAGIC: u32 = 0x4C4F4745;

/// Current version for all formats
pub const CURRENT_VERSION: u16 = 0x0001;
