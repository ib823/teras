//! NADI packet structure and parsing.
//!
//! NADI packets have a fixed 32-byte header followed by variable-length payload.
//!
//! # Header Format (32 bytes)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ Byte 0:  Version (4 bits) | Type (4 bits)                       │
//! │ Byte 1:  Flags (8 bits)                                         │
//! │ Bytes 2-5:  Sequence number (32 bits, big-endian)               │
//! │ Bytes 6-9:  Acknowledgment number (32 bits, big-endian)         │
//! │ Bytes 10-17: Session ID (64 bits, big-endian)                   │
//! │ Bytes 18-19: Payload length (16 bits, big-endian)               │
//! │ Byte 20: Priority (8 bits, 0-255)                               │
//! │ Bytes 21-23: Reserved (24 bits)                                 │
//! │ Bytes 24-31: Header MAC (64 bits, truncated HMAC)               │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{NadiError, NadiResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// NADI protocol version.
pub const NADI_VERSION: u8 = 1;

/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 32;

/// Maximum payload size (65535 - header).
pub const MAX_PAYLOAD_SIZE: usize = 65503;

/// Maximum packet size.
pub const MAX_PACKET_SIZE: usize = HEADER_SIZE + MAX_PAYLOAD_SIZE;

/// Minimum packet size (header only).
pub const MIN_PACKET_SIZE: usize = HEADER_SIZE;

/// Header MAC size in bytes.
pub const HEADER_MAC_SIZE: usize = 8;

/// NADI packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    /// Initiate handshake (client -> server).
    HandshakeInit = 0x0,
    /// Respond to handshake (server -> client).
    HandshakeResp = 0x1,
    /// Complete handshake (client -> server).
    HandshakeDone = 0x2,
    /// Regular data packet.
    Data = 0x3,
    /// Acknowledgment.
    Ack = 0x4,
    /// Keepalive ping.
    Ping = 0x5,
    /// Keepalive pong.
    Pong = 0x6,
    /// High-priority threat alert (bypasses congestion control).
    ThreatAlert = 0x7,
    /// Announce peer presence.
    PeerAnnounce = 0x8,
    /// Query for peers.
    PeerQuery = 0x9,
    /// Update peer reputation.
    ReputationUpdate = 0xA,
    /// IOC bloom filter sync.
    BloomSync = 0xB,
    /// Close connection gracefully.
    Close = 0xC,
    /// Reset connection.
    Reset = 0xD,
}

impl PacketType {
    /// Parse packet type from byte.
    pub fn from_u8(value: u8) -> NadiResult<Self> {
        match value {
            0x0 => Ok(Self::HandshakeInit),
            0x1 => Ok(Self::HandshakeResp),
            0x2 => Ok(Self::HandshakeDone),
            0x3 => Ok(Self::Data),
            0x4 => Ok(Self::Ack),
            0x5 => Ok(Self::Ping),
            0x6 => Ok(Self::Pong),
            0x7 => Ok(Self::ThreatAlert),
            0x8 => Ok(Self::PeerAnnounce),
            0x9 => Ok(Self::PeerQuery),
            0xA => Ok(Self::ReputationUpdate),
            0xB => Ok(Self::BloomSync),
            0xC => Ok(Self::Close),
            0xD => Ok(Self::Reset),
            _ => Err(NadiError::InvalidPacketType(value)),
        }
    }

    /// Check if this packet type requires reliability (ACK).
    #[must_use]
    pub fn requires_reliability(self) -> bool {
        matches!(
            self,
            Self::Data
                | Self::ThreatAlert
                | Self::BloomSync
                | Self::HandshakeInit
                | Self::HandshakeResp
                | Self::HandshakeDone
        )
    }

    /// Check if this is a handshake packet.
    #[must_use]
    pub fn is_handshake(self) -> bool {
        matches!(
            self,
            Self::HandshakeInit | Self::HandshakeResp | Self::HandshakeDone
        )
    }

    /// Get default priority for this packet type.
    #[must_use]
    pub fn default_priority(self) -> u8 {
        match self {
            Self::ThreatAlert => 255,          // Critical - highest
            Self::HandshakeInit => 200,        // High
            Self::HandshakeResp => 200,        // High
            Self::HandshakeDone => 200,        // High
            Self::Reset => 180,                // Above normal
            Self::Close => 150,                // Above normal
            Self::Ack => 128,                  // Normal
            Self::Ping => 100,                 // Below normal
            Self::Pong => 100,                 // Below normal
            Self::Data => 64,                  // Default for data
            Self::BloomSync => 32,             // Background
            Self::PeerAnnounce => 16,          // Low
            Self::PeerQuery => 16,             // Low
            Self::ReputationUpdate => 16,      // Low
        }
    }
}

/// NADI packet flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketFlags(u8);

impl PacketFlags {
    /// Payload is encrypted.
    pub const ENCRYPTED: u8 = 0x01;
    /// Payload is compressed (zstd).
    pub const COMPRESSED: u8 = 0x02;
    /// This is a fragment of larger message.
    pub const FRAGMENTED: u8 = 0x04;
    /// This is the last fragment.
    pub const LAST_FRAGMENT: u8 = 0x08;
    /// Packet is onion-routed.
    pub const ONION: u8 = 0x10;
    /// High-priority, skip queue.
    pub const PRIORITY: u8 = 0x20;
    /// Requires acknowledgment.
    pub const RELIABLE: u8 = 0x40;

    /// Create new flags.
    #[must_use]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Create flags from raw byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        Self(byte)
    }

    /// Get raw byte value.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Check if flag is set.
    #[must_use]
    pub const fn has(self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    /// Set a flag.
    #[must_use]
    pub const fn set(self, flag: u8) -> Self {
        Self(self.0 | flag)
    }

    /// Clear a flag.
    #[must_use]
    pub const fn clear(self, flag: u8) -> Self {
        Self(self.0 & !flag)
    }

    /// Check if encrypted.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        self.has(Self::ENCRYPTED)
    }

    /// Check if compressed.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.has(Self::COMPRESSED)
    }

    /// Check if fragmented.
    #[must_use]
    pub const fn is_fragmented(self) -> bool {
        self.has(Self::FRAGMENTED)
    }

    /// Check if last fragment.
    #[must_use]
    pub const fn is_last_fragment(self) -> bool {
        self.has(Self::LAST_FRAGMENT)
    }

    /// Check if onion-routed.
    #[must_use]
    pub const fn is_onion(self) -> bool {
        self.has(Self::ONION)
    }

    /// Check if high-priority.
    #[must_use]
    pub const fn is_priority(self) -> bool {
        self.has(Self::PRIORITY)
    }

    /// Check if reliable.
    #[must_use]
    pub const fn is_reliable(self) -> bool {
        self.has(Self::RELIABLE)
    }
}

/// NADI packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Protocol version (4 bits, current = 1).
    pub version: u8,
    /// Packet type.
    pub packet_type: PacketType,
    /// Control flags.
    pub flags: PacketFlags,
    /// Packet sequence number.
    pub sequence: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// Encrypted session identifier.
    pub session_id: u64,
    /// Payload length.
    pub payload_length: u16,
    /// Message priority (0 = low, 255 = critical).
    pub priority: u8,
    /// Header MAC (truncated HMAC-SHA256).
    pub header_mac: [u8; HEADER_MAC_SIZE],
}

impl PacketHeader {
    /// Create a new header with default values.
    #[must_use]
    pub fn new(packet_type: PacketType) -> Self {
        Self {
            version: NADI_VERSION,
            packet_type,
            flags: PacketFlags::new(),
            sequence: 0,
            ack: 0,
            session_id: 0,
            payload_length: 0,
            priority: packet_type.default_priority(),
            header_mac: [0u8; HEADER_MAC_SIZE],
        }
    }

    /// Parse header from bytes.
    pub fn parse(data: &[u8]) -> NadiResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(NadiError::PacketTooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut buf = &data[..HEADER_SIZE];

        // Byte 0: version (high 4 bits) | type (low 4 bits)
        let version_type = buf.get_u8();
        let version = (version_type >> 4) & 0x0F;
        let pkt_type = version_type & 0x0F;

        if version != NADI_VERSION {
            return Err(NadiError::UnsupportedVersion(version));
        }

        let packet_type = PacketType::from_u8(pkt_type)?;

        // Byte 1: flags
        let flags = PacketFlags::from_byte(buf.get_u8());

        // Bytes 2-5: sequence
        let sequence = buf.get_u32();

        // Bytes 6-9: ack
        let ack = buf.get_u32();

        // Bytes 10-17: session_id
        let session_id = buf.get_u64();

        // Bytes 18-19: payload_length
        let payload_length = buf.get_u16();

        // Byte 20: priority
        let priority = buf.get_u8();

        // Bytes 21-23: reserved (skip)
        buf.advance(3);

        // Bytes 24-31: header_mac
        let mut header_mac = [0u8; HEADER_MAC_SIZE];
        header_mac.copy_from_slice(&buf[..HEADER_MAC_SIZE]);

        Ok(Self {
            version,
            packet_type,
            flags,
            sequence,
            ack,
            session_id,
            payload_length,
            priority,
            header_mac,
        })
    }

    /// Serialize header to bytes.
    #[must_use]
    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        let mut writer = &mut buf[..];

        // Byte 0: version (high 4 bits) | type (low 4 bits)
        writer.put_u8((self.version << 4) | (self.packet_type as u8 & 0x0F));

        // Byte 1: flags
        writer.put_u8(self.flags.as_byte());

        // Bytes 2-5: sequence
        writer.put_u32(self.sequence);

        // Bytes 6-9: ack
        writer.put_u32(self.ack);

        // Bytes 10-17: session_id
        writer.put_u64(self.session_id);

        // Bytes 18-19: payload_length
        writer.put_u16(self.payload_length);

        // Byte 20: priority
        writer.put_u8(self.priority);

        // Bytes 21-23: reserved
        writer.put_u8(0);
        writer.put_u8(0);
        writer.put_u8(0);

        // Bytes 24-31: header_mac
        writer.put_slice(&self.header_mac);

        buf
    }

    /// Get bytes for MAC calculation (header without MAC field).
    #[must_use]
    pub fn mac_input(&self) -> [u8; HEADER_SIZE - HEADER_MAC_SIZE] {
        let full = self.serialize();
        let mut result = [0u8; HEADER_SIZE - HEADER_MAC_SIZE];
        result.copy_from_slice(&full[..HEADER_SIZE - HEADER_MAC_SIZE]);
        result
    }
}

/// Complete NADI packet (header + payload).
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet header.
    pub header: PacketHeader,
    /// Packet payload (may be encrypted).
    pub payload: Bytes,
}

impl Packet {
    /// Create a new packet.
    #[must_use]
    pub fn new(packet_type: PacketType, payload: Bytes) -> Self {
        let mut header = PacketHeader::new(packet_type);
        header.payload_length = payload.len().min(u16::MAX as usize) as u16;
        Self { header, payload }
    }

    /// Create an empty packet of given type.
    #[must_use]
    pub fn empty(packet_type: PacketType) -> Self {
        Self::new(packet_type, Bytes::new())
    }

    /// Parse packet from bytes.
    pub fn parse(data: &[u8]) -> NadiResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(NadiError::PacketTooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let header = PacketHeader::parse(data)?;
        let payload_start = HEADER_SIZE;
        let payload_end = payload_start + header.payload_length as usize;

        if data.len() < payload_end {
            return Err(NadiError::PacketTooShort {
                expected: payload_end,
                actual: data.len(),
            });
        }

        let payload = Bytes::copy_from_slice(&data[payload_start..payload_end]);

        Ok(Self { header, payload })
    }

    /// Serialize packet to bytes.
    #[must_use]
    pub fn serialize(&self) -> BytesMut {
        let header_bytes = self.header.serialize();
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.put_slice(&header_bytes);
        buf.put_slice(&self.payload);
        buf
    }

    /// Total packet size.
    #[must_use]
    pub fn size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Check if packet is within size limits.
    pub fn validate_size(&self) -> NadiResult<()> {
        if self.size() > MAX_PACKET_SIZE {
            return Err(NadiError::PacketTooLarge {
                max: MAX_PACKET_SIZE,
                actual: self.size(),
            });
        }
        Ok(())
    }
}

/// Priority level for NADI-CC (8 levels as specified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Priority {
    /// Lowest priority - background sync.
    Background = 0,
    /// Low priority.
    Low = 1,
    /// Below normal.
    BelowNormal = 2,
    /// Normal priority.
    Normal = 3,
    /// Above normal.
    AboveNormal = 4,
    /// High priority.
    High = 5,
    /// Very high priority.
    VeryHigh = 6,
    /// Critical - threat alerts.
    Critical = 7,
}

impl Priority {
    /// Map raw priority byte to level (0-255 -> 0-7).
    #[must_use]
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0..=31 => Self::Background,
            32..=63 => Self::Low,
            64..=95 => Self::BelowNormal,
            96..=127 => Self::Normal,
            128..=159 => Self::AboveNormal,
            160..=191 => Self::High,
            192..=223 => Self::VeryHigh,
            224..=255 => Self::Critical,
        }
    }

    /// Get bandwidth quota percentage for this priority.
    /// As per spec:
    /// - Critical (7): 40%
    /// - VeryHigh (6): 25%
    /// - High (5): 15%
    /// - Others (0-4): Share 20%
    #[must_use]
    pub fn quota_percentage(self) -> u8 {
        match self {
            Self::Critical => 40,
            Self::VeryHigh => 25,
            Self::High => 15,
            Self::AboveNormal => 5,
            Self::Normal => 5,
            Self::BelowNormal => 4,
            Self::Low => 3,
            Self::Background => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_roundtrip() {
        for i in 0..=0xD {
            let pt = PacketType::from_u8(i).unwrap();
            assert_eq!(pt as u8, i);
        }
    }

    #[test]
    fn test_packet_type_invalid() {
        assert!(PacketType::from_u8(0xE).is_err());
        assert!(PacketType::from_u8(0xF).is_err());
        assert!(PacketType::from_u8(0xFF).is_err());
    }

    #[test]
    fn test_packet_flags() {
        let flags = PacketFlags::new()
            .set(PacketFlags::ENCRYPTED)
            .set(PacketFlags::RELIABLE);

        assert!(flags.is_encrypted());
        assert!(flags.is_reliable());
        assert!(!flags.is_compressed());

        let cleared = flags.clear(PacketFlags::ENCRYPTED);
        assert!(!cleared.is_encrypted());
        assert!(cleared.is_reliable());
    }

    #[test]
    fn test_header_serialize_parse_roundtrip() {
        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = 0x12345678;
        header.ack = 0xDEADBEEF;
        header.session_id = 0x0102030405060708;
        header.payload_length = 1234;
        header.priority = 128;
        header.flags = PacketFlags::new()
            .set(PacketFlags::ENCRYPTED)
            .set(PacketFlags::RELIABLE);
        header.header_mac = [1, 2, 3, 4, 5, 6, 7, 8];

        let serialized = header.serialize();
        assert_eq!(serialized.len(), HEADER_SIZE);

        let parsed = PacketHeader::parse(&serialized).unwrap();
        assert_eq!(parsed.version, NADI_VERSION);
        assert_eq!(parsed.packet_type, PacketType::Data);
        assert_eq!(parsed.sequence, 0x12345678);
        assert_eq!(parsed.ack, 0xDEADBEEF);
        assert_eq!(parsed.session_id, 0x0102030405060708);
        assert_eq!(parsed.payload_length, 1234);
        assert_eq!(parsed.priority, 128);
        assert!(parsed.flags.is_encrypted());
        assert!(parsed.flags.is_reliable());
        assert_eq!(parsed.header_mac, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_packet_serialize_parse_roundtrip() {
        let payload = Bytes::from_static(b"Hello, NADI!");
        let mut packet = Packet::new(PacketType::ThreatAlert, payload.clone());
        packet.header.sequence = 42;
        packet.header.session_id = 0x1234;

        let serialized = packet.serialize();
        let parsed = Packet::parse(&serialized).unwrap();

        assert_eq!(parsed.header.packet_type, PacketType::ThreatAlert);
        assert_eq!(parsed.header.sequence, 42);
        assert_eq!(parsed.header.session_id, 0x1234);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_packet_too_short() {
        let short_data = [0u8; 16];
        let result = Packet::parse(&short_data);
        assert!(matches!(result, Err(NadiError::PacketTooShort { .. })));
    }

    #[test]
    fn test_packet_invalid_version() {
        let mut data = [0u8; HEADER_SIZE];
        data[0] = 0xF3; // Version 15, Type 3 (Data)

        let result = PacketHeader::parse(&data);
        assert!(matches!(result, Err(NadiError::UnsupportedVersion(15))));
    }

    #[test]
    fn test_priority_from_raw() {
        assert_eq!(Priority::from_raw(0), Priority::Background);
        assert_eq!(Priority::from_raw(31), Priority::Background);
        assert_eq!(Priority::from_raw(32), Priority::Low);
        assert_eq!(Priority::from_raw(96), Priority::Normal);
        assert_eq!(Priority::from_raw(224), Priority::Critical);
        assert_eq!(Priority::from_raw(255), Priority::Critical);
    }

    #[test]
    fn test_priority_quota() {
        assert_eq!(Priority::Critical.quota_percentage(), 40);
        assert_eq!(Priority::VeryHigh.quota_percentage(), 25);
        assert_eq!(Priority::High.quota_percentage(), 15);
    }

    #[test]
    fn test_packet_type_default_priority() {
        assert_eq!(PacketType::ThreatAlert.default_priority(), 255);
        assert_eq!(PacketType::Data.default_priority(), 64);
        assert_eq!(PacketType::BloomSync.default_priority(), 32);
    }

    #[test]
    fn test_packet_type_requires_reliability() {
        assert!(PacketType::Data.requires_reliability());
        assert!(PacketType::ThreatAlert.requires_reliability());
        assert!(!PacketType::Ping.requires_reliability());
        assert!(!PacketType::Pong.requires_reliability());
    }

    #[test]
    fn test_header_mac_input() {
        let header = PacketHeader::new(PacketType::Data);
        let mac_input = header.mac_input();
        assert_eq!(mac_input.len(), HEADER_SIZE - HEADER_MAC_SIZE);
    }

    #[test]
    fn test_packet_size_validation() {
        let small_payload = Bytes::from(vec![0u8; 100]);
        let packet = Packet::new(PacketType::Data, small_payload);
        assert!(packet.validate_size().is_ok());
    }

    #[test]
    fn test_empty_packet() {
        let packet = Packet::empty(PacketType::Ping);
        assert_eq!(packet.header.payload_length, 0);
        assert!(packet.payload.is_empty());
        assert_eq!(packet.size(), HEADER_SIZE);
    }
}
