//! Additional packet tests for comprehensive coverage.

use bytes::Bytes;
use teras_nadi::packet::*;
use teras_nadi::*;

#[test]
fn test_packet_type_all_values() {
    assert_eq!(PacketType::HandshakeInit as u8, 0x0);
    assert_eq!(PacketType::HandshakeResp as u8, 0x1);
    assert_eq!(PacketType::HandshakeDone as u8, 0x2);
    assert_eq!(PacketType::Data as u8, 0x3);
    assert_eq!(PacketType::Ack as u8, 0x4);
    assert_eq!(PacketType::Ping as u8, 0x5);
    assert_eq!(PacketType::Pong as u8, 0x6);
    assert_eq!(PacketType::ThreatAlert as u8, 0x7);
    assert_eq!(PacketType::PeerAnnounce as u8, 0x8);
    assert_eq!(PacketType::PeerQuery as u8, 0x9);
    assert_eq!(PacketType::ReputationUpdate as u8, 0xA);
    assert_eq!(PacketType::BloomSync as u8, 0xB);
    assert_eq!(PacketType::Close as u8, 0xC);
    assert_eq!(PacketType::Reset as u8, 0xD);
}

#[test]
fn test_packet_type_is_handshake() {
    assert!(PacketType::HandshakeInit.is_handshake());
    assert!(PacketType::HandshakeResp.is_handshake());
    assert!(PacketType::HandshakeDone.is_handshake());
    assert!(!PacketType::Data.is_handshake());
    assert!(!PacketType::ThreatAlert.is_handshake());
}

#[test]
fn test_flags_byte_operations() {
    let flags = PacketFlags::from_byte(0xFF);
    assert!(flags.is_encrypted());
    assert!(flags.is_compressed());
    assert!(flags.is_fragmented());
    assert!(flags.is_last_fragment());
    assert!(flags.is_onion());
    assert!(flags.is_priority());
    assert!(flags.is_reliable());
    assert_eq!(flags.as_byte(), 0xFF);
}

#[test]
fn test_header_all_fields() {
    let mut header = PacketHeader::new(PacketType::ThreatAlert);
    header.version = NADI_VERSION;
    header.sequence = 0xDEADBEEF;
    header.ack = 0xCAFEBABE;
    header.session_id = 0x123456789ABCDEF0;
    header.payload_length = 12345;
    header.priority = 255;
    header.flags = PacketFlags::new()
        .set(PacketFlags::ENCRYPTED)
        .set(PacketFlags::RELIABLE);
    header.header_mac = [1, 2, 3, 4, 5, 6, 7, 8];

    let serialized = header.serialize();
    let parsed = PacketHeader::parse(&serialized).unwrap();

    assert_eq!(parsed.version, NADI_VERSION);
    assert_eq!(parsed.packet_type, PacketType::ThreatAlert);
    assert_eq!(parsed.sequence, 0xDEADBEEF);
    assert_eq!(parsed.ack, 0xCAFEBABE);
    assert_eq!(parsed.session_id, 0x123456789ABCDEF0);
    assert_eq!(parsed.payload_length, 12345);
    assert_eq!(parsed.priority, 255);
    assert!(parsed.flags.is_encrypted());
    assert!(parsed.flags.is_reliable());
    assert!(!parsed.flags.is_compressed());
}

#[test]
fn test_priority_all_levels() {
    assert_eq!(Priority::from_raw(0), Priority::Background);
    assert_eq!(Priority::from_raw(15), Priority::Background);
    assert_eq!(Priority::from_raw(31), Priority::Background);
    assert_eq!(Priority::from_raw(32), Priority::Low);
    assert_eq!(Priority::from_raw(63), Priority::Low);
    assert_eq!(Priority::from_raw(64), Priority::BelowNormal);
    assert_eq!(Priority::from_raw(95), Priority::BelowNormal);
    assert_eq!(Priority::from_raw(96), Priority::Normal);
    assert_eq!(Priority::from_raw(127), Priority::Normal);
    assert_eq!(Priority::from_raw(128), Priority::AboveNormal);
    assert_eq!(Priority::from_raw(159), Priority::AboveNormal);
    assert_eq!(Priority::from_raw(160), Priority::High);
    assert_eq!(Priority::from_raw(191), Priority::High);
    assert_eq!(Priority::from_raw(192), Priority::VeryHigh);
    assert_eq!(Priority::from_raw(223), Priority::VeryHigh);
    assert_eq!(Priority::from_raw(224), Priority::Critical);
    assert_eq!(Priority::from_raw(255), Priority::Critical);
}

#[test]
fn test_packet_with_binary_payload() {
    let payload = Bytes::from(vec![0u8, 1, 2, 3, 255, 254, 253, 0, 0, 0]);
    let packet = Packet::new(PacketType::Data, payload.clone());

    let serialized = packet.serialize();
    let parsed = Packet::parse(&serialized).unwrap();

    assert_eq!(parsed.payload, payload);
}

#[test]
fn test_packet_header_mac_input_length() {
    let header = PacketHeader::new(PacketType::Data);
    let mac_input = header.mac_input();

    // MAC input should be header minus MAC field
    assert_eq!(mac_input.len(), HEADER_SIZE - 8);
}

#[test]
fn test_packet_error_messages() {
    let err = NadiError::PacketTooShort {
        expected: 100,
        actual: 50,
    };
    let msg = err.to_string();
    assert!(msg.contains("100"));
    assert!(msg.contains("50"));
}

#[test]
fn test_packet_type_default_priorities() {
    // Verify all packet types have sensible default priorities
    let types = [
        PacketType::ThreatAlert,
        PacketType::HandshakeInit,
        PacketType::Data,
        PacketType::Ping,
        PacketType::BloomSync,
    ];

    for pkt_type in types {
        let priority = pkt_type.default_priority();
        assert!(priority > 0 || pkt_type == PacketType::BloomSync || pkt_type == PacketType::Ping);
    }
}

#[test]
fn test_header_serialize_is_deterministic() {
    let header = PacketHeader::new(PacketType::Data);

    let s1 = header.serialize();
    let s2 = header.serialize();
    let s3 = header.serialize();

    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}

#[test]
fn test_packet_size_boundaries() {
    // Minimum size packet
    let min_packet = Packet::empty(PacketType::Ping);
    assert_eq!(min_packet.size(), MIN_PACKET_SIZE);

    // Near-maximum payload
    let near_max = Bytes::from(vec![0u8; MAX_PAYLOAD_SIZE - 1]);
    let near_max_packet = Packet::new(PacketType::Data, near_max);
    assert!(near_max_packet.validate_size().is_ok());
}

#[test]
fn test_flags_clear_operation() {
    let flags = PacketFlags::from_byte(0xFF);
    let cleared = flags.clear(PacketFlags::ENCRYPTED);

    assert!(!cleared.is_encrypted());
    assert!(cleared.is_compressed()); // Other flags unchanged
}

#[test]
fn test_packet_type_from_all_invalid() {
    for i in 0xE..=0xFF {
        assert!(PacketType::from_u8(i).is_err());
    }
}
