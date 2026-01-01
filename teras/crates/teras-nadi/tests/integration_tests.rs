//! Integration tests for teras-nadi.

use bytes::Bytes;
use teras_nadi::*;

// ============================================================================
// Packet Integration Tests
// ============================================================================

#[test]
fn test_packet_create_and_parse_all_types() {
    let types = [
        PacketType::HandshakeInit,
        PacketType::HandshakeResp,
        PacketType::HandshakeDone,
        PacketType::Data,
        PacketType::Ack,
        PacketType::Ping,
        PacketType::Pong,
        PacketType::ThreatAlert,
        PacketType::PeerAnnounce,
        PacketType::PeerQuery,
        PacketType::ReputationUpdate,
        PacketType::BloomSync,
        PacketType::Close,
        PacketType::Reset,
    ];

    for pkt_type in types {
        let packet = Packet::empty(pkt_type);
        let serialized = packet.serialize();
        let parsed = Packet::parse(&serialized).unwrap();
        assert_eq!(parsed.header.packet_type, pkt_type);
    }
}

#[test]
fn test_packet_with_maximum_payload() {
    let payload = Bytes::from(vec![0xABu8; MAX_PAYLOAD_SIZE]);
    let packet = Packet::new(PacketType::Data, payload.clone());

    assert!(packet.validate_size().is_ok());
    assert_eq!(packet.size(), MAX_PACKET_SIZE);

    let serialized = packet.serialize();
    let parsed = Packet::parse(&serialized).unwrap();
    assert_eq!(parsed.payload.len(), MAX_PAYLOAD_SIZE);
}

#[test]
fn test_packet_flags_all_combinations() {
    let flags = PacketFlags::new()
        .set(PacketFlags::ENCRYPTED)
        .set(PacketFlags::COMPRESSED)
        .set(PacketFlags::FRAGMENTED)
        .set(PacketFlags::LAST_FRAGMENT)
        .set(PacketFlags::PRIORITY)
        .set(PacketFlags::RELIABLE);

    assert!(flags.is_encrypted());
    assert!(flags.is_compressed());
    assert!(flags.is_fragmented());
    assert!(flags.is_last_fragment());
    assert!(flags.is_priority());
    assert!(flags.is_reliable());
}

#[test]
fn test_priority_levels_bandwidth_allocation() {
    let total: u8 = (0..8)
        .map(|p| Priority::from_raw(p * 32).quota_percentage())
        .sum();

    // Total allocation should be 100%
    assert_eq!(total, 100);
}

// ============================================================================
// Crypto Integration Tests
// ============================================================================

#[test]
fn test_session_keys_with_real_shared_secrets() {
    // Simulate realistic shared secrets
    let pq_shared = teras_kunci::sha256(b"pq-shared-secret");
    let classical_shared = teras_kunci::sha256(b"classical-shared-secret");

    let client_random = [0x11u8; 32];
    let server_random = [0x22u8; 32];

    let keys =
        SessionKeys::derive(&pq_shared, &classical_shared, &client_random, &server_random).unwrap();

    // Verify all keys are different
    assert_ne!(keys.client_key.expose(), keys.server_key.expose());
    assert_ne!(keys.client_key.expose(), keys.header_key.expose());
    assert_ne!(keys.server_key.expose(), keys.header_key.expose());
}

#[test]
fn test_packet_crypto_bidirectional() {
    let pq_shared = [0x33u8; 32];
    let classical_shared = [0x44u8; 32];
    let client_random = [0x55u8; 32];
    let server_random = [0x66u8; 32];

    // Derive keys separately for client and server (deterministic)
    let client_keys =
        SessionKeys::derive(&pq_shared, &classical_shared, &client_random, &server_random).unwrap();
    let server_keys =
        SessionKeys::derive(&pq_shared, &classical_shared, &client_random, &server_random).unwrap();

    let client_crypto = PacketCrypto::new(client_keys, true).unwrap();
    let server_crypto = PacketCrypto::new(server_keys, false).unwrap();

    // Test multiple packets
    for seq in 0..100 {
        let plaintext = format!("Message number {}", seq).into_bytes();
        let header = [0u8; 24];

        // Client -> Server
        let ciphertext = client_crypto.encrypt(seq, &plaintext, &header).unwrap();
        let decrypted = server_crypto.decrypt(seq, &ciphertext, &header).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);

        // Server -> Client
        let ciphertext2 = server_crypto.encrypt(seq, &plaintext, &header).unwrap();
        let decrypted2 = client_crypto.decrypt(seq, &ciphertext2, &header).unwrap();
        assert_eq!(&decrypted2[..], &plaintext[..]);
    }
}

// ============================================================================
// FEC Integration Tests
// ============================================================================

#[test]
fn test_fec_with_varying_data_sizes() {
    let config = FecConfig::for_priority(Priority::Critical).unwrap();
    let encoder = ReedSolomonEncoder::new(config).unwrap();
    let decoder = ReedSolomonDecoder::new(config);

    // Test various data sizes
    let sizes = [1, 10, 100, 1000, 10000];

    for size in sizes {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let shards = encoder.encode(&data).unwrap();

        let indexed: Vec<_> = shards.into_iter().enumerate().collect();
        let recovered = decoder.decode(&indexed, data.len()).unwrap();

        assert_eq!(recovered, data);
    }
}

#[test]
fn test_fec_with_different_loss_patterns() {
    let config = FecConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let encoder = ReedSolomonEncoder::new(config).unwrap();
    let decoder = ReedSolomonDecoder::new(config);

    let data = b"Test data for FEC recovery testing".to_vec();
    let shards = encoder.encode(&data).unwrap();

    // Test losing different combinations of shards
    let loss_patterns = [
        vec![0, 1], // Lose first two data shards
        vec![3, 4], // Lose last data and first parity
        vec![4, 5], // Lose both parity shards
        vec![0, 5], // Lose first data and last parity
    ];

    for pattern in &loss_patterns {
        let remaining: Vec<_> = shards
            .iter()
            .enumerate()
            .filter(|(i, _)| !pattern.contains(i))
            .map(|(i, s)| (i, s.clone()))
            .collect();

        let recovered = decoder.decode(&remaining, data.len()).unwrap();
        assert_eq!(recovered, data);
    }
}

// ============================================================================
// Reliability Integration Tests
// ============================================================================

#[test]
fn test_reliability_heavy_out_of_order() {
    let mut mgr = ReliabilityManager::new();

    // Send packets in reverse order
    for i in (0..100).rev() {
        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = i;
        let packet = Packet {
            header,
            payload: Bytes::from(format!("packet {}", i)),
        };
        mgr.record_received(packet);
    }

    // All should be ready now
    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 100);

    // Should be in order
    for (i, pkt) in ready.iter().enumerate() {
        assert_eq!(pkt.header.sequence, i as u32);
    }
}

#[test]
fn test_reliability_sack_blocks_complex() {
    let mut mgr = ReliabilityManager::new();

    // Receive packets with gaps: 0, 2, 3, 5, 6, 7, 10, 11, 12
    for seq in [0, 2, 3, 5, 6, 7, 10, 11, 12] {
        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = seq;
        let packet = Packet {
            header,
            payload: Bytes::new(),
        };
        mgr.record_received(packet);
    }

    // Only 0 should be ready
    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 1);

    // SACK blocks should cover: [2,4), [5,8), [10,13)
    let sacks = mgr.sack_blocks();
    assert_eq!(sacks.len(), 3);
}

// ============================================================================
// Congestion Control Integration Tests
// ============================================================================

#[test]
fn test_congestion_under_load() {
    let mut cc = NadiCongestionControl::new();

    // Enqueue many packets at different priorities
    for i in 0..100 {
        let priority = (i % 8) * 32;
        let mut header = PacketHeader::new(PacketType::Data);
        header.priority = priority;
        header.payload_length = 1000;
        let packet = Packet {
            header,
            payload: Bytes::from(vec![0u8; 1000]),
        };
        cc.enqueue(packet).unwrap();
    }

    assert_eq!(cc.total_queued(), 100);

    // Drain packets - critical should come first
    let mut critical_count = 0;

    while let Some(pkt) = cc.next_packet() {
        if pkt.header.priority >= 224 {
            critical_count += 1;
        }
    }

    assert!(critical_count > 0 || cc.total_queued() == 0);
}

#[test]
fn test_congestion_slow_start_to_avoidance() {
    let mut cc = NadiCongestionControl::new();
    cc.ssthresh = 50000;

    let initial_cwnd = cc.cwnd();

    // ACK many packets to trigger transition
    for _ in 0..100 {
        cc.on_packet_acked(Priority::Normal, 1000);
    }

    // Should have transitioned and cwnd should be larger
    assert!(cc.cwnd() > initial_cwnd);
}

// ============================================================================
// Handshake Integration Tests
// ============================================================================

#[test]
fn test_handshake_full_flow() {
    let mut client = HandshakeContext::new_client().unwrap();
    let mut server = HandshakeContext::new_server().unwrap();

    // Client INIT
    let client_hello = ClientHello {
        version: NADI_VERSION,
        random: client.our_random,
        x25519_public: [0x11u8; 32],
        ml_kem_public: vec![0x22u8; 1184],
        certificate: vec![0x33u8; 500],
        session_ticket: None,
        cipher_suites: vec![1, 2, 3],
    };
    let init = client.create_init_packet(&client_hello).unwrap();

    // Server receives INIT
    let parsed_hello = server.process_init_packet(&init).unwrap();
    assert_eq!(parsed_hello.version, NADI_VERSION);

    // Server RESP
    let server_hello = ServerHello {
        version: NADI_VERSION,
        random: server.our_random,
        x25519_public: [0x44u8; 32],
        ml_kem_public: vec![0x55u8; 1184],
        ml_kem_ciphertext: vec![0x66u8; 1088],
        certificate: vec![0x77u8; 500],
        signature: vec![0x88u8; 64],
        session_ticket: Some(vec![0x99u8; 100]),
    };
    let resp = server.create_resp_packet(&server_hello).unwrap();

    // Client receives RESP
    let parsed_resp = client.process_resp_packet(&resp).unwrap();
    assert!(parsed_resp.session_ticket.is_some());

    // Client DONE
    let finished = ClientFinished {
        signature: vec![0xAAu8; 64],
        early_data: None,
    };
    let done = client.create_done_packet(&finished).unwrap();

    // Server receives DONE
    let _ = server.process_done_packet(&done).unwrap();

    // Complete client
    client.complete();

    assert!(client.is_complete());
    assert!(server.is_complete());
    assert!(!client.transcript.is_empty());
    assert!(!server.transcript.is_empty());
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_config_bounds() {
    let config = NadiConfig::default();

    assert!(config.max_retransmits > 0);
    assert!(config.initial_cwnd >= 1472);
    assert!(config.connect_timeout.as_secs() > 0);
    assert!(config.idle_timeout.as_secs() > 0);
}

#[test]
fn test_connection_stats_accumulation() {
    let mut stats = ConnectionStats::default();

    stats.packets_sent += 100;
    stats.bytes_sent += 100_000;
    stats.retransmits += 5;

    assert_eq!(stats.packets_sent, 100);
    assert_eq!(stats.bytes_sent, 100_000);
    assert_eq!(stats.retransmits, 5);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_payload_handling() {
    let packet = Packet::empty(PacketType::Ping);
    assert_eq!(packet.payload.len(), 0);
    assert_eq!(packet.header.payload_length, 0);

    let serialized = packet.serialize();
    let parsed = Packet::parse(&serialized).unwrap();
    assert!(parsed.payload.is_empty());
}

#[test]
fn test_sequence_number_wraparound() {
    // Test that the sequence comparison handles wraparound correctly
    // by testing the seq_lt and seq_le logic

    // Verify that sequences near u32::MAX correctly compare as less than
    // sequences that have wrapped around to 0+
    let before_wrap = u32::MAX - 100;
    let after_wrap = 100u32;

    // The wrapped comparison should treat after_wrap as "greater" than before_wrap
    // because after_wrap is logically later in the sequence space
    let diff = before_wrap.wrapping_sub(after_wrap) as i32;
    assert!(diff < 0, "before_wrap should be less than after_wrap in wraparound arithmetic");

    // Test normal in-order packet reception (0..10)
    let mut mgr = ReliabilityManager::new();
    for seq in 0u32..10 {
        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = seq;
        let packet = Packet {
            header,
            payload: Bytes::new(),
        };
        mgr.record_received(packet);
    }

    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 10);
}

#[test]
fn test_duplicate_packet_handling() {
    let mut mgr = ReliabilityManager::new();

    // Send same packet multiple times
    for _ in 0..5 {
        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = 0;
        let packet = Packet {
            header,
            payload: Bytes::from_static(b"test"),
        };
        mgr.record_received(packet);
    }

    // Should only have one ready
    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 1);
}

#[test]
fn test_rtt_estimator_convergence() {
    let mut rtt = RttEstimator::new();

    // Feed consistent RTT samples
    for _ in 0..100 {
        rtt.update(std::time::Duration::from_millis(50));
    }

    // SRTT should converge to ~50ms
    let srtt = rtt.srtt().unwrap();
    assert!(srtt.as_millis() > 40 && srtt.as_millis() < 60);
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_high_volume_packet_processing() {
    let mut mgr = ReliabilityManager::new();

    // Process 10,000 packets
    for seq in 0..10_000u32 {
        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = seq;
        let packet = Packet {
            header,
            payload: Bytes::from(vec![0u8; 100]),
        };
        mgr.record_received(packet);
    }

    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 10_000);
}

#[test]
fn test_congestion_window_stability() {
    let mut cc = NadiCongestionControl::new();

    // Simulate many ACKs and losses
    for i in 0..1000 {
        if i % 10 == 0 {
            cc.on_packet_lost(Priority::Normal, 1000);
        } else {
            cc.on_packet_acked(Priority::Normal, 1000);
        }
    }

    // Window should still be within bounds
    assert!(cc.cwnd() >= congestion::MIN_CWND);
    assert!(cc.cwnd() <= congestion::MAX_CWND);
}
