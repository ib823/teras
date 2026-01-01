//! NADI throughput benchmarks.
//!
//! Run with: cargo bench --package teras-nadi

use bytes::Bytes;
use std::time::{Duration, Instant};
use teras_nadi::*;

/// Simple benchmark harness.
fn bench<F>(name: &str, iterations: u64, mut f: F)
where
    F: FnMut(),
{
    // Warmup
    for _ in 0..10 {
        f();
    }

    // Measure
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();

    let per_op = elapsed / iterations as u32;
    let ops_per_sec = if per_op > Duration::ZERO {
        1_000_000_000 / per_op.as_nanos() as u64
    } else {
        0
    };

    println!(
        "{}: {} iterations in {:?} ({:?}/op, {} ops/sec)",
        name, iterations, elapsed, per_op, ops_per_sec
    );
}

/// Benchmark packet serialization.
fn bench_packet_serialize() {
    let payload = Bytes::from(vec![0u8; 1000]);

    bench("packet_serialize_1KB", 100_000, || {
        let packet = Packet::new(PacketType::Data, payload.clone());
        let _ = packet.serialize();
    });
}

/// Benchmark packet parsing.
fn bench_packet_parse() {
    let payload = Bytes::from(vec![0u8; 1000]);
    let packet = Packet::new(PacketType::Data, payload);
    let serialized = packet.serialize();
    let data = serialized.freeze();

    bench("packet_parse_1KB", 100_000, || {
        let _ = Packet::parse(&data).unwrap();
    });
}

/// Benchmark header serialization.
fn bench_header_serialize() {
    let header = PacketHeader::new(PacketType::Data);

    bench("header_serialize", 1_000_000, || {
        let _ = header.serialize();
    });
}

/// Benchmark session key derivation.
fn bench_key_derivation() {
    let pq_shared = [0x11u8; 32];
    let classical_shared = [0x22u8; 32];
    let client_random = [0x33u8; 32];
    let server_random = [0x44u8; 32];

    bench("session_key_derivation", 10_000, || {
        let _ =
            SessionKeys::derive(&pq_shared, &classical_shared, &client_random, &server_random)
                .unwrap();
    });
}

/// Benchmark packet encryption (1KB).
fn bench_encrypt_1kb() {
    let keys = SessionKeys::derive(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .unwrap();
    let crypto = PacketCrypto::new(keys, true).unwrap();
    let plaintext = vec![0u8; 1024];
    let header = [0u8; 24];
    let mut seq = 0u32;

    bench("encrypt_1KB", 100_000, || {
        let _ = crypto.encrypt(seq, &plaintext, &header).unwrap();
        seq = seq.wrapping_add(1);
    });
}

/// Benchmark packet decryption (1KB).
fn bench_decrypt_1kb() {
    // Derive keys separately for client and server (deterministic)
    let client_keys = SessionKeys::derive(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .unwrap();
    let server_keys = SessionKeys::derive(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .unwrap();
    let client_crypto = PacketCrypto::new(client_keys, true).unwrap();
    let server_crypto = PacketCrypto::new(server_keys, false).unwrap();
    let plaintext = vec![0u8; 1024];
    let header = [0u8; 24];

    // Pre-encrypt
    let ciphertexts: Vec<_> = (0..100_000u32)
        .map(|seq| client_crypto.encrypt(seq, &plaintext, &header).unwrap())
        .collect();

    let mut idx = 0usize;
    bench("decrypt_1KB", 100_000, || {
        let _ = server_crypto
            .decrypt(idx as u32, &ciphertexts[idx], &header)
            .unwrap();
        idx = (idx + 1) % ciphertexts.len();
    });
}

/// Benchmark FEC encode (4+2).
fn bench_fec_encode() {
    let config = FecConfig {
        data_shards: 4,
        parity_shards: 2,
    };
    let encoder = ReedSolomonEncoder::new(config).unwrap();
    let data = vec![0u8; 4000];

    bench("fec_encode_4+2_4KB", 10_000, || {
        let _ = encoder.encode(&data).unwrap();
    });
}

/// Benchmark FEC decode (no loss).
fn bench_fec_decode_no_loss() {
    let config = FecConfig {
        data_shards: 4,
        parity_shards: 2,
    };
    let encoder = ReedSolomonEncoder::new(config).unwrap();
    let decoder = ReedSolomonDecoder::new(config);
    let data = vec![0u8; 4000];
    let shards = encoder.encode(&data).unwrap();
    let indexed: Vec<_> = shards.into_iter().enumerate().collect();

    bench("fec_decode_no_loss_4KB", 10_000, || {
        let _ = decoder.decode(&indexed, data.len()).unwrap();
    });
}

/// Benchmark reliability manager receive.
fn bench_reliability_receive() {
    bench("reliability_receive_10K", 100, || {
        let mut mgr = ReliabilityManager::new();
        for seq in 0..10_000u32 {
            let mut header = PacketHeader::new(PacketType::Data);
            header.sequence = seq;
            let packet = Packet {
                header,
                payload: Bytes::from(vec![0u8; 100]),
            };
            mgr.record_received(packet);
        }
        let _ = mgr.get_ready_packets();
    });
}

/// Benchmark congestion control enqueue/dequeue.
fn bench_congestion_enqueue() {
    bench("congestion_enqueue_1K", 1_000, || {
        let mut cc = NadiCongestionControl::new();
        for i in 0..1000u32 {
            let mut header = PacketHeader::new(PacketType::Data);
            header.priority = ((i % 8) * 32) as u8;
            header.payload_length = 1000;
            let packet = Packet {
                header,
                payload: Bytes::from(vec![0u8; 1000]),
            };
            cc.enqueue(packet).unwrap();
        }
        while cc.next_packet().is_some() {}
    });
}

/// Benchmark header MAC computation.
fn bench_header_mac() {
    let keys = SessionKeys::derive(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .unwrap();
    let crypto = PacketCrypto::new(keys, true).unwrap();
    let mut header = PacketHeader::new(PacketType::Data);
    header.sequence = 12345;
    header.session_id = 0xDEADBEEF;

    bench("header_mac_compute", 100_000, || {
        crypto.sign_header(&mut header);
    });
}

/// Benchmark header MAC verification.
fn bench_header_mac_verify() {
    let keys = SessionKeys::derive(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .unwrap();
    let crypto = PacketCrypto::new(keys, true).unwrap();
    let mut header = PacketHeader::new(PacketType::Data);
    header.sequence = 12345;
    crypto.sign_header(&mut header);

    bench("header_mac_verify", 100_000, || {
        let _ = crypto.verify_header_mac(&header);
    });
}

/// Benchmark handshake message serialization.
fn bench_handshake_serialize() {
    let client_hello = ClientHello {
        version: NADI_VERSION,
        random: [0x42u8; 32],
        x25519_public: [0x11u8; 32],
        ml_kem_public: vec![0x22u8; 1184],
        certificate: vec![0x33u8; 500],
        session_ticket: None,
        cipher_suites: vec![1, 2, 3],
    };

    bench("client_hello_serialize", 100_000, || {
        let _ = client_hello.serialize();
    });
}

/// Benchmark RTT estimator update.
fn bench_rtt_update() {
    let mut rtt = RttEstimator::new();

    bench("rtt_update", 1_000_000, || {
        rtt.update(Duration::from_millis(50));
    });
}

/// Benchmark priority from raw.
fn bench_priority_from_raw() {
    bench("priority_from_raw", 10_000_000, || {
        for p in 0..=255u8 {
            let _ = Priority::from_raw(p);
        }
    });
}

fn main() {
    println!("=== NADI Protocol Benchmarks ===\n");

    println!("--- Packet Operations ---");
    bench_packet_serialize();
    bench_packet_parse();
    bench_header_serialize();

    println!("\n--- Cryptographic Operations ---");
    bench_key_derivation();
    bench_encrypt_1kb();
    bench_decrypt_1kb();
    bench_header_mac();
    bench_header_mac_verify();

    println!("\n--- FEC Operations ---");
    bench_fec_encode();
    bench_fec_decode_no_loss();

    println!("\n--- Reliability & Congestion ---");
    bench_reliability_receive();
    bench_congestion_enqueue();
    bench_rtt_update();

    println!("\n--- Handshake ---");
    bench_handshake_serialize();

    println!("\n--- Miscellaneous ---");
    bench_priority_from_raw();

    println!("\n=== Benchmarks Complete ===");
}
