//! Additional crypto tests for comprehensive coverage.

use teras_nadi::crypto::*;
use teras_nadi::packet::*;

#[test]
fn test_session_keys_derive_consistency() {
    let pq = [0x11u8; 32];
    let classical = [0x22u8; 32];
    let client_random = [0x33u8; 32];
    let server_random = [0x44u8; 32];

    let keys1 = SessionKeys::derive(&pq, &classical, &client_random, &server_random).unwrap();
    let keys2 = SessionKeys::derive(&pq, &classical, &client_random, &server_random).unwrap();

    assert_eq!(keys1.client_key.expose(), keys2.client_key.expose());
    assert_eq!(keys1.server_key.expose(), keys2.server_key.expose());
    assert_eq!(keys1.header_key.expose(), keys2.header_key.expose());
    assert_eq!(keys1.client_nonce, keys2.client_nonce);
    assert_eq!(keys1.server_nonce, keys2.server_nonce);
}

#[test]
fn test_session_keys_derive_different_inputs() {
    let pq1 = [0x11u8; 32];
    let pq2 = [0x12u8; 32];
    let classical = [0x22u8; 32];
    let client_random = [0x33u8; 32];
    let server_random = [0x44u8; 32];

    let keys1 = SessionKeys::derive(&pq1, &classical, &client_random, &server_random).unwrap();
    let keys2 = SessionKeys::derive(&pq2, &classical, &client_random, &server_random).unwrap();

    assert_ne!(keys1.client_key.expose(), keys2.client_key.expose());
}

#[test]
fn test_packet_crypto_large_payload() {
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

    let crypto = PacketCrypto::new(client_keys, true).unwrap();
    let server_crypto = PacketCrypto::new(server_keys, false).unwrap();

    // Test with large payload
    let plaintext = vec![0xABu8; 10000];
    let header = [0u8; 24];

    let ciphertext = crypto.encrypt(0, &plaintext, &header).unwrap();
    let decrypted = server_crypto.decrypt(0, &ciphertext, &header).unwrap();

    assert_eq!(&decrypted[..], &plaintext[..]);
}

#[test]
fn test_packet_crypto_empty_payload() {
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

    let plaintext = vec![];
    let header = [0u8; 24];

    let ciphertext = client_crypto.encrypt(0, &plaintext, &header).unwrap();
    let decrypted = server_crypto.decrypt(0, &ciphertext, &header).unwrap();

    assert!(decrypted.is_empty());
}

#[test]
fn test_packet_crypto_sequence_independence() {
    let keys = SessionKeys::derive(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .unwrap();

    let crypto = PacketCrypto::new(keys, true).unwrap();

    let plaintext = b"same message";
    let header = [0u8; 24];

    // Same plaintext with different sequences should produce different ciphertexts
    let ct1 = crypto.encrypt(1, plaintext, &header).unwrap();
    let ct2 = crypto.encrypt(2, plaintext, &header).unwrap();

    assert_ne!(&ct1[..], &ct2[..]);
}

#[test]
fn test_header_mac_tamper_detection() {
    let keys = SessionKeys::derive(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &[0x33u8; 32],
        &[0x44u8; 32],
    )
    .unwrap();

    let crypto = PacketCrypto::new(keys, true).unwrap();

    let mut header = PacketHeader::new(PacketType::Data);
    header.sequence = 100;
    header.session_id = 12345;

    crypto.sign_header(&mut header);
    assert!(crypto.verify_header_mac(&header));

    // Tamper with each field
    let mut tampered = header.clone();
    tampered.sequence = 101;
    assert!(!crypto.verify_header_mac(&tampered));

    let mut tampered = header.clone();
    tampered.session_id = 54321;
    assert!(!crypto.verify_header_mac(&tampered));

    let mut tampered = header.clone();
    tampered.priority = 255;
    assert!(!crypto.verify_header_mac(&tampered));
}

#[test]
fn test_handshake_crypto_random_generation() {
    let r1 = HandshakeCrypto::generate_random().unwrap();
    let r2 = HandshakeCrypto::generate_random().unwrap();
    let r3 = HandshakeCrypto::generate_random().unwrap();

    // All should be different
    assert_ne!(r1, r2);
    assert_ne!(r2, r3);
    assert_ne!(r1, r3);

    // None should be all zeros
    assert_ne!(r1, [0u8; 32]);
    assert_ne!(r2, [0u8; 32]);
    assert_ne!(r3, [0u8; 32]);
}

#[test]
fn test_transcript_hash_different_transcripts() {
    let t1 = b"client hello";
    let t2 = b"client hello server hello";

    let h1 = HandshakeCrypto::hash_transcript(t1);
    let h2 = HandshakeCrypto::hash_transcript(t2);

    assert_ne!(h1, h2);
    assert_eq!(h1.len(), 32);
    assert_eq!(h2.len(), 32);
}

#[test]
fn test_packet_crypto_client_server_asymmetry() {
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

    let plaintext = b"test message";
    let header = [0u8; 24];

    // Client encrypts, server decrypts
    let ct1 = client_crypto.encrypt(0, plaintext, &header).unwrap();
    let pt1 = server_crypto.decrypt(0, &ct1, &header).unwrap();
    assert_eq!(&pt1[..], plaintext);

    // Server encrypts, client decrypts
    let ct2 = server_crypto.encrypt(0, plaintext, &header).unwrap();
    let pt2 = client_crypto.decrypt(0, &ct2, &header).unwrap();
    assert_eq!(&pt2[..], plaintext);

    // Client can't decrypt its own ciphertext
    assert!(client_crypto.decrypt(0, &ct1, &header).is_err());
}
