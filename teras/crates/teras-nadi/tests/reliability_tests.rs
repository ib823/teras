//! Additional reliability tests for comprehensive coverage.

use bytes::Bytes;
use teras_nadi::packet::*;
use teras_nadi::reliability::*;

fn make_packet(seq: u32) -> Packet {
    let mut header = PacketHeader::new(PacketType::Data);
    header.sequence = seq;
    Packet {
        header,
        payload: Bytes::from(format!("data for {}", seq)),
    }
}

#[test]
fn test_sack_block_basic_operations() {
    let block = SackBlock::new(10, 20);

    assert!(block.contains(10));
    assert!(block.contains(15));
    assert!(block.contains(19));
    assert!(!block.contains(9));
    assert!(!block.contains(20));
    assert!(!block.contains(21));
}

#[test]
fn test_sack_block_empty() {
    let block = SackBlock::new(10, 10);
    assert!(block.is_empty());
    assert_eq!(block.len(), 0);
}

#[test]
fn test_rtt_estimator_initial_sample() {
    let mut rtt = RttEstimator::new();
    assert!(rtt.srtt().is_none());

    rtt.update(std::time::Duration::from_millis(100));

    assert!(rtt.srtt().is_some());
    assert!(rtt.rto() > std::time::Duration::ZERO);
}

#[test]
fn test_rtt_estimator_rto_bounds() {
    let mut rtt = RttEstimator::new();

    // Very high RTT
    rtt.update(std::time::Duration::from_secs(100));
    assert!(rtt.rto() <= MAX_RTO);

    // Very low RTT
    let mut rtt2 = RttEstimator::new();
    rtt2.update(std::time::Duration::from_nanos(1));
    assert!(rtt2.rto() >= MIN_RTO);
}

#[test]
fn test_reliability_manager_initial_state() {
    let mgr = ReliabilityManager::new();

    assert_eq!(mgr.cumulative_ack(), 0);
    assert_eq!(mgr.in_flight(), 0);
    assert!(mgr.sack_blocks().is_empty());
}

#[test]
fn test_reliability_manager_sequence_allocation() {
    let mut mgr = ReliabilityManager::new();

    assert_eq!(mgr.next_sequence(), 0);
    assert_eq!(mgr.next_sequence(), 1);
    assert_eq!(mgr.next_sequence(), 2);
}

#[test]
fn test_reliability_manager_record_sent() {
    let mut mgr = ReliabilityManager::new();

    for i in 0..10 {
        let mut pkt = make_packet(i);
        pkt.header.sequence = mgr.next_sequence();
        mgr.record_sent(pkt).unwrap();
    }

    assert_eq!(mgr.in_flight(), 10);
}

#[test]
fn test_reliability_manager_ack_cumulative() {
    let mut mgr = ReliabilityManager::new();

    for i in 0..10 {
        let mut pkt = make_packet(i);
        pkt.header.sequence = mgr.next_sequence();
        mgr.record_sent(pkt).unwrap();
    }

    // ACK up to sequence 5
    mgr.process_ack(5, &[]);

    // Sequences 0-5 should be removed
    assert_eq!(mgr.in_flight(), 4); // 6,7,8,9 remain
}

#[test]
fn test_reliability_manager_ack_with_sack() {
    let mut mgr = ReliabilityManager::new();

    for i in 0..10 {
        let mut pkt = make_packet(i);
        pkt.header.sequence = mgr.next_sequence();
        mgr.record_sent(pkt).unwrap();
    }

    // ACK 2, SACK 5-7
    mgr.process_ack(2, &[SackBlock::new(5, 7)]);

    // 0,1,2 removed by cumulative ACK
    // 5,6 removed by SACK
    assert_eq!(mgr.in_flight(), 5); // 3,4,7,8,9 remain
}

#[test]
fn test_reliability_manager_receive_in_order() {
    let mut mgr = ReliabilityManager::new();

    for i in 0..5 {
        mgr.record_received(make_packet(i));
    }

    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 5);

    for (i, pkt) in ready.iter().enumerate() {
        assert_eq!(pkt.header.sequence, i as u32);
    }

    assert_eq!(mgr.cumulative_ack(), 5);
}

#[test]
fn test_reliability_manager_receive_gap() {
    let mut mgr = ReliabilityManager::new();

    // Receive 0, then skip 1, receive 2,3,4
    mgr.record_received(make_packet(0));
    mgr.record_received(make_packet(2));
    mgr.record_received(make_packet(3));
    mgr.record_received(make_packet(4));

    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 1); // Only 0 is ready
    assert_eq!(mgr.cumulative_ack(), 1);

    // Now receive 1
    mgr.record_received(make_packet(1));
    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 4); // 1,2,3,4 now ready
}

#[test]
fn test_sack_serialization_roundtrip() {
    let blocks = vec![
        SackBlock::new(100, 200),
        SackBlock::new(300, 400),
        SackBlock::new(500, 600),
    ];

    let serialized = serialize_sack_blocks(&blocks);
    let deserialized = deserialize_sack_blocks(&serialized).unwrap();

    assert_eq!(deserialized.len(), 3);
    assert_eq!(deserialized[0], blocks[0]);
    assert_eq!(deserialized[1], blocks[1]);
    assert_eq!(deserialized[2], blocks[2]);
}

#[test]
fn test_sack_serialization_empty() {
    let blocks = vec![];
    let serialized = serialize_sack_blocks(&blocks);
    let deserialized = deserialize_sack_blocks(&serialized).unwrap();
    assert!(deserialized.is_empty());
}

#[test]
fn test_sent_packet_retransmit_timing() {
    let pkt = make_packet(0);
    let sent = SentPacket::new(pkt);

    assert_eq!(sent.send_count, 1);
    assert!(!sent.exceeded_retransmit_limit());

    // Initial RTO should be INITIAL_RTO
    let rto = sent.next_rto();
    assert!(rto >= MIN_RTO);
    assert!(rto <= MAX_RTO);
}

#[test]
fn test_sent_packet_backoff() {
    let pkt = make_packet(0);
    let mut sent = SentPacket::new(pkt);

    let rto1 = sent.next_rto();
    sent.send_count = 2;
    let rto2 = sent.next_rto();
    sent.send_count = 3;
    let rto3 = sent.next_rto();

    // RTO should increase (exponential backoff)
    assert!(rto2 >= rto1);
    assert!(rto3 >= rto2);
}

#[test]
fn test_reliability_manager_duplicate_rejection() {
    let mut mgr = ReliabilityManager::new();

    // Receive same packet multiple times
    for _ in 0..10 {
        mgr.record_received(make_packet(0));
    }

    let ready = mgr.get_ready_packets();
    assert_eq!(ready.len(), 1);
}

#[test]
fn test_reliability_manager_old_packet_rejection() {
    let mut mgr = ReliabilityManager::new();

    // Receive 0,1,2
    for i in 0..3 {
        mgr.record_received(make_packet(i));
    }
    let _ = mgr.get_ready_packets();

    // Try to receive 0 again
    mgr.record_received(make_packet(0));
    let ready = mgr.get_ready_packets();
    assert!(ready.is_empty());
}
