//! Additional congestion control tests.

use bytes::Bytes;
use teras_nadi::congestion::*;
use teras_nadi::packet::*;

fn make_packet(priority: u8) -> Packet {
    let mut header = PacketHeader::new(PacketType::Data);
    header.priority = priority;
    header.payload_length = 1000;
    Packet {
        header,
        payload: Bytes::from(vec![0u8; 1000]),
    }
}

#[test]
fn test_congestion_initial_slow_start() {
    let cc = NadiCongestionControl::new();

    assert_eq!(cc.state(), CongestionState::SlowStart);
    assert_eq!(cc.cwnd(), INITIAL_CWND);
    assert_eq!(cc.ssthresh(), INITIAL_SSTHRESH);
}

#[test]
fn test_congestion_window_bounds() {
    let mut cc = NadiCongestionControl::new();

    // Try to grow beyond max
    for _ in 0..10000 {
        cc.on_packet_acked(Priority::Normal, 10000);
    }
    assert!(cc.cwnd() <= MAX_CWND);

    // Reset and try to shrink below min
    cc.reset();
    for _ in 0..1000 {
        cc.on_packet_lost(Priority::Normal, 10000);
    }
    assert!(cc.cwnd() >= MIN_CWND);
}

#[test]
fn test_congestion_priority_ordering() {
    let mut cc = NadiCongestionControl::new();

    // Add packets in reverse priority order
    cc.enqueue(make_packet(0)).unwrap();   // Background
    cc.enqueue(make_packet(64)).unwrap();  // BelowNormal
    cc.enqueue(make_packet(128)).unwrap(); // AboveNormal
    cc.enqueue(make_packet(255)).unwrap(); // Critical

    // Critical should come first
    let p1 = cc.next_packet().unwrap();
    assert_eq!(Priority::from_raw(p1.header.priority), Priority::Critical);

    // Then AboveNormal
    let p2 = cc.next_packet().unwrap();
    assert_eq!(Priority::from_raw(p2.header.priority), Priority::AboveNormal);
}

#[test]
fn test_congestion_track_in_flight() {
    let mut cc = NadiCongestionControl::new();

    assert_eq!(cc.in_flight(), 0);

    cc.on_packet_sent(Priority::Normal, 1000);
    assert_eq!(cc.in_flight(), 1000);

    cc.on_packet_sent(Priority::High, 500);
    assert_eq!(cc.in_flight(), 1500);

    cc.on_packet_acked(Priority::Normal, 1000);
    assert_eq!(cc.in_flight(), 500);
}

#[test]
fn test_congestion_priority_in_flight() {
    let mut cc = NadiCongestionControl::new();

    cc.on_packet_sent(Priority::Normal, 1000);
    cc.on_packet_sent(Priority::High, 500);
    cc.on_packet_sent(Priority::Critical, 200);

    assert_eq!(cc.priority_in_flight(Priority::Normal), 1000);
    assert_eq!(cc.priority_in_flight(Priority::High), 500);
    assert_eq!(cc.priority_in_flight(Priority::Critical), 200);
}

#[test]
fn test_pacing_controller_basic() {
    let pacing = PacingController::new(1_000_000); // 1 MB/s

    assert_eq!(pacing.rate(), 1_000_000);
    assert!(pacing.can_send(1000));
}

#[test]
fn test_pacing_controller_rate_change() {
    let mut pacing = PacingController::new(1_000_000);

    pacing.set_rate(2_000_000);
    assert_eq!(pacing.rate(), 2_000_000);
}

#[test]
fn test_pacing_controller_token_consumption() {
    let mut pacing = PacingController::new(100_000); // 100 KB/s

    // Consume all tokens
    while pacing.can_send(10000) {
        pacing.consume(10000);
    }

    assert!(!pacing.can_send(10000));

    // Time to send should be positive
    let wait = pacing.time_until_send(10000);
    assert!(wait > std::time::Duration::ZERO);
}

#[test]
fn test_congestion_queue_length() {
    let mut cc = NadiCongestionControl::new();

    cc.enqueue(make_packet(255)).unwrap();
    cc.enqueue(make_packet(255)).unwrap();
    cc.enqueue(make_packet(64)).unwrap();

    assert_eq!(cc.queue_len(Priority::Critical), 2);
    assert_eq!(cc.queue_len(Priority::BelowNormal), 1);
    assert_eq!(cc.total_queued(), 3);
}

#[test]
fn test_congestion_stealth_jitter_range() {
    let mut cc = NadiCongestionControl::new();

    cc.enable_stealth(100, 1000);

    for _ in 0..100 {
        let jitter = cc.stealth_jitter();
        assert!(jitter >= std::time::Duration::from_micros(100));
        assert!(jitter <= std::time::Duration::from_micros(1000));
    }
}

#[test]
fn test_congestion_can_send() {
    let mut cc = NadiCongestionControl::new();

    assert!(cc.can_send()); // Empty, can send

    // Fill congestion window
    cc.total_in_flight = cc.cwnd();
    assert!(!cc.can_send()); // Window full

    // But critical can still go
    cc.enqueue(make_packet(255)).unwrap();
    assert!(cc.can_send()); // Critical bypasses
}

#[test]
fn test_congestion_dup_ack_threshold() {
    let mut cc = NadiCongestionControl::new();
    cc.cwnd = 50000;

    // 1-2 dup ACKs shouldn't trigger fast recovery
    cc.on_dup_ack();
    assert_eq!(cc.state(), CongestionState::SlowStart);
    cc.on_dup_ack();
    assert_eq!(cc.state(), CongestionState::SlowStart);

    // 3rd dup ACK triggers fast recovery
    cc.on_dup_ack();
    assert_eq!(cc.state(), CongestionState::FastRecovery);
}
