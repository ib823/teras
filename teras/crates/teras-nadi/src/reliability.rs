//! NADI reliability layer.
//!
//! Provides:
//! - Sequence number tracking
//! - Acknowledgment handling
//! - Selective ACK (SACK)
//! - Retransmission with exponential backoff
//! - FEC integration for critical packets

use crate::error::{NadiError, NadiResult};
use crate::fec::{FecConfig, ReedSolomonDecoder, ReedSolomonEncoder};
use crate::packet::{Packet, Priority};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum retransmission attempts before giving up.
pub const MAX_RETRANSMITS: u8 = 5;

/// Initial retransmission timeout.
pub const INITIAL_RTO: Duration = Duration::from_millis(200);

/// Maximum retransmission timeout.
pub const MAX_RTO: Duration = Duration::from_secs(10);

/// Minimum retransmission timeout.
pub const MIN_RTO: Duration = Duration::from_millis(100);

/// SACK block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    /// Start of acknowledged range (inclusive).
    pub start: u32,
    /// End of acknowledged range (exclusive).
    pub end: u32,
}

impl SackBlock {
    /// Create a new SACK block.
    #[must_use]
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Check if a sequence number is in this block.
    #[must_use]
    pub fn contains(&self, seq: u32) -> bool {
        seq >= self.start && seq < self.end
    }

    /// Number of sequences in this block.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Check if block is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// Sent packet awaiting acknowledgment.
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// The packet that was sent.
    pub packet: Packet,
    /// Time when packet was first sent.
    pub first_sent: Instant,
    /// Time when packet was last sent (for retransmit).
    pub last_sent: Instant,
    /// Number of times this packet has been sent.
    pub send_count: u8,
    /// FEC shard index (if using FEC).
    pub fec_index: Option<usize>,
}

impl SentPacket {
    /// Create a new sent packet record.
    pub fn new(packet: Packet) -> Self {
        let now = Instant::now();
        Self {
            packet,
            first_sent: now,
            last_sent: now,
            send_count: 1,
            fec_index: None,
        }
    }

    /// Check if retransmit limit has been exceeded.
    #[must_use]
    pub fn exceeded_retransmit_limit(&self) -> bool {
        self.send_count > MAX_RETRANSMITS
    }

    /// Calculate next retransmit timeout (exponential backoff).
    #[must_use]
    pub fn next_rto(&self) -> Duration {
        let backoff = 1u64 << self.send_count.min(6);
        let rto = INITIAL_RTO.saturating_mul(backoff as u32);
        rto.clamp(MIN_RTO, MAX_RTO)
    }

    /// Check if packet should be retransmitted.
    #[must_use]
    pub fn should_retransmit(&self) -> bool {
        self.last_sent.elapsed() >= self.next_rto()
    }
}

/// Received packet (for ordering).
#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    /// The received packet.
    pub packet: Packet,
    /// Time when received.
    pub received_at: Instant,
    /// FEC shard index (if using FEC).
    pub fec_index: Option<usize>,
}

impl ReceivedPacket {
    /// Create a new received packet record.
    pub fn new(packet: Packet) -> Self {
        Self {
            packet,
            received_at: Instant::now(),
            fec_index: None,
        }
    }
}

/// RTT (Round Trip Time) estimator using Jacobson/Karels algorithm.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT.
    srtt: Option<Duration>,
    /// RTT variance.
    rttvar: Option<Duration>,
    /// Retransmission timeout.
    rto: Duration,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// Create a new RTT estimator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: INITIAL_RTO,
        }
    }

    /// Update RTT estimate with a new sample.
    pub fn update(&mut self, rtt: Duration) {
        let rtt_secs = rtt.as_secs_f64();

        match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                // Update existing estimates
                let srtt_secs = srtt.as_secs_f64();
                let rttvar_secs = rttvar.as_secs_f64();

                // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
                // where beta = 1/4
                let diff = (srtt_secs - rtt_secs).abs();
                let new_rttvar = rttvar_secs * 0.75 + diff * 0.25;

                // SRTT = (1 - alpha) * SRTT + alpha * R
                // where alpha = 1/8
                let new_srtt = srtt_secs * 0.875 + rtt_secs * 0.125;

                self.srtt = Some(Duration::from_secs_f64(new_srtt));
                self.rttvar = Some(Duration::from_secs_f64(new_rttvar));
            }
            _ => {
                // First measurement
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
        }

        // RTO = SRTT + max(G, 4 * RTTVAR)
        // where G is clock granularity (assume 1ms)
        let srtt = self.srtt.unwrap();
        let rttvar = self.rttvar.unwrap();
        let g = Duration::from_millis(1);

        self.rto = srtt + g.max(rttvar * 4);
        self.rto = self.rto.clamp(MIN_RTO, MAX_RTO);
    }

    /// Get current RTO.
    #[must_use]
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Get smoothed RTT.
    #[must_use]
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }
}

/// Reliability manager for a connection.
pub struct ReliabilityManager {
    /// Next sequence number to send.
    next_send_seq: u32,
    /// Next expected sequence number to receive.
    next_recv_seq: u32,
    /// Sent packets awaiting ACK, indexed by sequence number.
    sent_buffer: HashMap<u32, SentPacket>,
    /// Received packets (out-of-order), indexed by sequence number.
    recv_buffer: BTreeMap<u32, ReceivedPacket>,
    /// In-order received packets ready for delivery.
    ready_queue: VecDeque<Packet>,
    /// SACK blocks for received ranges.
    sack_blocks: Vec<SackBlock>,
    /// RTT estimator.
    rtt: RttEstimator,
    /// FEC encoder (if enabled).
    fec_encoder: Option<ReedSolomonEncoder>,
    /// FEC decoder (if enabled).
    fec_decoder: Option<ReedSolomonDecoder>,
    /// Pending FEC shards for reconstruction.
    #[allow(dead_code)]
    fec_pending: HashMap<u32, Vec<(usize, Vec<u8>)>>,
    /// Maximum window size.
    max_window: u32,
    /// Packets in flight count.
    in_flight: u32,
}

impl ReliabilityManager {
    /// Create a new reliability manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_send_seq: 0,
            next_recv_seq: 0,
            sent_buffer: HashMap::new(),
            recv_buffer: BTreeMap::new(),
            ready_queue: VecDeque::new(),
            sack_blocks: Vec::new(),
            rtt: RttEstimator::new(),
            fec_encoder: None,
            fec_decoder: None,
            fec_pending: HashMap::new(),
            max_window: 256,
            in_flight: 0,
        }
    }

    /// Configure FEC for a priority level.
    pub fn configure_fec(&mut self, priority: Priority) -> NadiResult<()> {
        if let Some(config) = FecConfig::for_priority(priority) {
            self.fec_encoder = Some(ReedSolomonEncoder::new(config)?);
            self.fec_decoder = Some(ReedSolomonDecoder::new(config));
        } else {
            self.fec_encoder = None;
            self.fec_decoder = None;
        }
        Ok(())
    }

    /// Get next sequence number for sending.
    pub fn next_sequence(&mut self) -> u32 {
        let seq = self.next_send_seq;
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        seq
    }

    /// Record a sent packet.
    pub fn record_sent(&mut self, packet: Packet) -> NadiResult<()> {
        let seq = packet.header.sequence;

        if self.in_flight >= self.max_window {
            return Err(NadiError::CongestionWindowExhausted);
        }

        self.sent_buffer.insert(seq, SentPacket::new(packet));
        self.in_flight += 1;

        Ok(())
    }

    /// Process an acknowledgment.
    pub fn process_ack(&mut self, ack_seq: u32, sack_blocks: &[SackBlock]) {
        // Remove all packets up to and including ack_seq
        let mut to_remove = Vec::new();
        for &seq in self.sent_buffer.keys() {
            if Self::seq_le(seq, ack_seq) {
                to_remove.push(seq);
            }
        }

        for seq in &to_remove {
            if let Some(sent) = self.sent_buffer.remove(seq) {
                self.in_flight = self.in_flight.saturating_sub(1);

                // Update RTT if this was the first send
                if sent.send_count == 1 {
                    let rtt = sent.first_sent.elapsed();
                    self.rtt.update(rtt);
                }
            }
        }

        // Process SACK blocks
        for block in sack_blocks {
            for seq in block.start..block.end {
                if let Some(sent) = self.sent_buffer.remove(&seq) {
                    self.in_flight = self.in_flight.saturating_sub(1);
                    if sent.send_count == 1 {
                        let rtt = sent.first_sent.elapsed();
                        self.rtt.update(rtt);
                    }
                }
            }
        }
    }

    /// Record a received packet.
    pub fn record_received(&mut self, packet: Packet) {
        let seq = packet.header.sequence;

        // Check if this is a duplicate or old packet
        if Self::seq_lt(seq, self.next_recv_seq) {
            return; // Already received
        }

        if seq == self.next_recv_seq {
            // In-order packet
            self.ready_queue.push_back(packet);
            self.next_recv_seq = self.next_recv_seq.wrapping_add(1);

            // Check if we can deliver more from recv_buffer
            while let Some(entry) = self.recv_buffer.remove(&self.next_recv_seq) {
                self.ready_queue.push_back(entry.packet);
                self.next_recv_seq = self.next_recv_seq.wrapping_add(1);
            }

            self.update_sack_blocks();
        } else {
            // Out-of-order packet
            self.recv_buffer.insert(seq, ReceivedPacket::new(packet));
            self.update_sack_blocks();
        }
    }

    /// Get packets ready for delivery.
    pub fn get_ready_packets(&mut self) -> Vec<Packet> {
        self.ready_queue.drain(..).collect()
    }

    /// Get packets that need retransmission.
    pub fn get_retransmits(&mut self) -> NadiResult<Vec<Packet>> {
        let mut retransmits = Vec::new();

        for sent in self.sent_buffer.values_mut() {
            if sent.exceeded_retransmit_limit() {
                return Err(NadiError::RetransmitLimitExceeded(sent.packet.header.sequence));
            }

            if sent.should_retransmit() {
                sent.send_count += 1;
                sent.last_sent = Instant::now();
                retransmits.push(sent.packet.clone());
            }
        }

        Ok(retransmits)
    }

    /// Get current SACK blocks.
    #[must_use]
    pub fn sack_blocks(&self) -> &[SackBlock] {
        &self.sack_blocks
    }

    /// Get the cumulative ACK (next expected sequence).
    #[must_use]
    pub fn cumulative_ack(&self) -> u32 {
        self.next_recv_seq
    }

    /// Get RTT estimator.
    #[must_use]
    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    /// Get number of packets in flight.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Update SACK blocks based on receive buffer.
    fn update_sack_blocks(&mut self) {
        self.sack_blocks.clear();

        if self.recv_buffer.is_empty() {
            return;
        }

        let mut iter = self.recv_buffer.keys().copied();
        let mut block_start = match iter.next() {
            Some(s) => s,
            None => return,
        };
        let mut block_end = block_start + 1;

        for seq in iter {
            if seq == block_end {
                block_end += 1;
            } else {
                self.sack_blocks.push(SackBlock::new(block_start, block_end));
                block_start = seq;
                block_end = seq + 1;
            }
        }

        self.sack_blocks.push(SackBlock::new(block_start, block_end));
    }

    /// Compare sequence numbers (handles wraparound).
    fn seq_lt(a: u32, b: u32) -> bool {
        let diff = a.wrapping_sub(b) as i32;
        diff < 0
    }

    /// Compare sequence numbers (handles wraparound).
    fn seq_le(a: u32, b: u32) -> bool {
        a == b || Self::seq_lt(a, b)
    }
}

impl Default for ReliabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize SACK blocks to bytes.
pub fn serialize_sack_blocks(blocks: &[SackBlock]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + blocks.len() * 8);
    buf.push(blocks.len().min(255) as u8);

    for block in blocks.iter().take(255) {
        buf.extend_from_slice(&block.start.to_be_bytes());
        buf.extend_from_slice(&block.end.to_be_bytes());
    }

    buf
}

/// Deserialize SACK blocks from bytes.
pub fn deserialize_sack_blocks(data: &[u8]) -> NadiResult<Vec<SackBlock>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let count = data[0] as usize;
    if data.len() < 1 + count * 8 {
        return Err(NadiError::InvalidPacket("SACK data too short".into()));
    }

    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 1 + i * 8;
        let start = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let end = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        blocks.push(SackBlock::new(start, end));
    }

    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketHeader, PacketType};
    use bytes::Bytes;

    fn make_packet(seq: u32) -> Packet {
        let mut header = PacketHeader::new(PacketType::Data);
        header.sequence = seq;
        Packet {
            header,
            payload: Bytes::from_static(b"test"),
        }
    }

    #[test]
    fn test_sack_block() {
        let block = SackBlock::new(10, 15);
        assert!(block.contains(10));
        assert!(block.contains(14));
        assert!(!block.contains(15));
        assert!(!block.contains(9));
        assert_eq!(block.len(), 5);
    }

    #[test]
    fn test_rtt_estimator() {
        let mut rtt = RttEstimator::new();
        assert!(rtt.srtt().is_none());

        rtt.update(Duration::from_millis(100));
        assert!(rtt.srtt().is_some());

        rtt.update(Duration::from_millis(120));
        rtt.update(Duration::from_millis(80));

        // RTO should be reasonable
        let rto = rtt.rto();
        assert!(rto >= MIN_RTO);
        assert!(rto <= MAX_RTO);
    }

    #[test]
    fn test_reliability_in_order() {
        let mut mgr = ReliabilityManager::new();

        for i in 0..5 {
            let pkt = make_packet(i);
            mgr.record_received(pkt);
        }

        let ready = mgr.get_ready_packets();
        assert_eq!(ready.len(), 5);
        assert_eq!(mgr.cumulative_ack(), 5);
    }

    #[test]
    fn test_reliability_out_of_order() {
        let mut mgr = ReliabilityManager::new();

        // Receive packets out of order: 0, 2, 1, 4, 3
        mgr.record_received(make_packet(0));
        mgr.record_received(make_packet(2));
        mgr.record_received(make_packet(1));
        mgr.record_received(make_packet(4));
        mgr.record_received(make_packet(3));

        let ready = mgr.get_ready_packets();
        assert_eq!(ready.len(), 5);

        // Verify order
        for (i, pkt) in ready.iter().enumerate() {
            assert_eq!(pkt.header.sequence, i as u32);
        }
    }

    #[test]
    fn test_reliability_sack_blocks() {
        let mut mgr = ReliabilityManager::new();

        // Receive 0, 2, 3, 5, 6, 7 (missing 1 and 4)
        mgr.record_received(make_packet(0));
        mgr.record_received(make_packet(2));
        mgr.record_received(make_packet(3));
        mgr.record_received(make_packet(5));
        mgr.record_received(make_packet(6));
        mgr.record_received(make_packet(7));

        // Only 0 should be ready (waiting for 1)
        let ready = mgr.get_ready_packets();
        assert_eq!(ready.len(), 1);
        assert_eq!(mgr.cumulative_ack(), 1);

        // Should have SACK blocks for [2,4) and [5,8)
        let sacks = mgr.sack_blocks();
        assert_eq!(sacks.len(), 2);
        assert_eq!(sacks[0], SackBlock::new(2, 4));
        assert_eq!(sacks[1], SackBlock::new(5, 8));
    }

    #[test]
    fn test_reliability_ack_processing() {
        let mut mgr = ReliabilityManager::new();

        // Record sent packets
        for i in 0..5 {
            let mut pkt = make_packet(i);
            pkt.header.sequence = mgr.next_sequence();
            mgr.record_sent(pkt).unwrap();
        }

        assert_eq!(mgr.in_flight(), 5);

        // ACK up to sequence 2
        mgr.process_ack(2, &[]);
        assert_eq!(mgr.in_flight(), 2); // 3 and 4 still in flight
    }

    #[test]
    fn test_sack_serialization() {
        let blocks = vec![
            SackBlock::new(10, 20),
            SackBlock::new(30, 35),
        ];

        let serialized = serialize_sack_blocks(&blocks);
        let deserialized = deserialize_sack_blocks(&serialized).unwrap();

        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0], blocks[0]);
        assert_eq!(deserialized[1], blocks[1]);
    }

    #[test]
    fn test_sent_packet_retransmit() {
        let pkt = make_packet(0);
        let mut sent = SentPacket::new(pkt);

        assert_eq!(sent.send_count, 1);
        assert!(!sent.exceeded_retransmit_limit());

        // Simulate retransmits
        for _ in 0..MAX_RETRANSMITS {
            sent.send_count += 1;
        }

        assert!(sent.exceeded_retransmit_limit());
    }

    #[test]
    fn test_sequence_wraparound() {
        assert!(ReliabilityManager::seq_lt(u32::MAX - 1, u32::MAX));
        assert!(ReliabilityManager::seq_lt(u32::MAX, 0)); // Wraparound
        assert!(ReliabilityManager::seq_lt(0, 1));
        assert!(!ReliabilityManager::seq_lt(1, 0));
    }
}
