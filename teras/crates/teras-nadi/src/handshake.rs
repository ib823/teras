//! NADI 3-RTT Handshake Protocol.
//!
//! Implements the NADI handshake with:
//! - Hybrid PQ key exchange (ML-KEM-768 + X25519)
//! - Mutual authentication via certificates
//! - 0-RTT resumption with session tickets
//!
//! # Protocol Flow
//!
//! ```text
//! INITIAL HANDSHAKE (3-RTT):
//!
//!     Client                                              Server
//!        │                                                   │
//!        │  HANDSHAKE_INIT                                   │
//!        │  - Client ephemeral PQ public key (ML-KEM-768)    │
//!        │  - Client ephemeral classical key (X25519)        │
//!        │  - Client random (32 bytes)                       │
//!        │  - Supported versions                             │
//!        │  - Client certificate                             │
//!        │─────────────────────────────────────────────────▶│
//!        │                                                   │
//!        │                         HANDSHAKE_RESP            │
//!        │  - Server ephemeral PQ public key                 │
//!        │  - Server ephemeral classical key                 │
//!        │  - Server random (32 bytes)                       │
//!        │  - PQ ciphertext (ML-KEM encapsulation)           │
//!        │  - Server certificate                             │
//!        │  - Signature over transcript                      │
//!        │◀─────────────────────────────────────────────────│
//!        │                                                   │
//!        │  HANDSHAKE_DONE                                   │
//!        │  - Client signature over transcript               │
//!        │  - First encrypted application data               │
//!        │─────────────────────────────────────────────────▶│
//!        │                                                   │
//!        │  ◀══════════ SECURE CHANNEL ESTABLISHED ══════▶   │
//! ```

use crate::crypto::{HandshakeCrypto, SessionKeys, RANDOM_SIZE};
use crate::error::{NadiError, NadiResult};
use crate::packet::{Packet, PacketFlags, PacketHeader, PacketType, NADI_VERSION};
use bytes::{BufMut, BytesMut};
use std::time::{Duration, Instant};

/// Maximum handshake duration before timeout.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Session ticket lifetime.
pub const TICKET_LIFETIME: Duration = Duration::from_secs(86400); // 24 hours

/// Handshake state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state.
    Initial,
    /// Client has sent HANDSHAKE_INIT.
    ClientInitSent,
    /// Server has received INIT and sent RESP.
    ServerRespSent,
    /// Client has received RESP and sent DONE.
    ClientDoneSent,
    /// Handshake completed successfully.
    Completed,
    /// Handshake failed.
    Failed,
}

/// Client hello payload.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Protocol version.
    pub version: u8,
    /// Client random.
    pub random: [u8; RANDOM_SIZE],
    /// Client's X25519 ephemeral public key.
    pub x25519_public: [u8; 32],
    /// Client's ML-KEM-768 ephemeral public key (1184 bytes).
    pub ml_kem_public: Vec<u8>,
    /// Client certificate (serialized).
    pub certificate: Vec<u8>,
    /// Session ticket for resumption (optional).
    pub session_ticket: Option<Vec<u8>>,
    /// Supported cipher suites.
    pub cipher_suites: Vec<u8>,
}

impl ClientHello {
    /// Serialize to bytes.
    #[must_use]
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(2048);

        buf.put_u8(self.version);
        buf.put_slice(&self.random);
        buf.put_slice(&self.x25519_public);
        buf.put_u16(self.ml_kem_public.len() as u16);
        buf.put_slice(&self.ml_kem_public);
        buf.put_u16(self.certificate.len() as u16);
        buf.put_slice(&self.certificate);

        // Session ticket (prefixed with length, 0 if none)
        match &self.session_ticket {
            Some(ticket) => {
                buf.put_u16(ticket.len() as u16);
                buf.put_slice(ticket);
            }
            None => {
                buf.put_u16(0);
            }
        }

        buf.put_u8(self.cipher_suites.len() as u8);
        buf.put_slice(&self.cipher_suites);

        buf
    }

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> NadiResult<Self> {
        if data.len() < 1 + RANDOM_SIZE + 32 + 2 {
            return Err(NadiError::HandshakeError("ClientHello too short".into()));
        }

        let mut offset = 0;

        let version = data[offset];
        offset += 1;

        let mut random = [0u8; RANDOM_SIZE];
        random.copy_from_slice(&data[offset..offset + RANDOM_SIZE]);
        offset += RANDOM_SIZE;

        let mut x25519_public = [0u8; 32];
        x25519_public.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let ml_kem_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + ml_kem_len + 2 {
            return Err(NadiError::HandshakeError("ClientHello truncated".into()));
        }

        let ml_kem_public = data[offset..offset + ml_kem_len].to_vec();
        offset += ml_kem_len;

        let cert_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + cert_len + 2 {
            return Err(NadiError::HandshakeError("ClientHello truncated".into()));
        }

        let certificate = data[offset..offset + cert_len].to_vec();
        offset += cert_len;

        let ticket_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let session_ticket = if ticket_len > 0 {
            if data.len() < offset + ticket_len + 1 {
                return Err(NadiError::HandshakeError("ClientHello truncated".into()));
            }
            let ticket = data[offset..offset + ticket_len].to_vec();
            offset += ticket_len;
            Some(ticket)
        } else {
            None
        };

        if data.len() < offset + 1 {
            return Err(NadiError::HandshakeError("ClientHello truncated".into()));
        }

        let cipher_suite_len = data[offset] as usize;
        offset += 1;

        if data.len() < offset + cipher_suite_len {
            return Err(NadiError::HandshakeError("ClientHello truncated".into()));
        }

        let cipher_suites = data[offset..offset + cipher_suite_len].to_vec();

        Ok(Self {
            version,
            random,
            x25519_public,
            ml_kem_public,
            certificate,
            session_ticket,
            cipher_suites,
        })
    }
}

/// Server hello payload.
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Protocol version.
    pub version: u8,
    /// Server random.
    pub random: [u8; RANDOM_SIZE],
    /// Server's X25519 ephemeral public key.
    pub x25519_public: [u8; 32],
    /// Server's ML-KEM-768 ephemeral public key.
    pub ml_kem_public: Vec<u8>,
    /// ML-KEM ciphertext (encapsulated shared secret).
    pub ml_kem_ciphertext: Vec<u8>,
    /// Server certificate.
    pub certificate: Vec<u8>,
    /// Signature over transcript.
    pub signature: Vec<u8>,
    /// New session ticket (for future resumption).
    pub session_ticket: Option<Vec<u8>>,
}

impl ServerHello {
    /// Serialize to bytes.
    #[must_use]
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(4096);

        buf.put_u8(self.version);
        buf.put_slice(&self.random);
        buf.put_slice(&self.x25519_public);
        buf.put_u16(self.ml_kem_public.len() as u16);
        buf.put_slice(&self.ml_kem_public);
        buf.put_u16(self.ml_kem_ciphertext.len() as u16);
        buf.put_slice(&self.ml_kem_ciphertext);
        buf.put_u16(self.certificate.len() as u16);
        buf.put_slice(&self.certificate);
        buf.put_u16(self.signature.len() as u16);
        buf.put_slice(&self.signature);

        match &self.session_ticket {
            Some(ticket) => {
                buf.put_u16(ticket.len() as u16);
                buf.put_slice(ticket);
            }
            None => {
                buf.put_u16(0);
            }
        }

        buf
    }

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> NadiResult<Self> {
        if data.len() < 1 + RANDOM_SIZE + 32 + 2 {
            return Err(NadiError::HandshakeError("ServerHello too short".into()));
        }

        let mut offset = 0;

        let version = data[offset];
        offset += 1;

        let mut random = [0u8; RANDOM_SIZE];
        random.copy_from_slice(&data[offset..offset + RANDOM_SIZE]);
        offset += RANDOM_SIZE;

        let mut x25519_public = [0u8; 32];
        x25519_public.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let read_vec = |data: &[u8], offset: &mut usize| -> NadiResult<Vec<u8>> {
            if data.len() < *offset + 2 {
                return Err(NadiError::HandshakeError("ServerHello truncated".into()));
            }
            let len = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as usize;
            *offset += 2;
            if data.len() < *offset + len {
                return Err(NadiError::HandshakeError("ServerHello truncated".into()));
            }
            let vec = data[*offset..*offset + len].to_vec();
            *offset += len;
            Ok(vec)
        };

        let ml_kem_public = read_vec(data, &mut offset)?;
        let ml_kem_ciphertext = read_vec(data, &mut offset)?;
        let certificate = read_vec(data, &mut offset)?;
        let signature = read_vec(data, &mut offset)?;

        let session_ticket = {
            let ticket = read_vec(data, &mut offset)?;
            if ticket.is_empty() {
                None
            } else {
                Some(ticket)
            }
        };

        Ok(Self {
            version,
            random,
            x25519_public,
            ml_kem_public,
            ml_kem_ciphertext,
            certificate,
            signature,
            session_ticket,
        })
    }
}

/// Client finished payload.
#[derive(Debug, Clone)]
pub struct ClientFinished {
    /// Signature over transcript.
    pub signature: Vec<u8>,
    /// First encrypted data (optional).
    pub early_data: Option<Vec<u8>>,
}

impl ClientFinished {
    /// Serialize to bytes.
    #[must_use]
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(1024);

        buf.put_u16(self.signature.len() as u16);
        buf.put_slice(&self.signature);

        match &self.early_data {
            Some(data) => {
                buf.put_u32(data.len() as u32);
                buf.put_slice(data);
            }
            None => {
                buf.put_u32(0);
            }
        }

        buf
    }

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> NadiResult<Self> {
        if data.len() < 2 {
            return Err(NadiError::HandshakeError("ClientFinished too short".into()));
        }

        let mut offset = 0;

        let sig_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + sig_len + 4 {
            return Err(NadiError::HandshakeError("ClientFinished truncated".into()));
        }

        let signature = data[offset..offset + sig_len].to_vec();
        offset += sig_len;

        let early_data_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        let early_data = if early_data_len > 0 {
            if data.len() < offset + early_data_len {
                return Err(NadiError::HandshakeError("ClientFinished truncated".into()));
            }
            Some(data[offset..offset + early_data_len].to_vec())
        } else {
            None
        };

        Ok(Self {
            signature,
            early_data,
        })
    }
}

/// Session ticket for 0-RTT resumption.
#[derive(Debug, Clone)]
pub struct SessionTicket {
    /// Ticket creation time.
    pub created: Instant,
    /// Pre-shared key.
    pub psk: [u8; 32],
    /// Session ID.
    pub session_id: u64,
    /// Associated data (e.g., peer identity).
    pub associated_data: Vec<u8>,
}

impl SessionTicket {
    /// Check if ticket is still valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.created.elapsed() < TICKET_LIFETIME
    }
}

/// Handshake context.
pub struct HandshakeContext {
    /// Current state.
    pub state: HandshakeState,
    /// Start time.
    pub started: Instant,
    /// Our role (true = client, false = server).
    pub is_client: bool,
    /// Our random.
    pub our_random: [u8; RANDOM_SIZE],
    /// Peer's random.
    pub peer_random: Option<[u8; RANDOM_SIZE]>,
    /// Transcript hash.
    pub transcript: Vec<u8>,
    /// Derived session keys (after key exchange).
    pub session_keys: Option<SessionKeys>,
    /// Generated session ID.
    pub session_id: u64,
}

impl HandshakeContext {
    /// Create a new client handshake context.
    pub fn new_client() -> NadiResult<Self> {
        Ok(Self {
            state: HandshakeState::Initial,
            started: Instant::now(),
            is_client: true,
            our_random: HandshakeCrypto::generate_random()?,
            peer_random: None,
            transcript: Vec::new(),
            session_keys: None,
            session_id: rand::random(),
        })
    }

    /// Create a new server handshake context.
    pub fn new_server() -> NadiResult<Self> {
        Ok(Self {
            state: HandshakeState::Initial,
            started: Instant::now(),
            is_client: false,
            our_random: HandshakeCrypto::generate_random()?,
            peer_random: None,
            transcript: Vec::new(),
            session_keys: None,
            session_id: rand::random(),
        })
    }

    /// Check if handshake has timed out.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        self.started.elapsed() > HANDSHAKE_TIMEOUT
    }

    /// Update transcript with message data.
    pub fn update_transcript(&mut self, data: &[u8]) {
        self.transcript.extend_from_slice(data);
    }

    /// Get transcript hash.
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 32] {
        HandshakeCrypto::hash_transcript(&self.transcript)
    }

    /// Check if handshake is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Completed
    }

    /// Check if handshake failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.state == HandshakeState::Failed
    }

    /// Create HANDSHAKE_INIT packet (client).
    pub fn create_init_packet(&mut self, hello: &ClientHello) -> NadiResult<Packet> {
        if !self.is_client || self.state != HandshakeState::Initial {
            return Err(NadiError::InvalidHandshakeState {
                expected: "Initial (client)".into(),
                actual: format!("{:?}", self.state),
            });
        }

        let payload = hello.serialize();
        self.update_transcript(&payload);

        let mut header = PacketHeader::new(PacketType::HandshakeInit);
        header.session_id = self.session_id;
        header.flags = PacketFlags::new().set(PacketFlags::RELIABLE);

        self.state = HandshakeState::ClientInitSent;

        Ok(Packet {
            header,
            payload: payload.freeze(),
        })
    }

    /// Process HANDSHAKE_INIT packet (server).
    pub fn process_init_packet(&mut self, packet: &Packet) -> NadiResult<ClientHello> {
        if self.is_client || self.state != HandshakeState::Initial {
            return Err(NadiError::InvalidHandshakeState {
                expected: "Initial (server)".into(),
                actual: format!("{:?}", self.state),
            });
        }

        if packet.header.packet_type != PacketType::HandshakeInit {
            return Err(NadiError::HandshakeError("expected HANDSHAKE_INIT".into()));
        }

        let hello = ClientHello::parse(&packet.payload)?;

        if hello.version != NADI_VERSION {
            return Err(NadiError::UnsupportedVersion(hello.version));
        }

        self.peer_random = Some(hello.random);
        self.session_id = packet.header.session_id;
        self.update_transcript(&packet.payload);

        Ok(hello)
    }

    /// Create HANDSHAKE_RESP packet (server).
    pub fn create_resp_packet(&mut self, hello: &ServerHello) -> NadiResult<Packet> {
        if self.is_client {
            return Err(NadiError::InvalidHandshakeState {
                expected: "server".into(),
                actual: "client".into(),
            });
        }

        let payload = hello.serialize();
        self.update_transcript(&payload);

        let mut header = PacketHeader::new(PacketType::HandshakeResp);
        header.session_id = self.session_id;
        header.flags = PacketFlags::new().set(PacketFlags::RELIABLE);

        self.state = HandshakeState::ServerRespSent;

        Ok(Packet {
            header,
            payload: payload.freeze(),
        })
    }

    /// Process HANDSHAKE_RESP packet (client).
    pub fn process_resp_packet(&mut self, packet: &Packet) -> NadiResult<ServerHello> {
        if !self.is_client || self.state != HandshakeState::ClientInitSent {
            return Err(NadiError::InvalidHandshakeState {
                expected: "ClientInitSent".into(),
                actual: format!("{:?}", self.state),
            });
        }

        if packet.header.packet_type != PacketType::HandshakeResp {
            return Err(NadiError::HandshakeError("expected HANDSHAKE_RESP".into()));
        }

        let hello = ServerHello::parse(&packet.payload)?;

        if hello.version != NADI_VERSION {
            return Err(NadiError::UnsupportedVersion(hello.version));
        }

        self.peer_random = Some(hello.random);
        self.update_transcript(&packet.payload);

        Ok(hello)
    }

    /// Create HANDSHAKE_DONE packet (client).
    pub fn create_done_packet(&mut self, finished: &ClientFinished) -> NadiResult<Packet> {
        if !self.is_client {
            return Err(NadiError::InvalidHandshakeState {
                expected: "client".into(),
                actual: "server".into(),
            });
        }

        let payload = finished.serialize();
        self.update_transcript(&payload);

        let mut header = PacketHeader::new(PacketType::HandshakeDone);
        header.session_id = self.session_id;
        header.flags = PacketFlags::new()
            .set(PacketFlags::RELIABLE)
            .set(PacketFlags::ENCRYPTED);

        self.state = HandshakeState::ClientDoneSent;

        Ok(Packet {
            header,
            payload: payload.freeze(),
        })
    }

    /// Process HANDSHAKE_DONE packet (server).
    pub fn process_done_packet(&mut self, packet: &Packet) -> NadiResult<ClientFinished> {
        if self.is_client || self.state != HandshakeState::ServerRespSent {
            return Err(NadiError::InvalidHandshakeState {
                expected: "ServerRespSent".into(),
                actual: format!("{:?}", self.state),
            });
        }

        if packet.header.packet_type != PacketType::HandshakeDone {
            return Err(NadiError::HandshakeError("expected HANDSHAKE_DONE".into()));
        }

        let finished = ClientFinished::parse(&packet.payload)?;
        self.update_transcript(&packet.payload);

        self.state = HandshakeState::Completed;

        Ok(finished)
    }

    /// Complete handshake on client side.
    pub fn complete(&mut self) {
        self.state = HandshakeState::Completed;
    }

    /// Mark handshake as failed.
    pub fn fail(&mut self) {
        self.state = HandshakeState::Failed;
    }

    /// Set session keys after key exchange.
    pub fn set_session_keys(&mut self, keys: SessionKeys) {
        self.session_keys = Some(keys);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_roundtrip() {
        let hello = ClientHello {
            version: NADI_VERSION,
            random: [0x42u8; RANDOM_SIZE],
            x25519_public: [0x11u8; 32],
            ml_kem_public: vec![0x22u8; 100],
            certificate: vec![0x33u8; 200],
            session_ticket: Some(vec![0x44u8; 50]),
            cipher_suites: vec![1, 2, 3],
        };

        let serialized = hello.serialize();
        let parsed = ClientHello::parse(&serialized).unwrap();

        assert_eq!(parsed.version, hello.version);
        assert_eq!(parsed.random, hello.random);
        assert_eq!(parsed.x25519_public, hello.x25519_public);
        assert_eq!(parsed.ml_kem_public, hello.ml_kem_public);
        assert_eq!(parsed.certificate, hello.certificate);
        assert_eq!(parsed.session_ticket, hello.session_ticket);
        assert_eq!(parsed.cipher_suites, hello.cipher_suites);
    }

    #[test]
    fn test_server_hello_roundtrip() {
        let hello = ServerHello {
            version: NADI_VERSION,
            random: [0x55u8; RANDOM_SIZE],
            x25519_public: [0x66u8; 32],
            ml_kem_public: vec![0x77u8; 100],
            ml_kem_ciphertext: vec![0x88u8; 150],
            certificate: vec![0x99u8; 200],
            signature: vec![0xAAu8; 64],
            session_ticket: None,
        };

        let serialized = hello.serialize();
        let parsed = ServerHello::parse(&serialized).unwrap();

        assert_eq!(parsed.version, hello.version);
        assert_eq!(parsed.random, hello.random);
        assert_eq!(parsed.ml_kem_ciphertext, hello.ml_kem_ciphertext);
        assert!(parsed.session_ticket.is_none());
    }

    #[test]
    fn test_client_finished_roundtrip() {
        let finished = ClientFinished {
            signature: vec![0xBBu8; 64],
            early_data: Some(vec![0xCCu8; 1000]),
        };

        let serialized = finished.serialize();
        let parsed = ClientFinished::parse(&serialized).unwrap();

        assert_eq!(parsed.signature, finished.signature);
        assert_eq!(parsed.early_data, finished.early_data);
    }

    #[test]
    fn test_handshake_state_machine() {
        // Create client and server contexts
        let mut client = HandshakeContext::new_client().unwrap();
        let mut server = HandshakeContext::new_server().unwrap();

        assert_eq!(client.state, HandshakeState::Initial);
        assert_eq!(server.state, HandshakeState::Initial);

        // Client creates INIT
        let client_hello = ClientHello {
            version: NADI_VERSION,
            random: client.our_random,
            x25519_public: [0u8; 32],
            ml_kem_public: vec![0u8; 100],
            certificate: vec![],
            session_ticket: None,
            cipher_suites: vec![1],
        };
        let init_packet = client.create_init_packet(&client_hello).unwrap();
        assert_eq!(client.state, HandshakeState::ClientInitSent);

        // Server processes INIT
        let _ = server.process_init_packet(&init_packet).unwrap();

        // Server creates RESP
        let server_hello = ServerHello {
            version: NADI_VERSION,
            random: server.our_random,
            x25519_public: [0u8; 32],
            ml_kem_public: vec![0u8; 100],
            ml_kem_ciphertext: vec![0u8; 150],
            certificate: vec![],
            signature: vec![0u8; 64],
            session_ticket: None,
        };
        let resp_packet = server.create_resp_packet(&server_hello).unwrap();
        assert_eq!(server.state, HandshakeState::ServerRespSent);

        // Client processes RESP
        let _ = client.process_resp_packet(&resp_packet).unwrap();

        // Client creates DONE
        let client_finished = ClientFinished {
            signature: vec![0u8; 64],
            early_data: None,
        };
        let done_packet = client.create_done_packet(&client_finished).unwrap();
        assert_eq!(client.state, HandshakeState::ClientDoneSent);

        // Server processes DONE
        let _ = server.process_done_packet(&done_packet).unwrap();
        assert_eq!(server.state, HandshakeState::Completed);

        // Client marks complete
        client.complete();
        assert!(client.is_complete());
        assert!(server.is_complete());
    }

    #[test]
    fn test_handshake_timeout() {
        let ctx = HandshakeContext::new_client().unwrap();
        assert!(!ctx.is_timed_out());
    }

    #[test]
    fn test_transcript_hash() {
        let mut ctx = HandshakeContext::new_client().unwrap();
        ctx.update_transcript(b"hello");
        ctx.update_transcript(b"world");

        let hash = ctx.transcript_hash();
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }
}
