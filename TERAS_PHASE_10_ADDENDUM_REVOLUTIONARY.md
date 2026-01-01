# TERAS PHASE 10 ADDENDUM: REVOLUTIONARY SPECIFICATIONS

> **CLASSIFICATION:** MANDATORY ENHANCEMENT DIRECTIVE
> **VERSION:** 1.0.0
> **DATE:** 2025-12-31
> **STATUS:** BINDING - SUPERSEDES BASE HANDOFF WHERE CONFLICTS EXIST
> **PURPOSE:** Transform TERAS from excellent to WORLD-FIRST, COMPETITOR-DESTROYING

---

# ⚠️ THIS DOCUMENT EXTENDS THE BASE HANDOFF

Read this AFTER the base handoff. This addendum specifies:

1. Pre-requisite: teras-jejak audit_log! macro update
2. Custom transport protocol: NADI (replacing QUIC)
3. Real-world malware corpus integration
4. All revolutionary differentiators

---

# PART A: PRE-REQUISITE - TERAS-JEJAK UPDATE

## A.1 REQUIRED MACRO ADDITION

Before implementing teras-menara, you MUST update teras-jejak to add the `audit_log!` macro.

### A.1.1 File: teras-jejak/src/macros.rs (NEW FILE)

```rust
//! Audit logging macros for ergonomic, consistent logging across TERAS.
//!
//! The `audit_log!` macro provides a structured way to log security-relevant
//! events with consistent formatting and automatic context capture.

/// Structured audit logging macro.
///
/// # Syntax
///
/// ```rust
/// audit_log!(
///     level = Level::Info,           // Optional, defaults to Info
///     action = "action_name",        // Required
///     actor = Actor::System("x"),    // Optional, defaults to current module
///     field1 = value1,               // Optional context fields
///     field2 = ?debug_value,         // Use ? for Debug formatting
///     "Human readable message"       // Required message
/// );
/// ```
///
/// # Examples
///
/// ```rust
/// use teras_jejak::audit_log;
///
/// // Simple usage
/// audit_log!(action = "user_login", "User logged in successfully");
///
/// // With context
/// audit_log!(
///     action = "threat_detected",
///     threat_id = threat.id,
///     severity = threat.severity,
///     source = ?threat.source,
///     "Threat detected and blocked"
/// );
///
/// // With explicit level and actor
/// audit_log!(
///     level = Level::Critical,
///     action = "key_compromise",
///     actor = Actor::System("teras-kunci"),
///     key_id = key.id,
///     "Potential key compromise detected"
/// );
/// ```
#[macro_export]
macro_rules! audit_log {
    // Full form with level and actor
    (
        level = $level:expr,
        action = $action:expr,
        actor = $actor:expr,
        $($key:ident = $(?$debug:tt)? $value:expr),* $(,)?
        $msg:expr
    ) => {{
        let mut context = ::std::collections::HashMap::new();
        $(
            audit_log!(@insert context, $key, $($debug)? $value);
        )*
        
        let entry = $crate::AuditLogEntry::builder()
            .level($level)
            .action($crate::Action::Custom($action.into()))
            .actor($actor)
            .message($msg)
            .context(context)
            .timestamp($crate::now_utc())
            .build();
        
        $crate::GLOBAL_AUDIT_LOG.append(entry)
    }};
    
    // Without level (defaults to Info)
    (
        action = $action:expr,
        actor = $actor:expr,
        $($key:ident = $(?$debug:tt)? $value:expr),* $(,)?
        $msg:expr
    ) => {{
        $crate::audit_log!(
            level = $crate::Level::Info,
            action = $action,
            actor = $actor,
            $($key = $($debug)? $value,)*
            $msg
        )
    }};
    
    // Without actor (defaults to module path)
    (
        level = $level:expr,
        action = $action:expr,
        $($key:ident = $(?$debug:tt)? $value:expr),* $(,)?
        $msg:expr
    ) => {{
        $crate::audit_log!(
            level = $level,
            action = $action,
            actor = $crate::Actor::System(module_path!().into()),
            $($key = $($debug)? $value,)*
            $msg
        )
    }};
    
    // Minimal form (just action and message)
    (
        action = $action:expr,
        $($key:ident = $(?$debug:tt)? $value:expr),* $(,)?
        $msg:expr
    ) => {{
        $crate::audit_log!(
            level = $crate::Level::Info,
            action = $action,
            actor = $crate::Actor::System(module_path!().into()),
            $($key = $($debug)? $value,)*
            $msg
        )
    }};
    
    // Helper for inserting into context map
    (@insert $ctx:ident, $key:ident, ? $value:expr) => {{
        $ctx.insert(stringify!($key).to_string(), format!("{:?}", $value));
    }};
    (@insert $ctx:ident, $key:ident, $value:expr) => {{
        $ctx.insert(stringify!($key).to_string(), $value.to_string());
    }};
}

/// Global audit log instance.
/// 
/// Thread-safe, append-only, cryptographically chained.
/// Initialized lazily on first use.
pub static GLOBAL_AUDIT_LOG: once_cell::sync::Lazy<std::sync::Arc<crate::AuditLog>> = 
    once_cell::sync::Lazy::new(|| {
        std::sync::Arc::new(crate::AuditLog::new().expect("Failed to initialize global audit log"))
    });
```

### A.1.2 Update teras-jejak/src/lib.rs

```rust
// Add at top
mod macros;

// Add to exports
pub use macros::GLOBAL_AUDIT_LOG;

// Re-export macro (happens automatically via #[macro_export])
```

### A.1.3 Add Dependency

```toml
# In teras-jejak/Cargo.toml
[dependencies]
once_cell = "=1.19.0"  # For lazy static initialization
```

### A.1.4 Validation

After updating teras-jejak:

```bash
cd teras-jejak
cargo test
cargo clippy -- -D warnings

# Verify macro works
cat > /tmp/test_macro.rs << 'EOF'
use teras_jejak::{audit_log, Level, Actor};

fn main() {
    audit_log!(action = "test", "Simple test");
    audit_log!(action = "test", user = "alice", "With context");
    audit_log!(
        level = Level::Critical,
        action = "security_event",
        threat_id = 12345,
        source = ?"network",
        "Critical event"
    );
}
EOF
```

---

# PART B: NADI PROTOCOL - CUSTOM TRANSPORT

## B.1 OVERVIEW

**NADI** (نادي - "pulse" in Malay) is TERAS's proprietary transport protocol, purpose-built for threat intelligence sharing. It is designed to be **SUPERIOR to QUIC** in every dimension that matters for security applications.

### B.1.1 Why Not QUIC?

| Aspect | QUIC | NADI |
|--------|------|------|
| **Dependencies** | 159 transitive crates (quinn) | ZERO external deps |
| **Purpose** | General web transport | Security-first threat sharing |
| **Encryption** | TLS 1.3 (good) | Hybrid PQ + classical (better) |
| **Anonymity** | None | Built-in onion routing |
| **Bandwidth** | Optimized for throughput | Optimized for stealth |
| **Detection** | Standard QUIC fingerprint | Polymorphic, undetectable |
| **Key Exchange** | X25519 only | ML-KEM-768 + X25519 hybrid |
| **Threat-specific** | No | Yes - threat metadata compression |

### B.1.2 NADI Design Principles

```
PRINCIPLE 1: ZERO TRUST TRANSPORT
- Every packet authenticated
- Every peer verified cryptographically
- No trust in network infrastructure

PRINCIPLE 2: POST-QUANTUM READY
- Hybrid key exchange (ML-KEM-768 + X25519)
- Hybrid signatures (ML-DSA-65 + Ed25519)
- Algorithm agility built-in

PRINCIPLE 3: STEALTH BY DEFAULT
- Traffic looks like random noise
- No fixed port (dynamic port hopping)
- Polymorphic packet structure
- Resistant to DPI (Deep Packet Inspection)

PRINCIPLE 4: THREAT-OPTIMIZED
- Native threat indicator compression
- Bloom filter transmission for IOC sets
- Differential sync for feed updates
- Priority lanes for critical alerts

PRINCIPLE 5: BYZANTINE FAULT TOLERANT
- Tolerates up to 1/3 malicious peers
- Cryptographic voting for consensus
- Reputation-weighted message propagation
```

## B.2 NADI PROTOCOL SPECIFICATION

### B.2.1 Packet Structure

```
NADI PACKET FORMAT (Variable length, 64-65535 bytes)

┌─────────────────────────────────────────────────────────────────┐
│ HEADER (32 bytes, encrypted after handshake)                    │
├─────────────────────────────────────────────────────────────────┤
│ Version     │ 4 bits  │ Protocol version (current: 1)          │
│ Type        │ 4 bits  │ Packet type (see below)                 │
│ Flags       │ 8 bits  │ Control flags                           │
│ Sequence    │ 32 bits │ Packet sequence number                  │
│ Ack         │ 32 bits │ Acknowledgment number                   │
│ Session ID  │ 64 bits │ Encrypted session identifier            │
│ Length      │ 16 bits │ Payload length                          │
│ Priority    │ 8 bits  │ Message priority (0=low, 255=critical)  │
│ Reserved    │ 24 bits │ Reserved for future use                 │
│ Header MAC  │ 64 bits │ Truncated HMAC of header                │
├─────────────────────────────────────────────────────────────────┤
│ PAYLOAD (0-65503 bytes, always encrypted)                       │
├─────────────────────────────────────────────────────────────────┤
│ Encrypted payload using ChaCha20-Poly1305                       │
│ Key derived from session key + sequence number                  │
│ Nonce: Session nonce XOR sequence number                        │
└─────────────────────────────────────────────────────────────────┘

PACKET TYPES:
0x0 - HANDSHAKE_INIT      Initiate connection
0x1 - HANDSHAKE_RESP      Respond to handshake
0x2 - HANDSHAKE_DONE      Complete handshake
0x3 - DATA                Regular data packet
0x4 - ACK                 Acknowledgment
0x5 - PING                Keepalive
0x6 - PONG                Keepalive response
0x7 - THREAT_ALERT        High-priority threat (bypasses congestion)
0x8 - PEER_ANNOUNCE       Announce peer presence
0x9 - PEER_QUERY          Query for peers
0xA - REPUTATION_UPDATE   Update peer reputation
0xB - BLOOM_SYNC          IOC bloom filter sync
0xC - CLOSE               Close connection
0xD - RESET               Reset connection state
0xE-0xF - RESERVED        Future use

FLAGS:
0x01 - ENCRYPTED          Payload is encrypted (always set after handshake)
0x02 - COMPRESSED         Payload is compressed (zstd)
0x04 - FRAGMENTED         This is a fragment of larger message
0x08 - LAST_FRAGMENT      This is the last fragment
0x10 - ONION              Packet is onion-routed
0x20 - PRIORITY           High-priority, skip queue
0x40 - RELIABLE           Requires acknowledgment
0x80 - RESERVED           Future use
```

### B.2.2 Handshake Protocol (3-RTT with 0-RTT resumption)

```
INITIAL HANDSHAKE (First connection between peers):

    Client                                              Server
       │                                                   │
       │  HANDSHAKE_INIT                                   │
       │  - Client ephemeral PQ public key (ML-KEM-768)    │
       │  - Client ephemeral classical key (X25519)        │
       │  - Client random (32 bytes)                       │
       │  - Supported versions                             │
       │  - Client certificate (signed by TERAS root)      │
       │─────────────────────────────────────────────────▶│
       │                                                   │
       │                         HANDSHAKE_RESP            │
       │  - Server ephemeral PQ public key                 │
       │  - Server ephemeral classical key                 │
       │  - Server random (32 bytes)                       │
       │  - PQ ciphertext (ML-KEM encapsulation)           │
       │  - Server certificate                             │
       │  - Signature over transcript                      │
       │◀─────────────────────────────────────────────────│
       │                                                   │
       │  HANDSHAKE_DONE                                   │
       │  - Client signature over transcript               │
       │  - First encrypted application data               │
       │─────────────────────────────────────────────────▶│
       │                                                   │
       │  ◀══════════ SECURE CHANNEL ESTABLISHED ══════▶   │

SESSION KEY DERIVATION:

  pq_shared = ML-KEM-768.Decapsulate(pq_ciphertext, client_sk)
  classical_shared = X25519(client_sk, server_pk)
  
  master_secret = HKDF-SHA3-256(
      ikm = pq_shared || classical_shared,
      salt = client_random || server_random,
      info = "NADI-v1-master"
  )
  
  client_key = HKDF-Expand(master_secret, "client-key", 32)
  server_key = HKDF-Expand(master_secret, "server-key", 32)
  client_nonce = HKDF-Expand(master_secret, "client-nonce", 12)
  server_nonce = HKDF-Expand(master_secret, "server-nonce", 12)


0-RTT RESUMPTION (Subsequent connections):

    Client                                              Server
       │                                                   │
       │  HANDSHAKE_INIT + DATA                            │
       │  - Session ticket (encrypted)                     │
       │  - 0-RTT encrypted data                           │
       │─────────────────────────────────────────────────▶│
       │                                                   │
       │                    HANDSHAKE_RESP + DATA          │
       │  - New session ticket                             │
       │  - Response data                                  │
       │◀─────────────────────────────────────────────────│
       │                                                   │
       │  ◀════════ 1-RTT SECURE CHANNEL ═══════▶          │
```

### B.2.3 Congestion Control: NADI-CC

Custom congestion control optimized for threat intelligence:

```rust
/// NADI Congestion Control
/// 
/// Unlike TCP/QUIC which optimize for throughput,
/// NADI-CC optimizes for:
/// 1. Latency of critical alerts
/// 2. Stealth (avoid traffic analysis)
/// 3. Fairness among threat priorities
pub struct NadiCongestionControl {
    /// Congestion window in bytes
    cwnd: u32,
    
    /// Slow start threshold
    ssthresh: u32,
    
    /// RTT estimator
    rtt: RttEstimator,
    
    /// Priority queues (0-7, 7 = highest)
    priority_queues: [VecDeque<Packet>; 8],
    
    /// Bytes in flight per priority
    in_flight: [u32; 8],
    
    /// Stealth mode: randomize send timing
    stealth_mode: bool,
    
    /// Jitter range for stealth (microseconds)
    stealth_jitter: Range<u64>,
}

impl NadiCongestionControl {
    /// Priority-weighted packet selection
    /// 
    /// Higher priority packets get more bandwidth share:
    /// - Priority 7 (CRITICAL): 40% of cwnd
    /// - Priority 6 (HIGH):     25% of cwnd
    /// - Priority 5 (MEDIUM):   15% of cwnd
    /// - Priority 0-4 (LOW):    Share remaining 20%
    fn select_next_packet(&mut self) -> Option<Packet> {
        // Critical alerts ALWAYS go first, even if over quota
        if let Some(pkt) = self.priority_queues[7].pop_front() {
            return Some(pkt);
        }
        
        // Check quotas for other priorities
        for priority in (0..7).rev() {
            let quota = self.priority_quota(priority);
            if self.in_flight[priority] < quota {
                if let Some(pkt) = self.priority_queues[priority].pop_front() {
                    return Some(pkt);
                }
            }
        }
        
        None
    }
    
    /// Stealth send: add random jitter to avoid timing analysis
    async fn stealth_send(&self, socket: &UdpSocket, packet: &[u8], addr: SocketAddr) {
        if self.stealth_mode {
            let jitter = rand::thread_rng().gen_range(self.stealth_jitter.clone());
            tokio::time::sleep(Duration::from_micros(jitter)).await;
        }
        socket.send_to(packet, addr).await.ok();
    }
}
```

### B.2.4 Reliability Layer

```rust
/// Selective Acknowledgment with Forward Error Correction
pub struct NadiReliability {
    /// Sent packets awaiting ACK
    sent_buffer: HashMap<u32, SentPacket>,
    
    /// Received packets (for ordering)
    recv_buffer: BTreeMap<u32, ReceivedPacket>,
    
    /// Next expected sequence number
    next_expected: u32,
    
    /// SACK ranges
    sack_ranges: Vec<Range<u32>>,
    
    /// FEC encoder (Reed-Solomon)
    fec_encoder: ReedSolomonEncoder,
    
    /// Retransmit timeout
    rto: Duration,
}

impl NadiReliability {
    /// Add FEC redundancy for critical packets
    /// 
    /// For THREAT_ALERT packets, we add 25% redundancy
    /// so packet can be recovered from any 4 of 5 fragments
    fn encode_with_fec(&self, data: &[u8], priority: u8) -> Vec<Vec<u8>> {
        let redundancy = match priority {
            7 => 0.25,      // 25% for critical
            5..=6 => 0.15,  // 15% for high
            _ => 0.0,       // No FEC for low priority
        };
        
        if redundancy > 0.0 {
            self.fec_encoder.encode(data, redundancy)
        } else {
            vec![data.to_vec()]
        }
    }
}
```

### B.2.5 Onion Routing (Optional)

```rust
/// NADI Onion Routing for anonymous threat sharing
/// 
/// When a peer wants to share a threat anonymously:
/// 1. Select 3 relay nodes from peer list
/// 2. Create layered encryption (like Tor)
/// 3. Route through relays
/// 
/// This prevents even TERAS operators from knowing
/// which device originally detected a threat.
pub struct OnionRouter {
    /// Our node's key pair
    node_key: KeyPair,
    
    /// Known relay nodes
    relays: Vec<RelayNode>,
    
    /// Circuits we've built
    circuits: HashMap<CircuitId, Circuit>,
}

impl OnionRouter {
    /// Build anonymous circuit through 3 relays
    pub async fn build_circuit(&mut self) -> Result<CircuitId, NadiError> {
        // Select 3 random relays with good reputation
        let selected = self.select_relays(3)?;
        
        // Build circuit incrementally (like Tor)
        let mut circuit = Circuit::new();
        
        for relay in &selected {
            // Extend circuit to next relay
            // Each extension is encrypted to that relay only
            circuit.extend(relay).await?;
        }
        
        let id = circuit.id();
        self.circuits.insert(id, circuit);
        Ok(id)
    }
    
    /// Send data through onion circuit
    pub async fn send_onion(&self, circuit_id: CircuitId, data: &[u8]) -> Result<(), NadiError> {
        let circuit = self.circuits.get(&circuit_id)
            .ok_or(NadiError::CircuitNotFound)?;
        
        // Wrap data in 3 layers of encryption
        let onion = circuit.wrap(data)?;
        
        // Send to first relay
        circuit.send(onion).await
    }
}
```

## B.3 NADI IMPLEMENTATION STRUCTURE

```
teras-nadi/                     # Separate crate for transport
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── packet.rs               # Packet structure and parsing
│   ├── handshake.rs            # Handshake protocol
│   ├── crypto.rs               # Encryption/decryption
│   ├── reliability.rs          # ACK, retransmit, FEC
│   ├── congestion.rs           # NADI-CC congestion control
│   ├── onion.rs                # Onion routing
│   ├── socket.rs               # UDP socket wrapper
│   ├── connection.rs           # Connection state machine
│   ├── peer.rs                 # Peer management
│   └── error.rs
├── tests/
│   ├── handshake_tests.rs
│   ├── reliability_tests.rs
│   ├── congestion_tests.rs
│   └── integration_tests.rs
└── benches/
    └── throughput_bench.rs
```

## B.4 NADI vs QUIC BENCHMARKS (TARGETS)

| Metric | QUIC (quinn) | NADI Target | Notes |
|--------|--------------|-------------|-------|
| Handshake latency | ~100ms | <50ms | 0-RTT when possible |
| Throughput (LAN) | 10 Gbps | 5 Gbps | We trade for security |
| Throughput (WAN) | 1 Gbps | 1 Gbps | Match |
| Packet overhead | 20-40 bytes | 32 bytes | Fixed header |
| Memory per conn | ~50 KB | <20 KB | Optimized |
| Dependencies | 159 crates | 0 external | Just teras-* |
| PQ-ready | No | Yes | ML-KEM + X25519 |
| Stealth mode | No | Yes | DPI evasion |
| Threat priority | No | Yes | 8 priority levels |

---

# PART C: REAL-WORLD THREAT CORPUS

## C.1 OVERVIEW

TERAS detection validation requires the **MOST COMPREHENSIVE** threat corpus ever assembled. This includes:

1. **Commercial threat feeds** (licensed)
2. **Open-source repositories** (free)
3. **Academic datasets** (research)
4. **Dark web sources** (through authorized channels)
5. **Synthetic generation** (for edge cases)

## C.2 THREAT INTELLIGENCE SOURCES

### C.2.1 Commercial Feeds (REQUIRED INTEGRATIONS)

| Source | Content | Volume | Integration |
|--------|---------|--------|-------------|
| **VirusTotal** | Malware hashes, URLs, domains | 2B+ samples | API (Enterprise) |
| **CrowdStrike Falcon X** | APT intelligence, IOCs | 50M+ IOCs | API |
| **Recorded Future** | Dark web, threat actors | Real-time | API |
| **Mandiant Advantage** | APT reports, IOCs | 1M+ | API |
| **Abuse.ch** | Malware, botnets | 10M+ | Free API |

### C.2.2 Open-Source Repositories

| Source | Content | URL |
|--------|---------|-----|
| **MalwareBazaar** | Malware samples | bazaar.abuse.ch |
| **VirusShare** | Malware corpus | virusshare.com |
| **theZoo** | Live malware | github.com/ytisf/theZoo |
| **Malware-Traffic-Analysis** | PCAPs | malware-traffic-analysis.net |
| **PhishTank** | Phishing URLs | phishtank.org |
| **URLhaus** | Malicious URLs | urlhaus.abuse.ch |
| **Feodo Tracker** | C2 servers | feodotracker.abuse.ch |
| **YARA Rules** | Detection rules | github.com/Yara-Rules |

### C.2.3 Academic Datasets

| Dataset | Content | Size |
|---------|---------|------|
| **Drebin** | Android malware | 5,560 samples |
| **AMD** | Android malware | 24,000 samples |
| **Androzoo** | Android apps | 20M+ apps |
| **EMBER** | PE malware | 1.1M samples |
| **SOREL-20M** | PE malware | 20M samples |
| **CIC-Darknet2020** | Dark web traffic | 100GB |
| **CICIDS2017** | Intrusion detection | 80GB |

### C.2.4 Dark Web Integration (AUTHORIZED)

```rust
/// Dark Web Threat Intelligence Collector
/// 
/// LEGAL NOTICE: This component ONLY:
/// 1. Collects IOCs (hashes, domains, IPs) - NOT actual malware
/// 2. Operates through authorized threat intel partnerships
/// 3. Does not access illegal marketplaces directly
/// 4. Complies with all applicable laws
/// 
/// Partners that provide dark web intelligence:
/// - Recorded Future (legal, commercial)
/// - DarkOwl (legal, commercial)
/// - Flashpoint (legal, commercial)
/// - Intel471 (legal, commercial)
pub struct DarkWebCollector {
    /// Authorized API clients
    recorded_future: RecordedFutureClient,
    darkowl: DarkOwlClient,
    flashpoint: FlashpointClient,
    
    /// Collected IOCs (not actual malware)
    iocs: IocDatabase,
}

impl DarkWebCollector {
    /// Collect dark web IOCs through authorized channels
    /// 
    /// This fetches:
    /// - Malware hashes discussed on forums
    /// - C2 domains being traded
    /// - New exploit announcements
    /// - Credential leak indicators
    /// 
    /// We do NOT:
    /// - Download actual malware
    /// - Access illegal marketplaces
    /// - Participate in illegal activities
    pub async fn collect(&mut self) -> Result<Vec<Ioc>, CollectorError> {
        let mut iocs = Vec::new();
        
        // Recorded Future - dark web monitoring
        iocs.extend(self.recorded_future.get_dark_web_iocs().await?);
        
        // DarkOwl - dark web search
        iocs.extend(self.darkowl.search_threat_indicators().await?);
        
        // Flashpoint - threat actor tracking
        iocs.extend(self.flashpoint.get_threat_actor_iocs().await?);
        
        // Deduplicate and validate
        self.validate_and_store(iocs).await
    }
}
```

## C.3 CORPUS MANAGEMENT SYSTEM

### C.3.1 teras-corpus Crate Structure

```
teras-corpus/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── collectors/
│   │   ├── mod.rs
│   │   ├── virustotal.rs
│   │   ├── malwarebazaar.rs
│   │   ├── abuse_ch.rs
│   │   ├── academic.rs
│   │   └── darkweb.rs
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── sample_store.rs      # Encrypted malware storage
│   │   ├── ioc_store.rs         # IOC database
│   │   └── metadata.rs          # Sample metadata
│   ├── validation/
│   │   ├── mod.rs
│   │   ├── hash_validator.rs    # Verify sample integrity
│   │   ├── family_classifier.rs # Classify malware family
│   │   └── detonation.rs        # Sandbox execution
│   └── export/
│       ├── mod.rs
│       ├── yara.rs              # Export as YARA rules
│       └── stix.rs              # Export as STIX 2.1
├── tests/
└── data/
    └── README.md                # Instructions for obtaining samples
```

### C.3.2 Sample Storage (Encrypted)

```rust
/// Encrypted malware sample storage
/// 
/// All samples are:
/// 1. Encrypted at rest (AES-256-GCM)
/// 2. Indexed by SHA-256
/// 3. Stored with full metadata
/// 4. Access logged via teras-jejak
pub struct SampleStore {
    /// Storage path
    path: PathBuf,
    
    /// Encryption key (derived from HSM)
    key: Secret<[u8; 32]>,
    
    /// Sample index
    index: SampleIndex,
}

impl SampleStore {
    /// Store a malware sample
    pub fn store(&mut self, sample: &[u8], metadata: SampleMetadata) -> Result<SampleId, StoreError> {
        let hash = sha256(sample);
        
        // Check for duplicate
        if self.index.contains(&hash) {
            return Ok(SampleId(hash));
        }
        
        // Encrypt sample
        let encrypted = self.encrypt(sample)?;
        
        // Store to disk
        let path = self.path.join(hex::encode(&hash));
        std::fs::write(&path, &encrypted)?;
        
        // Update index
        self.index.insert(hash, metadata);
        
        // Audit log
        audit_log!(
            action = "sample_stored",
            hash = hex::encode(&hash),
            family = metadata.family,
            source = metadata.source,
            "Malware sample stored"
        );
        
        Ok(SampleId(hash))
    }
    
    /// Retrieve sample for analysis (requires elevated permission)
    pub fn retrieve(&self, id: &SampleId, permission: &Permission) -> Result<Vec<u8>, StoreError> {
        // Verify permission
        if !permission.can_access_samples() {
            return Err(StoreError::PermissionDenied);
        }
        
        // Read encrypted data
        let path = self.path.join(hex::encode(&id.0));
        let encrypted = std::fs::read(&path)?;
        
        // Decrypt
        let sample = self.decrypt(&encrypted)?;
        
        // Audit log
        audit_log!(
            action = "sample_accessed",
            hash = hex::encode(&id.0),
            accessor = permission.identity(),
            "Malware sample accessed"
        );
        
        Ok(sample)
    }
}
```

### C.3.3 Corpus Statistics (TARGET)

| Category | Target Count | Sources |
|----------|--------------|---------|
| **Malware hashes (SHA-256)** | 50,000,000+ | VT, MB, VS, Academic |
| **Malicious domains** | 10,000,000+ | PhishTank, URLhaus, Recorded Future |
| **C2 IPs** | 1,000,000+ | Feodo, abuse.ch, CrowdStrike |
| **Phishing URLs** | 5,000,000+ | PhishTank, OpenPhish |
| **YARA rules** | 10,000+ | Yara-Rules, custom |
| **Android malware samples** | 100,000+ | Androzoo, Drebin, AMD |
| **Windows malware samples** | 500,000+ | EMBER, SOREL, MalwareBazaar |
| **Network IOCs (PCAPs)** | 10,000+ | CICIDS, Malware-Traffic |
| **Dark web IOCs** | 1,000,000+ | Recorded Future, DarkOwl |

---

# PART D: REVOLUTIONARY DIFFERENTIATORS

## D.1 HOMOMORPHIC THREAT AGGREGATION

### D.1.1 Overview

**World-first**: Aggregate threat statistics across the entire TERAS network WITHOUT revealing individual device sightings.

```
TRADITIONAL APPROACH:
Device A: "I saw malware hash X"  ──▶  Server: "Device A saw X"
                                        (Privacy leak!)

TERAS APPROACH (Homomorphic):
Device A: Encrypt(1, public_key)  ──┐
Device B: Encrypt(1, public_key)  ──┼──▶  Server: Sum(ciphertexts)
Device C: Encrypt(0, public_key)  ──┘            = Encrypt(2, public_key)
                                                  
                                        Server knows: "2 devices saw threat"
                                        Server CANNOT know: "which devices"
```

### D.1.2 Implementation

```rust
/// Homomorphic threat counter using Paillier encryption
/// 
/// Properties:
/// - Additive homomorphism: E(a) * E(b) = E(a + b)
/// - Semantic security: Ciphertexts reveal nothing about plaintexts
/// - Threshold decryption: Requires k-of-n servers to decrypt
pub struct HomomorphicCounter {
    /// Paillier public key (shared by all devices)
    public_key: PaillierPublicKey,
    
    /// Our contribution (encrypted)
    local_count: Ciphertext,
}

impl HomomorphicCounter {
    /// Report threat sighting (without revealing identity)
    pub fn report_sighting(&mut self, threat_id: &ThreatId) -> Ciphertext {
        // Encrypt "1" to indicate we saw this threat
        let one = BigUint::one();
        let encrypted = self.public_key.encrypt(&one);
        
        // Create proof that we encrypted 0 or 1 (not arbitrary number)
        // This prevents inflation attacks
        let proof = self.create_zero_one_proof(&encrypted);
        
        Ciphertext {
            value: encrypted,
            proof,
            threat_id: threat_id.clone(),
        }
    }
    
    /// Aggregate counts from multiple devices
    /// 
    /// Due to homomorphism, we can sum encrypted values
    /// WITHOUT decrypting individual contributions
    pub fn aggregate(ciphertexts: &[Ciphertext]) -> Ciphertext {
        let mut sum = ciphertexts[0].value.clone();
        
        for ct in &ciphertexts[1..] {
            // Homomorphic addition: multiply ciphertexts
            sum = (&sum * &ct.value) % &ct.public_key.n_squared;
        }
        
        Ciphertext {
            value: sum,
            proof: AggregateProof::new(ciphertexts),
            threat_id: ciphertexts[0].threat_id.clone(),
        }
    }
}
```

## D.2 DIFFERENTIAL PRIVACY FOR IOC SHARING

### D.2.1 Overview

**Mathematically provable** privacy guarantees when sharing threat intelligence.

```
DIFFERENTIAL PRIVACY GUARANTEE:

For any two neighboring datasets D and D' (differing in one device):
  Pr[M(D) ∈ S] ≤ e^ε × Pr[M(D') ∈ S]

Where:
- M is our mechanism (threat sharing)
- ε is the privacy budget (smaller = more private)
- S is any set of outputs

This means: An attacker cannot determine if a specific device
contributed to the aggregate, even with unlimited computing power.
```

### D.2.2 Implementation

```rust
/// Differential Privacy for threat intelligence sharing
/// 
/// Uses the Laplace mechanism for count queries.
pub struct DifferentiallyPrivateSharing {
    /// Privacy budget (epsilon)
    /// Lower = more privacy, less accuracy
    /// TERAS default: 0.1 (very private)
    epsilon: f64,
    
    /// Sensitivity of our queries
    /// For counting queries, sensitivity = 1
    sensitivity: f64,
    
    /// Privacy accountant (tracks total budget spent)
    accountant: PrivacyAccountant,
}

impl DifferentiallyPrivateSharing {
    /// Share threat count with differential privacy
    /// 
    /// Adds calibrated Laplace noise to the true count.
    pub fn share_count(&mut self, true_count: u64) -> Result<u64, PrivacyError> {
        // Check if we have budget remaining
        self.accountant.check_budget(self.epsilon)?;
        
        // Calculate noise scale: sensitivity / epsilon
        let scale = self.sensitivity / self.epsilon;
        
        // Sample from Laplace distribution
        let noise = laplace_sample(0.0, scale);
        
        // Add noise to true count
        let noisy_count = (true_count as f64 + noise).max(0.0) as u64;
        
        // Account for privacy spent
        self.accountant.spend(self.epsilon);
        
        Ok(noisy_count)
    }
    
    /// Share threat histogram with differential privacy
    /// 
    /// For multiple categories, we use the sparse vector technique
    /// to answer many queries with less total privacy cost.
    pub fn share_histogram(&mut self, histogram: &HashMap<ThreatCategory, u64>) -> Result<HashMap<ThreatCategory, u64>, PrivacyError> {
        let mut noisy = HashMap::new();
        
        // Use sparse vector technique for efficiency
        let threshold = self.calculate_threshold(histogram.len());
        
        for (category, &count) in histogram {
            // Only share if above noisy threshold
            // This reduces privacy cost for sparse data
            let noisy_count = self.share_count(count)?;
            if noisy_count > threshold {
                noisy.insert(category.clone(), noisy_count);
            }
        }
        
        Ok(noisy)
    }
}
```

## D.3 FEDERATED LEARNING FOR ANOMALY DETECTION

### D.3.1 Overview

**Train machine learning models for threat detection WITHOUT sharing raw data.**

```
TRADITIONAL ML:
Device A: Raw data ──┐
Device B: Raw data ──┼──▶ Central Server ──▶ Trained Model
Device C: Raw data ──┘    (Privacy leak!)

FEDERATED LEARNING:
Device A: Local model update ──┐
Device B: Local model update ──┼──▶ Server: Aggregate updates ──▶ Global Model
Device C: Local model update ──┘    (No raw data leaves device!)
```

### D.3.2 Implementation

```rust
/// Federated Learning for threat detection models
/// 
/// Each device:
/// 1. Downloads global model
/// 2. Trains on local data
/// 3. Sends model UPDATE (not data)
/// 4. Server aggregates updates (FedAvg)
/// 
/// Privacy enhanced with:
/// - Differential privacy on updates
/// - Secure aggregation
/// - Gradient compression
pub struct FederatedLearning {
    /// Global model (downloaded from server)
    global_model: ThreatDetectionModel,
    
    /// Local training data (never leaves device)
    local_data: LocalDataset,
    
    /// Privacy settings
    dp_config: DpConfig,
    
    /// Secure aggregation keys
    secure_agg: SecureAggregation,
}

impl FederatedLearning {
    /// Train on local data and produce update
    pub fn local_train(&mut self) -> Result<ModelUpdate, FLError> {
        // Clone global model for local training
        let mut local_model = self.global_model.clone();
        
        // Train for configured epochs
        for epoch in 0..self.config.local_epochs {
            for batch in self.local_data.batches() {
                let loss = local_model.train_step(&batch);
            }
        }
        
        // Compute update (difference from global)
        let update = local_model.diff(&self.global_model);
        
        // Clip gradients (for DP)
        let clipped = self.clip_gradients(update);
        
        // Add noise for differential privacy
        let noisy = self.add_dp_noise(clipped);
        
        // Encrypt for secure aggregation
        let encrypted = self.secure_agg.encrypt(noisy)?;
        
        Ok(encrypted)
    }
    
    /// Securely aggregate updates from multiple devices
    /// 
    /// Uses MPC so server only learns the sum,
    /// not individual updates.
    pub fn aggregate_updates(updates: &[EncryptedUpdate]) -> GlobalUpdate {
        // Threshold decryption (requires k-of-n servers)
        let decrypted = SecureAggregation::aggregate(updates);
        
        // Average the updates
        let averaged = decrypted.scale(1.0 / updates.len() as f32);
        
        averaged
    }
}

/// Threat detection model architecture
/// 
/// Optimized for mobile (small, fast, accurate)
pub struct ThreatDetectionModel {
    /// Embedding layer for app features
    embedding: Embedding,
    
    /// LSTM for sequence analysis (permissions, API calls)
    lstm: LSTM,
    
    /// Attention for important features
    attention: Attention,
    
    /// Classification head
    classifier: Linear,
}

impl ThreatDetectionModel {
    /// Inference on device
    /// 
    /// Target: <10ms on mobile
    pub fn predict(&self, app: &AppFeatures) -> ThreatPrediction {
        let embedded = self.embedding.forward(&app.features);
        let sequence = self.lstm.forward(&embedded);
        let attended = self.attention.forward(&sequence);
        let logits = self.classifier.forward(&attended);
        
        ThreatPrediction::from_logits(logits)
    }
}
```

## D.4 HARDWARE-BACKED CANARIES

### D.4.1 Overview

**Tamper-proof tripwires using Secure Enclave / TrustZone.**

Traditional canaries can be bypassed by:
1. Detecting canary check code
2. Patching canary values
3. Hooking canary functions

Hardware-backed canaries are stored in:
- iOS: Secure Enclave
- Android: TrustZone / StrongBox
- Desktop: TPM 2.0

**Cannot be accessed or modified even with root/jailbreak.**

### D.4.2 Implementation

```rust
/// Hardware-backed canary system
/// 
/// Canary values are:
/// 1. Generated in secure hardware
/// 2. Stored in secure hardware
/// 3. Verified by secure hardware
/// 
/// Even with full device compromise, attacker cannot:
/// - Read canary values
/// - Modify canary values
/// - Bypass canary checks
pub struct HardwareCanary {
    /// Platform-specific secure element
    secure_element: Box<dyn SecureElement>,
    
    /// Canary slots (each has unique purpose)
    slots: [CanarySlot; 16],
}

impl HardwareCanary {
    /// Initialize canary in secure hardware
    /// 
    /// This generates a random value inside the secure element.
    /// The value NEVER leaves the secure element.
    pub fn initialize(&mut self, slot: usize) -> Result<(), CanaryError> {
        // Generate random canary in secure element
        self.secure_element.generate_canary(slot)?;
        
        // Store hash of expected state alongside canary
        let state_hash = self.compute_protected_state_hash();
        self.secure_element.store_state_hash(slot, state_hash)?;
        
        audit_log!(
            action = "canary_initialized",
            slot = slot,
            "Hardware canary initialized"
        );
        
        Ok(())
    }
    
    /// Verify canary in secure hardware
    /// 
    /// Returns true only if:
    /// 1. Canary value is intact (verified inside secure element)
    /// 2. Protected state hash matches
    pub fn verify(&self, slot: usize) -> CanaryStatus {
        // Ask secure element to verify canary
        // The value itself never leaves the secure element
        let canary_ok = self.secure_element.verify_canary(slot);
        
        // Verify state hash
        let current_hash = self.compute_protected_state_hash();
        let expected_hash = self.secure_element.get_state_hash(slot);
        let state_ok = current_hash == expected_hash;
        
        match (canary_ok, state_ok) {
            (true, true) => CanaryStatus::Intact,
            (false, _) => CanaryStatus::Triggered { reason: "Canary value modified" },
            (_, false) => CanaryStatus::Triggered { reason: "Protected state modified" },
        }
    }
    
    /// Compute hash of critical protected state
    /// 
    /// Includes:
    /// - Code signature
    /// - Critical function addresses
    /// - Security settings
    fn compute_protected_state_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Hash code signature
        hasher.update(&self.get_code_signature());
        
        // Hash critical function addresses
        for func in CRITICAL_FUNCTIONS {
            hasher.update(&func.address().to_le_bytes());
        }
        
        // Hash security settings
        hasher.update(&self.get_security_settings());
        
        hasher.finalize().into()
    }
}

/// Platform-specific secure element abstraction
#[cfg(target_os = "ios")]
mod secure_element {
    /// iOS Secure Enclave implementation
    pub struct SecureEnclaveElement {
        // Uses Security.framework
    }
    
    impl SecureElement for SecureEnclaveElement {
        fn generate_canary(&self, slot: usize) -> Result<(), Error> {
            // Use kSecAttrTokenIDSecureEnclave
            // Generate and store key that acts as canary
        }
        
        fn verify_canary(&self, slot: usize) -> bool {
            // Attempt to use the key
            // If key is intact, operation succeeds
        }
    }
}

#[cfg(target_os = "android")]
mod secure_element {
    /// Android TrustZone / StrongBox implementation
    pub struct TrustZoneElement {
        // Uses Android Keystore with StrongBox
    }
    
    impl SecureElement for TrustZoneElement {
        fn generate_canary(&self, slot: usize) -> Result<(), Error> {
            // Use KeyProperties.PURPOSE_SIGN
            // with setIsStrongBoxBacked(true)
        }
        
        fn verify_canary(&self, slot: usize) -> bool {
            // Attempt to sign with the key
            // Verify signature matches expected
        }
    }
}
```

---

# PART E: UPDATED PHASE 10 SCOPE

## E.1 REVISED IMPLEMENTATION ORDER

Given the expanded scope, Phase 10 is now split into sub-phases:

```
PHASE 10.0: PREREQUISITES
├── Update teras-jejak with audit_log! macro
├── Verify all existing crates compile and pass tests
└── Set up test infrastructure

PHASE 10.1: NADI TRANSPORT PROTOCOL
├── teras-nadi crate creation
├── Packet structure and parsing
├── Handshake protocol
├── Reliability layer (ACK, retransmit, FEC)
├── Congestion control (NADI-CC)
├── Onion routing (optional feature)
└── Benchmarks proving superiority to QUIC

PHASE 10.2: CORE MENARA (6 PILLARS)
├── Pillar 1: Permission Auditor
├── Pillar 2: IOC Matcher  
├── Pillar 3: Power Anomaly Detector
├── Pillar 4: Sensor Fusion
├── Pillar 5: Timing Analysis
└── Pillar 6: Canary System

PHASE 10.3: REVOLUTIONARY FEATURES
├── Homomorphic threat aggregation
├── Differential privacy for IOC sharing
├── Federated learning infrastructure
└── Hardware-backed canaries

PHASE 10.4: KERISMESH + PINQ
├── KerisMesh over NADI
├── PINQ query language
├── Threat sharing protocol
└── Reputation system

PHASE 10.5: CORPUS INTEGRATION
├── teras-corpus crate creation
├── Commercial feed integrations
├── Open-source repository ingestion
├── Dark web IOC collection (through authorized partners)
└── Validation test suite with real threats
```

## E.2 TEST REQUIREMENTS (REVISED)

| Sub-phase | Unit Tests | Integration Tests | Benchmarks |
|-----------|------------|-------------------|------------|
| 10.0 | 10 | 5 | 0 |
| 10.1 (NADI) | 150 | 30 | 20 |
| 10.2 (Pillars) | 200 | 40 | 15 |
| 10.3 (Revolutionary) | 100 | 25 | 10 |
| 10.4 (KerisMesh) | 80 | 20 | 10 |
| 10.5 (Corpus) | 50 | 30 | 5 |
| **TOTAL** | **590** | **150** | **60** |

---

# CONFIRMATION REQUIRED

Before proceeding, acknowledge:

1. Phase 10 scope has expanded from ~100 tests to ~800 tests
2. New crates: teras-nadi, teras-corpus (in addition to teras-menara)
3. NADI transport must benchmark BETTER than quinn/QUIC
4. Revolutionary features are MANDATORY, not optional
5. Real threat corpus integration is required
6. Estimated timeline: 4-6x original estimate

If you understand and accept these requirements, proceed with:

"I acknowledge the TERAS Phase 10 Revolutionary Addendum v1.0.0.
Beginning with Phase 10.0: Prerequisites (teras-jejak macro update)."
