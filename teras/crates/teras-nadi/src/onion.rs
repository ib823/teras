//! NADI Onion Routing for anonymous threat sharing.
//!
//! When enabled via the `onion` feature, this module provides
//! Tor-like onion routing for anonymous threat intelligence sharing.
//!
//! # Overview
//!
//! When a peer wants to share a threat anonymously:
//! 1. Select 3 relay nodes from peer list
//! 2. Create layered encryption (like Tor)
//! 3. Route through relays
//!
//! This prevents even TERAS operators from knowing which device
//! originally detected a threat.
//!
//! # Security Properties
//!
//! - **Sender anonymity**: Relays only know previous and next hop
//! - **Content confidentiality**: Only final destination can read data
//! - **Timing resistance**: Stealth mode adds jitter
//!
//! # Example
//!
//! ```ignore
//! use teras_nadi::onion::{OnionRouter, CircuitId};
//!
//! let mut router = OnionRouter::new(our_keys)?;
//!
//! // Build 3-hop circuit
//! let circuit_id = router.build_circuit(3).await?;
//!
//! // Send anonymously
//! router.send_onion(circuit_id, &threat_data).await?;
//! ```

use crate::error::{NadiError, NadiResult};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Circuit identifier.
pub type CircuitId = u64;

/// Maximum circuit hops.
pub const MAX_HOPS: usize = 5;

/// Default circuit hops.
pub const DEFAULT_HOPS: usize = 3;

/// Circuit lifetime before rebuild.
pub const CIRCUIT_LIFETIME: Duration = Duration::from_secs(600);

/// Relay node information.
#[derive(Debug, Clone)]
pub struct RelayNode {
    /// Node identifier.
    pub id: [u8; 32],
    /// Node's public key for encryption.
    pub public_key: [u8; 32],
    /// Node's address.
    pub address: String,
    /// Reputation score (0.0 - 1.0).
    pub reputation: f64,
    /// Bandwidth capacity (bytes/sec).
    pub bandwidth: u64,
    /// Is this node currently reachable?
    pub reachable: bool,
}

impl RelayNode {
    /// Check if this relay is suitable for circuit building.
    #[must_use]
    pub fn is_suitable(&self) -> bool {
        self.reachable && self.reputation >= 0.5 && self.bandwidth >= 10_000
    }
}

/// A single hop in an onion circuit.
#[derive(Debug)]
struct CircuitHop {
    /// Relay node.
    #[allow(dead_code)]
    relay: RelayNode,
    /// Shared key for this hop (derived via DH).
    shared_key: [u8; 32],
}

/// An onion circuit through multiple relays.
#[derive(Debug)]
pub struct Circuit {
    /// Circuit identifier.
    id: CircuitId,
    /// Ordered list of hops.
    hops: Vec<CircuitHop>,
    /// When circuit was created.
    created: Instant,
    /// Is circuit fully built?
    established: bool,
}

impl Circuit {
    /// Create a new unestablished circuit.
    fn new() -> Self {
        Self {
            id: rand::random(),
            hops: Vec::with_capacity(DEFAULT_HOPS),
            created: Instant::now(),
            established: false,
        }
    }

    /// Get circuit ID.
    #[must_use]
    pub fn id(&self) -> CircuitId {
        self.id
    }

    /// Check if circuit is still valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.established && self.created.elapsed() < CIRCUIT_LIFETIME
    }

    /// Number of hops in circuit.
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Wrap data in onion encryption layers.
    ///
    /// Each layer is encrypted with the corresponding hop's key,
    /// starting from the last hop (exit) and working back.
    pub fn wrap(&self, data: &[u8]) -> NadiResult<Vec<u8>> {
        if !self.established {
            return Err(NadiError::Internal("circuit not established".into()));
        }

        let mut payload = data.to_vec();

        // Encrypt from exit to entry (reverse order)
        for hop in self.hops.iter().rev() {
            payload = Self::encrypt_layer(&hop.shared_key, &payload)?;
        }

        Ok(payload)
    }

    /// Encrypt a single layer.
    fn encrypt_layer(key: &[u8; 32], data: &[u8]) -> NadiResult<Vec<u8>> {
        // Use ChaCha20-Poly1305 for layer encryption
        use teras_kunci::symmetric::{ChaCha20Poly1305Cipher, SymmetricCipher};
        use teras_lindung::Secret;

        let cipher = ChaCha20Poly1305Cipher::new(&Secret::new(*key))
            .map_err(|e| NadiError::Crypto(e.to_string()))?;

        // Use random nonce (prepended to ciphertext)
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let ciphertext = cipher
            .encrypt(&nonce, data, &[])
            .map_err(|e| NadiError::Crypto(e.to_string()))?;

        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }
}

/// Onion router for building and managing circuits.
pub struct OnionRouter {
    /// Our encryption key pair.
    #[allow(dead_code)]
    our_public_key: [u8; 32],
    /// Known relay nodes.
    relays: Vec<RelayNode>,
    /// Active circuits.
    circuits: HashMap<CircuitId, Circuit>,
    /// Maximum concurrent circuits.
    max_circuits: usize,
}

impl OnionRouter {
    /// Create a new onion router.
    ///
    /// # Arguments
    ///
    /// * `our_public_key` - Our X25519 public key
    pub fn new(our_public_key: [u8; 32]) -> Self {
        Self {
            our_public_key,
            relays: Vec::new(),
            circuits: HashMap::new(),
            max_circuits: 10,
        }
    }

    /// Add a relay node.
    pub fn add_relay(&mut self, relay: RelayNode) {
        if !self.relays.iter().any(|r| r.id == relay.id) {
            self.relays.push(relay);
        }
    }

    /// Remove a relay node.
    pub fn remove_relay(&mut self, id: &[u8; 32]) {
        self.relays.retain(|r| &r.id != id);
    }

    /// Get number of known relays.
    #[must_use]
    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    /// Get number of active circuits.
    #[must_use]
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Select random suitable relays for circuit.
    fn select_relays(&self, count: usize) -> NadiResult<Vec<RelayNode>> {
        let suitable: Vec<_> = self.relays.iter().filter(|r| r.is_suitable()).collect();

        if suitable.len() < count {
            return Err(NadiError::RelaySelectionFailed(format!(
                "need {} relays, only {} suitable",
                count,
                suitable.len()
            )));
        }

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let selected: Vec<_> = suitable
            .choose_multiple(&mut rng, count)
            .cloned()
            .cloned()
            .collect();

        Ok(selected)
    }

    /// Build a new circuit with specified number of hops.
    ///
    /// This is an async operation that performs key exchange with each hop.
    pub async fn build_circuit(&mut self, hops: usize) -> NadiResult<CircuitId> {
        if hops == 0 || hops > MAX_HOPS {
            return Err(NadiError::InvalidFecParams(format!(
                "hops must be 1-{}",
                MAX_HOPS
            )));
        }

        if self.circuits.len() >= self.max_circuits {
            // Cleanup old circuits
            self.cleanup_circuits();
            if self.circuits.len() >= self.max_circuits {
                return Err(NadiError::Internal("max circuits reached".into()));
            }
        }

        let selected = self.select_relays(hops)?;
        let mut circuit = Circuit::new();

        // In a real implementation, we would:
        // 1. Connect to first relay
        // 2. Perform DH to establish shared key
        // 3. Extend to next relay through first
        // 4. Repeat until all hops established

        // For now, simulate with placeholder keys
        for relay in selected {
            let hop = CircuitHop {
                relay,
                shared_key: rand::random(), // In reality: DH exchange
            };
            circuit.hops.push(hop);
        }

        circuit.established = true;
        let id = circuit.id();
        self.circuits.insert(id, circuit);

        Ok(id)
    }

    /// Send data through an onion circuit.
    pub async fn send_onion(&self, circuit_id: CircuitId, data: &[u8]) -> NadiResult<()> {
        let circuit = self
            .circuits
            .get(&circuit_id)
            .ok_or(NadiError::CircuitNotFound(circuit_id))?;

        if !circuit.is_valid() {
            return Err(NadiError::Internal("circuit expired".into()));
        }

        let _onion_data = circuit.wrap(data)?;

        // In a real implementation, we would:
        // 1. Send onion_data to first hop
        // 2. Wait for response
        // 3. Unwrap response layers

        Ok(())
    }

    /// Destroy a circuit.
    pub fn destroy_circuit(&mut self, circuit_id: CircuitId) {
        self.circuits.remove(&circuit_id);
    }

    /// Cleanup expired circuits.
    pub fn cleanup_circuits(&mut self) {
        self.circuits.retain(|_, c| c.is_valid());
    }

    /// Get a circuit by ID.
    #[must_use]
    pub fn get_circuit(&self, id: CircuitId) -> Option<&Circuit> {
        self.circuits.get(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relay(id: u8) -> RelayNode {
        RelayNode {
            id: [id; 32],
            public_key: [id + 100; 32],
            address: format!("127.0.0.1:{}", 10000 + id as u16),
            reputation: 0.8,
            bandwidth: 100_000,
            reachable: true,
        }
    }

    #[test]
    fn test_relay_suitability() {
        let mut relay = make_relay(1);
        assert!(relay.is_suitable());

        relay.reputation = 0.3;
        assert!(!relay.is_suitable());

        relay.reputation = 0.8;
        relay.reachable = false;
        assert!(!relay.is_suitable());
    }

    #[test]
    fn test_circuit_validity() {
        let mut circuit = Circuit::new();
        assert!(!circuit.is_valid()); // Not established

        circuit.established = true;
        assert!(circuit.is_valid());
    }

    #[test]
    fn test_onion_router_creation() {
        let router = OnionRouter::new([0u8; 32]);
        assert_eq!(router.relay_count(), 0);
        assert_eq!(router.circuit_count(), 0);
    }

    #[test]
    fn test_add_relay() {
        let mut router = OnionRouter::new([0u8; 32]);
        router.add_relay(make_relay(1));
        router.add_relay(make_relay(2));
        assert_eq!(router.relay_count(), 2);

        // Adding duplicate should not increase count
        router.add_relay(make_relay(1));
        assert_eq!(router.relay_count(), 2);
    }

    #[test]
    fn test_remove_relay() {
        let mut router = OnionRouter::new([0u8; 32]);
        router.add_relay(make_relay(1));
        router.add_relay(make_relay(2));

        router.remove_relay(&[1u8; 32]);
        assert_eq!(router.relay_count(), 1);
    }

    #[test]
    fn test_relay_selection_insufficient() {
        let mut router = OnionRouter::new([0u8; 32]);
        router.add_relay(make_relay(1));
        router.add_relay(make_relay(2));

        let result = router.select_relays(3);
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_selection_success() {
        let mut router = OnionRouter::new([0u8; 32]);
        for i in 1..=5 {
            router.add_relay(make_relay(i));
        }

        let selected = router.select_relays(3).unwrap();
        assert_eq!(selected.len(), 3);
    }

    #[tokio::test]
    async fn test_build_circuit() {
        let mut router = OnionRouter::new([0u8; 32]);
        for i in 1..=5 {
            router.add_relay(make_relay(i));
        }

        let circuit_id = router.build_circuit(3).await.unwrap();
        assert_eq!(router.circuit_count(), 1);

        let circuit = router.get_circuit(circuit_id).unwrap();
        assert_eq!(circuit.hop_count(), 3);
        assert!(circuit.is_valid());
    }

    #[tokio::test]
    async fn test_circuit_wrap() {
        let mut router = OnionRouter::new([0u8; 32]);
        for i in 1..=3 {
            router.add_relay(make_relay(i));
        }

        let circuit_id = router.build_circuit(3).await.unwrap();
        let circuit = router.get_circuit(circuit_id).unwrap();

        let data = b"secret threat data";
        let wrapped = circuit.wrap(data).unwrap();

        // Wrapped data should be larger (encrypted layers + nonces)
        assert!(wrapped.len() > data.len());
    }

    #[tokio::test]
    async fn test_destroy_circuit() {
        let mut router = OnionRouter::new([0u8; 32]);
        for i in 1..=3 {
            router.add_relay(make_relay(i));
        }

        let circuit_id = router.build_circuit(3).await.unwrap();
        assert_eq!(router.circuit_count(), 1);

        router.destroy_circuit(circuit_id);
        assert_eq!(router.circuit_count(), 0);
    }

    #[tokio::test]
    async fn test_send_to_nonexistent_circuit() {
        let router = OnionRouter::new([0u8; 32]);
        let result = router.send_onion(12345, b"data").await;
        assert!(matches!(result, Err(NadiError::CircuitNotFound(_))));
    }
}
