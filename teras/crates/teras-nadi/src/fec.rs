//! Forward Error Correction using Reed-Solomon codes.
//!
//! Provides redundancy for critical packets to ensure delivery
//! even with packet loss.
//!
//! # Redundancy Levels
//!
//! - Critical (priority 7): 25% redundancy (4 data + 1 parity)
//! - High (priority 5-6): 15% redundancy
//! - Normal and below: No FEC
//!
//! # Implementation
//!
//! Uses systematic Reed-Solomon encoding over GF(2^8).
//! This is a simplified implementation suitable for small block sizes.

use crate::error::{NadiError, NadiResult};
use crate::packet::Priority;

/// Maximum number of data shards.
pub const MAX_DATA_SHARDS: usize = 255;

/// Maximum number of parity shards.
pub const MAX_PARITY_SHARDS: usize = 255;

/// Default shard size (MTU-friendly).
pub const DEFAULT_SHARD_SIZE: usize = 1400;

/// FEC configuration for a priority level.
#[derive(Debug, Clone, Copy)]
pub struct FecConfig {
    /// Number of data shards.
    pub data_shards: usize,
    /// Number of parity shards.
    pub parity_shards: usize,
}

impl FecConfig {
    /// Get FEC configuration for a priority level.
    ///
    /// Returns `None` if no FEC is needed for this priority.
    #[must_use]
    pub fn for_priority(priority: Priority) -> Option<Self> {
        match priority {
            Priority::Critical => Some(Self {
                data_shards: 4,
                parity_shards: 1, // 25% redundancy
            }),
            Priority::VeryHigh | Priority::High => Some(Self {
                data_shards: 6,
                parity_shards: 1, // ~17% redundancy
            }),
            _ => None, // No FEC for lower priorities
        }
    }

    /// Total number of shards (data + parity).
    #[must_use]
    pub const fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Minimum shards required for recovery.
    #[must_use]
    pub const fn required_shards(&self) -> usize {
        self.data_shards
    }

    /// Redundancy ratio as a percentage.
    #[must_use]
    pub fn redundancy_percent(&self) -> f32 {
        (self.parity_shards as f32 / self.data_shards as f32) * 100.0
    }
}

/// Galois Field GF(2^8) operations.
///
/// Uses the standard polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
mod gf256 {
    /// Field polynomial.
    const POLY: u16 = 0x11D;

    /// Logarithm table.
    static LOG: once_cell::sync::Lazy<[u8; 256]> = once_cell::sync::Lazy::new(|| {
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0u8..255 {
            log[x as usize] = i;
            x <<= 1;
            if x >= 256 {
                x ^= POLY;
            }
        }
        log
    });

    /// Exponent table.
    static EXP: once_cell::sync::Lazy<[u8; 512]> = once_cell::sync::Lazy::new(|| {
        let mut exp = [0u8; 512];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            x <<= 1;
            if x >= 256 {
                x ^= POLY;
            }
        }
        // Duplicate for easy modulo
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        exp
    });

    /// Multiply two GF(2^8) elements.
    #[inline]
    pub fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
        }
    }

    /// Divide in GF(2^8).
    #[inline]
    #[allow(dead_code)]
    pub fn div(a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else if b == 0 {
            panic!("division by zero in GF(2^8)")
        } else {
            let log_a = LOG[a as usize] as usize;
            let log_b = LOG[b as usize] as usize;
            EXP[(log_a + 255 - log_b) % 255]
        }
    }

    /// Exponentiate in GF(2^8).
    #[inline]
    pub fn exp(i: usize) -> u8 {
        EXP[i % 255]
    }

    /// Multiplicative inverse in GF(2^8).
    #[inline]
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            panic!("inverse of zero in GF(2^8)")
        }
        EXP[(255 - LOG[a as usize] as usize) % 255]
    }
}

/// Reed-Solomon encoder.
#[derive(Debug, Clone)]
pub struct ReedSolomonEncoder {
    /// Configuration.
    config: FecConfig,
    /// Generator matrix (stored as (data_shards + parity_shards) x data_shards).
    generator: Vec<Vec<u8>>,
}

impl ReedSolomonEncoder {
    /// Create a new Reed-Solomon encoder.
    pub fn new(config: FecConfig) -> NadiResult<Self> {
        if config.data_shards == 0 {
            return Err(NadiError::InvalidFecParams("data_shards must be > 0".into()));
        }
        if config.data_shards > MAX_DATA_SHARDS {
            return Err(NadiError::InvalidFecParams(format!(
                "data_shards must be <= {}",
                MAX_DATA_SHARDS
            )));
        }
        if config.parity_shards > MAX_PARITY_SHARDS {
            return Err(NadiError::InvalidFecParams(format!(
                "parity_shards must be <= {}",
                MAX_PARITY_SHARDS
            )));
        }

        // Build Vandermonde matrix for generator
        let n = config.total_shards();
        let k = config.data_shards;
        let mut generator = vec![vec![0u8; k]; n];

        // Identity matrix for data shards (systematic encoding)
        for i in 0..k {
            generator[i][i] = 1;
        }

        // Vandermonde matrix for parity shards
        for i in 0..config.parity_shards {
            for j in 0..k {
                // Use primitive element powers
                let row = (k + i) as u8;
                let col = j as u8;
                generator[k + i][j] = if col == 0 { 1 } else { gf256::exp(row as usize * col as usize) };
            }
        }

        Ok(Self { config, generator })
    }

    /// Encode data into shards.
    ///
    /// Returns a vector of shards where the first `data_shards` are the
    /// original data and the remaining are parity shards.
    pub fn encode(&self, data: &[u8]) -> NadiResult<Vec<Vec<u8>>> {
        let shard_size = (data.len() + self.config.data_shards - 1) / self.config.data_shards;

        // Pad data to shard_size * data_shards
        let padded_len = shard_size * self.config.data_shards;
        let mut padded = vec![0u8; padded_len];
        padded[..data.len()].copy_from_slice(data);

        // Split into data shards
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.config.total_shards());
        for i in 0..self.config.data_shards {
            let start = i * shard_size;
            let end = start + shard_size;
            shards.push(padded[start..end].to_vec());
        }

        // Generate parity shards
        for i in 0..self.config.parity_shards {
            let parity_row = self.config.data_shards + i;
            let mut parity = vec![0u8; shard_size];

            for j in 0..self.config.data_shards {
                let coeff = self.generator[parity_row][j];
                if coeff != 0 {
                    for (k, byte) in shards[j].iter().enumerate() {
                        parity[k] ^= gf256::mul(coeff, *byte);
                    }
                }
            }

            shards.push(parity);
        }

        Ok(shards)
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> FecConfig {
        self.config
    }
}

/// Reed-Solomon decoder.
#[derive(Debug, Clone)]
pub struct ReedSolomonDecoder {
    /// Configuration.
    config: FecConfig,
}

impl ReedSolomonDecoder {
    /// Create a new Reed-Solomon decoder.
    pub fn new(config: FecConfig) -> Self {
        Self { config }
    }

    /// Decode shards back to original data.
    ///
    /// # Arguments
    ///
    /// * `shards` - Vector of (shard_index, shard_data) pairs
    /// * `original_len` - Original data length before encoding
    ///
    /// At least `data_shards` shards must be present for successful decoding.
    pub fn decode(
        &self,
        shards: &[(usize, Vec<u8>)],
        original_len: usize,
    ) -> NadiResult<Vec<u8>> {
        if shards.len() < self.config.data_shards {
            return Err(NadiError::FecDecodeFailed {
                received: shards.len(),
                required: self.config.data_shards,
            });
        }

        if shards.is_empty() {
            return Err(NadiError::FecDecodeFailed {
                received: 0,
                required: self.config.data_shards,
            });
        }

        let shard_size = shards[0].1.len();

        // If we have all data shards, just concatenate them
        let mut has_all_data = true;
        for i in 0..self.config.data_shards {
            if !shards.iter().any(|(idx, _)| *idx == i) {
                has_all_data = false;
                break;
            }
        }

        if has_all_data {
            let mut result = Vec::with_capacity(shard_size * self.config.data_shards);
            for i in 0..self.config.data_shards {
                let shard = shards.iter().find(|(idx, _)| *idx == i).unwrap();
                result.extend_from_slice(&shard.1);
            }
            result.truncate(original_len);
            return Ok(result);
        }

        // Need to reconstruct using parity shards
        // This is a simplified Gaussian elimination approach
        self.reconstruct(shards, shard_size, original_len)
    }

    /// Reconstruct data using Gaussian elimination.
    fn reconstruct(
        &self,
        shards: &[(usize, Vec<u8>)],
        shard_size: usize,
        original_len: usize,
    ) -> NadiResult<Vec<u8>> {
        let k = self.config.data_shards;

        // Build the submatrix from received shard indices
        let encoder = ReedSolomonEncoder::new(self.config)?;
        let mut matrix: Vec<Vec<u8>> = shards
            .iter()
            .take(k)
            .map(|(idx, _)| encoder.generator[*idx].clone())
            .collect();

        // Invert the matrix
        let inv_matrix = self.invert_matrix(&mut matrix)?;

        // Multiply inverted matrix by received shards to get data shards
        let received: Vec<&[u8]> = shards.iter().take(k).map(|(_, data)| data.as_slice()).collect();

        let mut result = vec![0u8; shard_size * k];
        for i in 0..k {
            for byte_idx in 0..shard_size {
                let mut val = 0u8;
                for j in 0..k {
                    val ^= gf256::mul(inv_matrix[i][j], received[j][byte_idx]);
                }
                result[i * shard_size + byte_idx] = val;
            }
        }

        result.truncate(original_len);
        Ok(result)
    }

    /// Invert a matrix using Gaussian elimination.
    fn invert_matrix(&self, matrix: &mut [Vec<u8>]) -> NadiResult<Vec<Vec<u8>>> {
        let n = matrix.len();

        // Create augmented matrix [M | I]
        let mut aug: Vec<Vec<u8>> = matrix
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let mut new_row = row.clone();
                new_row.resize(2 * n, 0);
                new_row[n + i] = 1;
                new_row
            })
            .collect();

        // Forward elimination
        for i in 0..n {
            // Find pivot
            let mut pivot = i;
            for j in i + 1..n {
                if aug[j][i] != 0 {
                    pivot = j;
                    break;
                }
            }

            if aug[pivot][i] == 0 {
                return Err(NadiError::FecDecodeFailed {
                    received: 0,
                    required: self.config.data_shards,
                });
            }

            aug.swap(i, pivot);

            // Scale pivot row
            let scale = gf256::inv(aug[i][i]);
            for j in 0..2 * n {
                aug[i][j] = gf256::mul(aug[i][j], scale);
            }

            // Eliminate column
            for j in 0..n {
                if j != i && aug[j][i] != 0 {
                    let factor = aug[j][i];
                    for k in 0..2 * n {
                        aug[j][k] ^= gf256::mul(factor, aug[i][k]);
                    }
                }
            }
        }

        // Extract inverse matrix
        let inv: Vec<Vec<u8>> = aug.iter().map(|row| row[n..].to_vec()).collect();

        Ok(inv)
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> FecConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_mul() {
        assert_eq!(gf256::mul(0, 5), 0);
        assert_eq!(gf256::mul(1, 5), 5);
        assert_eq!(gf256::mul(2, 2), 4);
    }

    #[test]
    fn test_gf256_div() {
        for a in 1u8..=10 {
            for b in 1u8..=10 {
                let c = gf256::mul(a, b);
                assert_eq!(gf256::div(c, b), a);
            }
        }
    }

    #[test]
    fn test_gf256_inv() {
        for a in 1u8..=255 {
            let inv = gf256::inv(a);
            assert_eq!(gf256::mul(a, inv), 1);
        }
    }

    #[test]
    fn test_fec_config_for_priority() {
        assert!(FecConfig::for_priority(Priority::Critical).is_some());
        assert!(FecConfig::for_priority(Priority::VeryHigh).is_some());
        assert!(FecConfig::for_priority(Priority::Background).is_none());
    }

    #[test]
    fn test_encode_decode_no_loss() {
        let config = FecConfig {
            data_shards: 4,
            parity_shards: 2,
        };

        let encoder = ReedSolomonEncoder::new(config).unwrap();
        let decoder = ReedSolomonDecoder::new(config);

        let data = b"Hello, FEC World! This is a test message.";
        let shards = encoder.encode(data).unwrap();

        assert_eq!(shards.len(), 6);

        // Decode with all shards
        let indexed: Vec<(usize, Vec<u8>)> = shards.into_iter().enumerate().collect();
        let recovered = decoder.decode(&indexed, data.len()).unwrap();

        assert_eq!(recovered, data);
    }

    #[test]
    fn test_encode_decode_with_loss() {
        let config = FecConfig {
            data_shards: 4,
            parity_shards: 2,
        };

        let encoder = ReedSolomonEncoder::new(config).unwrap();
        let decoder = ReedSolomonDecoder::new(config);

        let data = b"Test data for FEC recovery with packet loss.";
        let shards = encoder.encode(data).unwrap();

        // Simulate losing 2 shards (indices 1 and 3)
        let indexed: Vec<(usize, Vec<u8>)> = shards
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 1 && *i != 3)
            .collect();

        assert_eq!(indexed.len(), 4); // Still have enough

        let recovered = decoder.decode(&indexed, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_decode_insufficient_shards() {
        let config = FecConfig {
            data_shards: 4,
            parity_shards: 1,
        };

        let encoder = ReedSolomonEncoder::new(config).unwrap();
        let decoder = ReedSolomonDecoder::new(config);

        let data = b"Test data";
        let shards = encoder.encode(data).unwrap();

        // Only keep 3 shards (need 4)
        let indexed: Vec<(usize, Vec<u8>)> = shards.into_iter().enumerate().take(3).collect();

        let result = decoder.decode(&indexed, data.len());
        assert!(matches!(result, Err(NadiError::FecDecodeFailed { .. })));
    }

    #[test]
    fn test_redundancy_percent() {
        let config = FecConfig {
            data_shards: 4,
            parity_shards: 1,
        };
        assert!((config.redundancy_percent() - 25.0).abs() < 0.1);
    }

    #[test]
    fn test_invalid_config() {
        let result = ReedSolomonEncoder::new(FecConfig {
            data_shards: 0,
            parity_shards: 1,
        });
        assert!(result.is_err());
    }
}
