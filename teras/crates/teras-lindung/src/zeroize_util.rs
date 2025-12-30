//! Zeroization utilities for secure memory clearing.
//!
//! This module provides the EXACT implementation specified in LAW 4.
//! DO NOT MODIFY THIS CODE.

use core::sync::atomic::{compiler_fence, Ordering};

/// Securely zeroize a byte slice.
///
/// # Security Properties
///
/// - Uses volatile writes to prevent compiler optimization
/// - Memory barrier prevents reordering
/// - Constant-time (does not short-circuit)
///
/// # LAW 4 Compliance
///
/// This is the EXACT implementation from the architecture specification.
/// Any modification is a LAW 4 violation.
///
/// # Example
///
/// ```
/// use teras_lindung::zeroize_bytes;
///
/// let mut secret = [0x42u8; 32];
/// zeroize_bytes(&mut secret);
/// assert!(secret.iter().all(|&b| b == 0));
/// ```
#[inline(never)]
pub fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: We have mutable access to the byte, and volatile write
        // is valid for any properly aligned, dereferenceable pointer.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Verify that a slice is zeroed (debug builds only).
///
/// # Panics
///
/// Panics if any byte is non-zero.
#[cfg(debug_assertions)]
pub fn verify_zeroed(bytes: &[u8]) {
    // Use constant-time comparison to avoid timing leaks even in debug
    let mut non_zero = 0u8;
    for &byte in bytes {
        non_zero |= byte;
    }
    assert!(non_zero == 0, "SECURITY: Memory was not properly zeroized!");
}

/// Verify that a slice is zeroed (no-op in release builds).
#[cfg(not(debug_assertions))]
pub fn verify_zeroed(_bytes: &[u8]) {
    // No-op in release builds to avoid overhead
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_bytes_all_ones() {
        let mut data = [0xFFu8; 64];
        zeroize_bytes(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_zeroize_bytes_random_pattern() {
        let mut data = [0u8; 64];
        for (i, byte) in data.iter_mut().enumerate() {
            // Intentional truncation to create a pattern
            *byte = (i * 17 + 42) as u8;
        }
        zeroize_bytes(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_bytes_empty() {
        let mut data: [u8; 0] = [];
        zeroize_bytes(&mut data); // Should not panic
    }

    #[test]
    fn test_zeroize_bytes_single() {
        let mut data = [0x42u8; 1];
        zeroize_bytes(&mut data);
        assert_eq!(data[0], 0);
    }

    #[test]
    fn test_verify_zeroed_passes() {
        let data = [0u8; 32];
        verify_zeroed(&data); // Should not panic
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "SECURITY")]
    fn test_verify_zeroed_fails_on_nonzero() {
        let data = [0x01u8; 32];
        verify_zeroed(&data); // Should panic
    }
}
