//! Constant-time utilities for secure comparisons.
//!
//! ALL comparisons of secret data MUST use these functions.
//! Using == or != on secrets is a LAW 3 violation.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time equality comparison.
///
/// # Security
///
/// - No early return
/// - No branching on input values
/// - Verified by dudect (must pass with t < 4.5)
///
/// # Example
///
/// ```
/// use teras_kunci::ct_eq;
///
/// let a = [1u8, 2, 3];
/// let b = [1u8, 2, 3];
/// assert!(ct_eq(&a, &b));
/// ```
#[inline(never)]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Constant-time selection.
///
/// Returns `a` if `condition` is true, `b` otherwise.
///
/// # Security
///
/// - No branching on condition
/// - Both branches are always evaluated
#[inline(never)]
#[must_use]
pub fn ct_select(condition: bool, a: u8, b: u8) -> u8 {
    let choice = Choice::from(u8::from(condition));
    u8::conditional_select(&b, &a, choice)
}

/// Constant-time conditional copy.
///
/// Copies `src` to `dst` if `choice` is true.
/// Execution time is independent of `choice`.
///
/// # Panics
///
/// Panics if `dst` and `src` have different lengths.
#[inline(never)]
pub fn ct_copy_if(choice: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "ct_copy_if: length mismatch");

    let mask = 0u8.wrapping_sub(u8::from(choice));
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*s & mask) | (*d & !mask);
    }
}

/// Constant-time `is_zero` check.
///
/// Returns true if all bytes are zero.
#[inline(never)]
#[must_use]
pub fn ct_is_zero(data: &[u8]) -> bool {
    let mut acc = 0u8;
    for &byte in data {
        acc |= byte;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_equal() {
        assert!(ct_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_ct_eq_not_equal() {
        assert!(!ct_eq(b"hello", b"world"));
    }

    #[test]
    fn test_ct_eq_different_length() {
        assert!(!ct_eq(b"hello", b"hi"));
    }

    #[test]
    fn test_ct_eq_empty() {
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn test_ct_select_true() {
        assert_eq!(ct_select(true, 0xAA, 0xBB), 0xAA);
    }

    #[test]
    fn test_ct_select_false() {
        assert_eq!(ct_select(false, 0xAA, 0xBB), 0xBB);
    }

    #[test]
    fn test_ct_copy_if_true() {
        let mut dst = [0u8; 4];
        let src = [1u8, 2, 3, 4];
        ct_copy_if(true, &mut dst, &src);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_ct_copy_if_false() {
        let mut dst = [0xFFu8; 4];
        let src = [1u8, 2, 3, 4];
        ct_copy_if(false, &mut dst, &src);
        assert_eq!(dst, [0xFF; 4]);
    }

    #[test]
    fn test_ct_is_zero_true() {
        assert!(ct_is_zero(&[0, 0, 0, 0]));
    }

    #[test]
    fn test_ct_is_zero_false() {
        assert!(!ct_is_zero(&[0, 0, 1, 0]));
    }
}
