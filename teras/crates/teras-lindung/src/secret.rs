//! Secret type for secure handling of sensitive data.
//!
//! This module provides the `Secret<T>` type which ensures:
//! - Automatic zeroization on drop
//! - Memory locking where supported
//! - No accidental exposure through Clone/Debug/Display

use core::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

use crate::mlock::{mlock_slice, munlock_slice};
use crate::zeroize_util::verify_zeroed;

/// A type that holds secret data with automatic zeroization.
///
/// # Security Properties
///
/// - Data is zeroized on drop (guaranteed by `compiler_fence`)
/// - No Clone implementation (secrets cannot be copied)
/// - No Debug implementation (secrets cannot be printed)
/// - Memory is mlocked if platform supports it
///
/// # Example
///
/// ```
/// use teras_lindung::Secret;
///
/// // Create a secret key
/// let key = Secret::new([0x42u8; 32]);
///
/// // Access the secret when needed
/// let key_bytes = key.expose();
/// assert_eq!(key_bytes.len(), 32);
///
/// // When key goes out of scope, memory is automatically zeroized
/// ```
pub struct Secret<T: Zeroize + AsRef<[u8]>> {
    data: Box<T>,
    is_locked: bool,
}

impl<T: Zeroize + AsRef<[u8]>> Secret<T> {
    /// Create a new secret.
    ///
    /// This will attempt to mlock the memory. If mlock fails:
    /// - With `strict-mlock` feature: panics
    /// - Without: continues with warning (in debug builds)
    ///
    /// # Panics
    ///
    /// Panics if memory locking fails and `TERAS_STRICT_MLOCK` environment
    /// variable is set, or if the `strict-mlock` feature is enabled.
    #[must_use]
    pub fn new(data: T) -> Self {
        let boxed = Box::new(data);

        let bytes = (*boxed).as_ref();
        let lock_result = mlock_slice(bytes);

        let is_locked = match lock_result {
            Ok(()) => true,
            Err(e) => {
                // In strict mode, fail if mlock fails
                #[cfg(feature = "strict-mlock")]
                {
                    panic!("mlock failed and strict-mlock feature is enabled: {e}");
                }

                #[cfg(not(feature = "strict-mlock"))]
                {
                    assert!(
                        std::env::var("TERAS_STRICT_MLOCK").is_err(),
                        "mlock failed and TERAS_STRICT_MLOCK is set: {e}"
                    );

                    // Suppress the warning in release builds to avoid any info leak
                    #[cfg(debug_assertions)]
                    {
                        // Note: This is the ONLY permitted eprintln in this crate
                        // It warns about mlock failure which is a security concern
                        eprintln!("[TERAS WARNING] mlock failed: {e}");
                    }
                    let _ = e; // Silence unused variable warning in release

                    false
                }
            }
        };

        Secret {
            data: boxed,
            is_locked,
        }
    }

    /// Expose the secret for reading.
    ///
    /// # Security
    ///
    /// The returned reference must not be stored or leaked.
    /// Use immediately and let go.
    ///
    /// # Example
    ///
    /// ```
    /// use teras_lindung::Secret;
    ///
    /// let secret = Secret::new([1u8, 2, 3]);
    /// let data = secret.expose();
    /// assert_eq!(data, &[1, 2, 3]);
    /// ```
    #[inline]
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.data
    }

    /// Expose the secret for mutation.
    ///
    /// # Security
    ///
    /// The returned reference must not be stored or leaked.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Check if the memory is locked.
    ///
    /// Returns `true` if mlock succeeded, `false` otherwise.
    #[inline]
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }
}

impl<T: Zeroize + AsRef<[u8]>> Drop for Secret<T> {
    fn drop(&mut self) {
        // Step 1: Zeroize the data
        self.data.zeroize();

        // Step 2: Memory barrier to prevent reordering
        compiler_fence(Ordering::SeqCst);

        // Step 3: Verify zeroization in debug builds
        #[cfg(debug_assertions)]
        {
            verify_zeroed((*self.data).as_ref());
        }

        // Step 4: Unlock memory
        if self.is_locked {
            let bytes = (*self.data).as_ref();
            let _ = munlock_slice(bytes); // Ignore errors on unlock
        }
    }
}

// ============================================================================
// PROHIBITED IMPLEMENTATIONS - These must NOT exist
// ============================================================================
// The following trait implementations are EXPLICITLY PROHIBITED:
//
// impl<T: Zeroize + AsRef<[u8]>> Clone for Secret<T> { ... }
//   - Secrets cannot be copied to prevent multiple copies in memory
//
// impl<T: Zeroize + AsRef<[u8]>> Debug for Secret<T> { ... }
//   - Secrets cannot be debug-printed to prevent logging
//
// impl<T: Zeroize + AsRef<[u8]>> Display for Secret<T> { ... }
//   - Secrets cannot be displayed to prevent accidental output
//
// impl<T: Zeroize + AsRef<[u8]>> Serialize for Secret<T> { ... }
//   - Secrets cannot be serialized to prevent persistence
//
// VALIDATION: Compile must fail if any of the above are implemented.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_new_and_expose() {
        let secret = Secret::new([0x42u8; 32]);
        let exposed = secret.expose();
        assert_eq!(exposed.len(), 32);
        assert!(exposed.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_secret_expose_mut() {
        let mut secret = Secret::new([0x00u8; 32]);
        {
            let data = secret.expose_mut();
            data[0] = 0xFF;
        }
        assert_eq!(secret.expose()[0], 0xFF);
    }

    #[test]
    fn test_secret_zeroized_on_drop() {
        // We can't directly test this since the memory is gone after drop,
        // but we can verify the drop code runs without panic
        let secret = Secret::new([0xFFu8; 64]);
        drop(secret);
        // If we get here, drop didn't panic
    }

    #[test]
    fn test_secret_empty() {
        let secret = Secret::new([0u8; 0]);
        assert_eq!(secret.expose().len(), 0);
    }

    #[test]
    fn test_secret_single_byte() {
        let secret = Secret::new([0x42u8; 1]);
        assert_eq!(secret.expose()[0], 0x42);
    }

    #[test]
    fn test_secret_large() {
        let secret = Secret::new([0xABu8; 4096]);
        assert!(secret.expose().iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_secret_is_locked() {
        let secret = Secret::new([0u8; 32]);
        // is_locked may be true or false depending on platform/permissions
        let _ = secret.is_locked();
    }

    // Compile-time test: These should NOT compile
    // Uncomment to verify they fail:
    //
    // #[test]
    // fn test_secret_not_clone() {
    //     let s1 = Secret::new([0u8; 32]);
    //     let s2 = s1.clone(); // Should fail: Secret does not implement Clone
    // }
    //
    // #[test]
    // fn test_secret_not_debug() {
    //     let s = Secret::new([0u8; 32]);
    //     println!("{:?}", s); // Should fail: Secret does not implement Debug
    // }
}
