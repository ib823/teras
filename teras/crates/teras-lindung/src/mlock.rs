//! Memory locking utilities to prevent secrets from being swapped to disk.
//!
//! This module provides platform-specific memory locking.
//! On failure, behavior depends on the `strict-mlock` feature.

use std::fmt;

/// Error type for mlock operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum MlockError {
    /// The platform does not support memory locking.
    NotSupported,
    /// Memory locking failed (e.g., resource limits).
    LockFailed(i32),
    /// Memory unlocking failed.
    UnlockFailed(i32),
}

impl fmt::Display for MlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "Memory locking not supported on this platform"),
            Self::LockFailed(code) => write!(f, "mlock failed with error code: {code}"),
            Self::UnlockFailed(code) => write!(f, "munlock failed with error code: {code}"),
        }
    }
}

impl std::error::Error for MlockError {}

/// Lock a memory region to prevent it from being swapped.
///
/// # Errors
///
/// Returns `MlockError` if locking fails or is not supported.
///
/// # Platform Support
///
/// - Unix: Uses `mlock(2)`
/// - Windows: Uses `VirtualLock`
/// - Other: Returns `MlockError::NotSupported`
#[cfg(unix)]
#[allow(clippy::module_name_repetitions)]
pub fn mlock_slice(data: &[u8]) -> Result<(), MlockError> {
    if data.is_empty() {
        return Ok(());
    }

    let ptr = data.as_ptr().cast::<libc::c_void>();
    let len = data.len();

    // SAFETY: ptr is valid for len bytes (it's from a slice),
    // and mlock is safe to call on any valid memory region.
    let result = unsafe { libc::mlock(ptr, len) };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        Err(MlockError::LockFailed(errno))
    }
}

/// Unlock a previously locked memory region.
///
/// # Errors
///
/// Returns `MlockError` if unlocking fails.
#[cfg(unix)]
pub fn munlock_slice(data: &[u8]) -> Result<(), MlockError> {
    if data.is_empty() {
        return Ok(());
    }

    let ptr = data.as_ptr().cast::<libc::c_void>();
    let len = data.len();

    // SAFETY: ptr is valid for len bytes, and munlock is safe
    // to call on any valid memory region (even if not locked).
    let result = unsafe { libc::munlock(ptr, len) };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        Err(MlockError::UnlockFailed(errno))
    }
}

/// Lock a memory region to prevent it from being swapped (Windows).
#[cfg(windows)]
#[allow(clippy::module_name_repetitions)]
pub fn mlock_slice(data: &[u8]) -> Result<(), MlockError> {
    if data.is_empty() {
        return Ok(());
    }

    use windows_sys::Win32::System::Memory::VirtualLock;

    let ptr = data.as_ptr();
    let len = data.len();

    // SAFETY: ptr is valid for len bytes
    let result = unsafe { VirtualLock(ptr.cast_mut().cast(), len) };

    if result != 0 {
        Ok(())
    } else {
        Err(MlockError::LockFailed(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        ))
    }
}

/// Unlock a previously locked memory region (Windows).
#[cfg(windows)]
pub fn munlock_slice(data: &[u8]) -> Result<(), MlockError> {
    if data.is_empty() {
        return Ok(());
    }

    use windows_sys::Win32::System::Memory::VirtualUnlock;

    let ptr = data.as_ptr();
    let len = data.len();

    // SAFETY: ptr is valid for len bytes
    let result = unsafe { VirtualUnlock(ptr.cast_mut().cast(), len) };

    if result != 0 {
        Ok(())
    } else {
        Err(MlockError::UnlockFailed(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        ))
    }
}

/// Lock a memory region (unsupported platform).
#[cfg(not(any(unix, windows)))]
#[allow(clippy::module_name_repetitions)]
pub fn mlock_slice(_data: &[u8]) -> Result<(), MlockError> {
    Err(MlockError::NotSupported)
}

/// Unlock a memory region (unsupported platform).
#[cfg(not(any(unix, windows)))]
pub fn munlock_slice(_data: &[u8]) -> Result<(), MlockError> {
    Err(MlockError::NotSupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_empty() {
        let data: [u8; 0] = [];
        assert!(mlock_slice(&data).is_ok());
        assert!(munlock_slice(&data).is_ok());
    }

    #[test]
    fn test_mlock_small() {
        let data = [0u8; 32];
        // mlock may fail due to resource limits, that's OK
        let lock_result = mlock_slice(&data);
        if lock_result.is_ok() {
            assert!(munlock_slice(&data).is_ok());
        }
    }

    #[test]
    fn test_munlock_without_lock() {
        // munlock on non-locked memory should be safe
        let data = [0u8; 32];
        // This may succeed or fail depending on platform, but shouldn't crash
        let _ = munlock_slice(&data);
    }

    #[test]
    fn test_mlock_error_display() {
        let err = MlockError::NotSupported;
        assert!(err.to_string().contains("not supported"));

        let err = MlockError::LockFailed(12);
        assert!(err.to_string().contains("12"));

        let err = MlockError::UnlockFailed(13);
        assert!(err.to_string().contains("13"));
    }
}
