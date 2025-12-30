//! TERAS Lindung - Memory Protection Primitives
//!
//! This crate provides secure memory handling for secrets:
//! - `Secret<T>`: A wrapper that zeroizes on drop
//! - Memory locking (mlock) to prevent swapping
//! - Constant-time zeroization
//!
//! # Security Properties
//!
//! - Secrets are zeroized when dropped (LAW 4)
//! - Secrets cannot be cloned (prevent accidental copies)
//! - Secrets cannot be printed (prevent accidental logging)
//! - Memory is locked to prevent swap (where supported)
//!
//! # Example
//!
//! ```
//! use teras_lindung::Secret;
//!
//! let secret = Secret::new([0x42u8; 32]);
//! // Use the secret...
//! let data = secret.expose();
//! // When `secret` drops, memory is zeroized
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod mlock;
mod secret;
mod zeroize_util;

pub use mlock::{mlock_slice, munlock_slice, MlockError};
pub use secret::Secret;
pub use zeroize_util::zeroize_bytes;
