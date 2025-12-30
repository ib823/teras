//! TERAS Core - Foundation types and error handling
//!
//! This crate provides the foundational types used across all TERAS components.
//! It has NO external dependencies by design.

pub mod error;
pub mod types;

pub use error::{TerasError, TerasResult};
