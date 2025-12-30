//! TERAS Integration Layer
//!
//! Provides audited wrappers for all security operations per LAW 8.
//!
//! # Architecture
//!
//! This crate enforces LAW 8 (audit logging) across all TERAS operations:
//!
//! - **Audited Crypto**: All key operations, encryption, signatures are logged
//! - **Audited Feeds**: All threat feed fetches and updates are logged
//! - **Unified Context**: Single entry point holding all TERAS state
//!
//! # Example
//!
//! ```no_run
//! use teras_integrasi::TerasContext;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize TERAS context
//! let ctx = TerasContext::new_in_memory();
//!
//! // All crypto operations are automatically logged
//! let keypair = ctx.crypto().generate_hybrid_keypair("my-key")?;
//!
//! // Verify audit chain
//! let result = ctx.audit().verify_chain()?;
//! assert!(result.valid);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod audited_crypto;
mod audited_feeds;
mod config;
mod context;

pub use audited_crypto::{AuditedCrypto, HybridKemPublicKey, HybridSigningPublicKey};
pub use audited_feeds::{AuditedFeeds, FeedFetchResult};
pub use config::TerasConfig;
pub use context::TerasContext;
