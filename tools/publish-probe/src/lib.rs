//! Staging-only probe for the registry upload and authentication workflow.
//!
//! This contains no PKCS#11 implementation. Use the pkcs11-components crates
//! for the actual libraries.
#![no_std]

/// The package version assigned by the staging workflow.
pub const PROBE_VERSION: &str = env!("CARGO_PKG_VERSION");
