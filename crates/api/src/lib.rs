//! Axum-based API server for TrustNet.
//!
//! This crate provides:
//! - `/v1/root` - Get current signed root bundle (server mode) / latest root metadata (chain mode)
//! - `/v1/contexts` - List canonical contexts
//! - `/v1/score/:decider/:target?contextTag=...` - Get a verifiable TrustNet v1.1 score bundle
//! - `/v1/proof` - Debug edge proof by edgeKey

#![warn(missing_docs)]

pub mod db;
/// API server runtime and in-process app builder.
pub mod server;
pub mod smm_cache;
