//! Axum-based API server for TrustNet.
//!
//! This crate provides:
//! - `/v1/root` - Get current signed root bundle (server mode) / latest root metadata (chain mode)
//! - `/v1/contexts` - List canonical contexts
//! - `/v1/decision` - Get a verifiable decision bundle (ALLOW|ASK|DENY + proofs)
//! - `/v1/proof` - Debug edge proof by edgeKey

#![warn(missing_docs)]

pub mod db;
pub mod smm_cache;
