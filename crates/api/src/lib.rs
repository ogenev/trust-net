//! Axum-based API server for TrustNet.
//!
//! This crate provides:
//! - `/v1/root` - Get current Merkle root
//! - `/v1/score` - Get reputation score with proof
//! - `/v1/context` - Get contextual reputation

#![warn(missing_docs)]

pub mod db;
pub mod smm_cache;
