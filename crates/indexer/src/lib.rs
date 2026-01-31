//! ERC-8004 and EdgeRated event ingestion for TrustNet.
//!
//! This crate provides:
//! - Event listeners for ERC-8004 feedback events
//! - EdgeRated event processing
//! - Edge storage and management with latest-wins semantics
//! - Sparse Merkle Map building
//! - Root publishing to RootRegistry

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod storage;

pub mod config;

pub mod listener;

pub mod smm_service;

pub mod publisher;

pub mod root_manifest;

// Re-export common types
pub use trustnet_core::{types::*, *};
