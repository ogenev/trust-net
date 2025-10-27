//! # TrustNet Core
//!
//! Core types, constants, hashing utilities, and score quantization for the TrustNet reputation system.
//!
//! This crate provides the fundamental building blocks used across all TrustNet components,
//! ensuring consistent data types and cryptographic operations that match the Solidity contracts.
//!
//! ## Features
//!
//! - **Ethereum Types**: Uses Alloy primitives for Address, B256, and keccak256
//! - **Domain Types**: Level, ContextId, AgentKey, Edge
//! - **Constants**: Canonical context IDs matching Solidity
//! - **Hashing**: Keccak256 utilities for SMM and edge keys
//! - **Quantization**: ERC-8004 score (0-100) to trust level (-2 to +2)

#![warn(missing_docs)]

pub mod constants;
pub mod error;
pub mod hashing;
pub mod quantizer;
pub mod types;

// Re-export commonly used items
pub use constants::*;
pub use error::{CoreError, Result};
pub use hashing::{compute_edge_key, keccak256};
pub use quantizer::quantize;
pub use types::*;

// Re-export Alloy primitives for convenience
pub use alloy_primitives::{Address, B256};
