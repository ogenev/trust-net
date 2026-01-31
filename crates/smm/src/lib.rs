//! Sparse Merkle Map implementation for TrustNet.
//!
//! This crate provides:
//! - **Sparse Merkle Map builder** - Construct trees from key-value pairs
//! - **Proof generation** - Generate membership and non-membership proofs
//! - **Proof verification** - Verify proofs against a root hash
//!
//! # Overview
//!
//! A Sparse Merkle Map (SMM) is a cryptographic data structure that maps
//! keys to values and provides:
//! - **Deterministic root hash** - Same leaves always produce same root
//! - **Compact proofs** - O(log n) proof size where n is tree depth (256 for our case)
//! - **Default values** - Missing keys have a default value (2, representing level 0)
//!
//! # Examples
//!
//! ## Building a tree
//!
//! ```
//! use trustnet_smm::SmmBuilder;
//! use alloy_primitives::B256;
//!
//! let mut builder = SmmBuilder::new();
//! builder.insert(B256::from([0x01; 32]), vec![2]).unwrap();
//! builder.insert(B256::from([0x02; 32]), vec![3]).unwrap();
//!
//! let smm = builder.build();
//! let root = smm.root();
//! ```
//!
//! # Architecture
//!
//! - `SmmBuilder` - Mutable builder for constructing trees
//! - `Smm` - Immutable tree structure
//! - `Node` - Internal tree node (Empty, Leaf, or Internal)
//! - `SmmProof` - Proof structure (to be implemented in Phase 3-4)

#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod node;
pub mod proof;
pub mod tree;

// Re-export main types
pub use builder::SmmBuilder;
pub use error::{Result, SmmError};
pub use proof::SmmProof;
pub use tree::Smm;

// Re-export commonly used types from dependencies
pub use alloy_primitives::B256;
