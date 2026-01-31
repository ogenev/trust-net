//! Error types for the SMM crate.

use alloy_primitives::B256;
use thiserror::Error;

/// SMM error type.
#[derive(Error, Debug)]
pub enum SmmError {
    /// Leaf value was empty (ambiguous with non-membership).
    #[error("Invalid leaf value: empty")]
    EmptyLeafValue,

    /// Leaf value failed validation.
    #[error("Invalid leaf value: {0}")]
    InvalidLeafValue(String),

    /// Invalid proof structure or verification failed.
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Tree is empty (no leaves).
    #[error("Tree is empty - cannot perform operation on empty tree")]
    EmptyTree,

    /// Key not found in the tree.
    #[error("Key not found: {0}")]
    KeyNotFound(B256),

    /// Internal error (should not happen in correct usage).
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for SmmError.
pub type Result<T> = std::result::Result<T, SmmError>;
