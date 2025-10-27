//! Error types for the SMM crate.

use alloy_primitives::B256;
use thiserror::Error;

/// SMM error type.
#[derive(Error, Debug)]
pub enum SmmError {
    /// Invalid value - must be 0-4 (representing levels -2 to +2).
    #[error("Invalid value {0}, must be 0-4 (representing trust levels -2 to +2)")]
    InvalidValue(u8),

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
