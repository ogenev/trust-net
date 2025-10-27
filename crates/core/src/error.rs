//! Error types for the core crate.

use thiserror::Error;

/// Core error type.
#[derive(Error, Debug)]
pub enum CoreError {
    /// Invalid trust level value.
    #[error("Invalid trust level: {0} (must be between -2 and +2)")]
    InvalidLevel(i8),

    /// Invalid SMM value.
    #[error("Invalid SMM value: {0} (must be between 0 and 4)")]
    InvalidSmmValue(u8),

    /// Invalid ERC-8004 score.
    #[error("Invalid ERC-8004 score: {0} (must be between 0 and 100)")]
    InvalidScore(u8),

    /// Invalid address format.
    #[error("Invalid address format")]
    InvalidAddress,

    /// Invalid context ID format.
    #[error("Invalid context ID format")]
    InvalidContextId,

    /// Invalid hex encoding.
    #[error("Invalid hex encoding")]
    InvalidHex,

    /// Generic error with message.
    #[error("{0}")]
    Other(String),
}

/// Result type alias for CoreError.
pub type Result<T> = std::result::Result<T, CoreError>;
