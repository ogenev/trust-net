//! Event listener for ERC-8004 NewFeedback events.
//!
//! This module provides:
//! - Event type definitions and parsing
//! - RPC provider wrapper for Ethereum communication
//! - Sync engine for historical and live block processing

pub mod events;
pub mod provider;
pub mod sync;

pub use events::NewFeedbackEvent;
pub use provider::RpcProvider;
pub use sync::SyncEngine;
