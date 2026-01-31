//! Event type definitions for on-chain TrustNet signals.

use alloy::primitives::{Address, B256};
use alloy::rpc::types::Log;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use trustnet_core::types::ContextId;

use crate::storage::{EdgeRecord, EdgeSource};

// Define the NewFeedback event using Alloy's sol! macro
sol! {
    /// ERC-8004 NewFeedback event
    #[derive(Debug, PartialEq, Eq)]
    event NewFeedback(
        address indexed feedbackFor,
        address indexed feedbackBy,
        bytes32 indexed contextId,
        uint8 score,
        bytes metadata
    );

    /// TrustGraph EdgeRated event.
    #[derive(Debug, PartialEq, Eq)]
    event EdgeRated(
        address indexed rater,
        address indexed target,
        int8 level,
        bytes32 indexed contextId
    );
}

/// Parsed NewFeedback event with block coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFeedbackEvent {
    /// Target of the feedback (the agent being rated)
    pub feedback_for: Address,

    /// Source of the feedback (the rater)
    pub feedback_by: Address,

    /// Context identifier for the rating
    pub context_id: ContextId,

    /// Score from 0 to 100
    pub score: u8,

    /// Additional metadata (optional, not used in MVP)
    pub metadata: Vec<u8>,

    /// Block number where the event occurred
    pub block_number: u64,

    /// Transaction index within the block
    pub tx_index: u64,

    /// Log index within the transaction
    pub log_index: u64,

    /// Transaction hash
    pub tx_hash: B256,
}

impl NewFeedbackEvent {
    /// Parse a NewFeedback event from an Alloy log.
    pub fn from_log(log: &Log) -> Result<Self> {
        // Decode the event data using SolEvent trait
        let event_data = NewFeedback::decode_log(log.as_ref(), true)
            .context("Failed to decode NewFeedback event")?;

        // Extract block coordinates
        let block_number = log.block_number.context("Log missing block_number")?;
        let tx_index = log
            .transaction_index
            .context("Log missing transaction_index")?;
        let log_index = log.log_index.context("Log missing log_index")?;
        let tx_hash = log
            .transaction_hash
            .context("Log missing transaction_hash")?;

        // Convert context_id from bytes32 to ContextId
        let context_id = ContextId::from(event_data.contextId.0);

        Ok(Self {
            feedback_for: event_data.feedbackFor,
            feedback_by: event_data.feedbackBy,
            context_id,
            score: event_data.score,
            metadata: event_data.metadata.to_vec(),
            block_number,
            tx_index,
            log_index,
            tx_hash,
        })
    }

    /// Convert this event to an EdgeRecord using the core quantizer.
    ///
    /// Returns `Ok(None)` when the TrustNet guard tag is missing (`tag2 != keccak256("trustnet:v1")`).
    pub fn to_edge_record(&self, chain_id: u64, updated_at_u64: u64) -> Result<Option<EdgeRecord>> {
        // Guard: only ingest feedback explicitly tagged for TrustNet semantics.
        // MVP assumption: `metadata` begins with `bytes32 tag2`.
        if self.metadata.len() < 32 {
            return Ok(None);
        }

        let tag2 = B256::from_slice(&self.metadata[..32]);
        if tag2 != trustnet_core::TAG_TRUSTNET_V1 {
            return Ok(None);
        }

        let level = trustnet_core::quantizer::quantize(self.score)?;

        Ok(Some(EdgeRecord {
            rater: trustnet_core::PrincipalId::from_evm_address(self.feedback_by),
            target: trustnet_core::PrincipalId::from_evm_address(self.feedback_for),
            context_id: self.context_id,
            level,
            updated_at_u64,
            evidence_hash: B256::ZERO,
            source: EdgeSource::Erc8004,
            chain_id: Some(chain_id),
            block_number: Some(self.block_number),
            tx_index: Some(self.tx_index),
            log_index: Some(self.log_index),
            tx_hash: Some(self.tx_hash),
            server_seq: None,
        }))
    }
}

/// Parsed EdgeRated event with block coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeRatedEvent {
    /// Rater emitting the edge (msg.sender in TrustGraph).
    pub rater: Address,

    /// Target receiving the rating.
    pub target: Address,

    /// Trust level (-2..+2).
    pub level: i8,

    /// Context identifier for the rating.
    pub context_id: ContextId,

    /// Block number where the event occurred.
    pub block_number: u64,

    /// Transaction index within the block.
    pub tx_index: u64,

    /// Log index within the transaction.
    pub log_index: u64,

    /// Transaction hash.
    pub tx_hash: B256,
}

impl EdgeRatedEvent {
    /// Parse an EdgeRated event from an Alloy log.
    pub fn from_log(log: &Log) -> Result<Self> {
        let event_data = EdgeRated::decode_log(log.as_ref(), true)
            .context("Failed to decode EdgeRated event")?;

        let block_number = log.block_number.context("Log missing block_number")?;
        let tx_index = log
            .transaction_index
            .context("Log missing transaction_index")?;
        let log_index = log.log_index.context("Log missing log_index")?;
        let tx_hash = log
            .transaction_hash
            .context("Log missing transaction_hash")?;

        Ok(Self {
            rater: event_data.rater,
            target: event_data.target,
            level: event_data.level,
            context_id: ContextId::from(event_data.contextId.0),
            block_number,
            tx_index,
            log_index,
            tx_hash,
        })
    }

    /// Convert this on-chain event into a normalized `EdgeRecord` for v0.4 storage/root building.
    pub fn to_edge_record(&self, chain_id: u64, updated_at_u64: u64) -> Result<EdgeRecord> {
        let level = trustnet_core::types::Level::new(self.level)?;

        Ok(EdgeRecord {
            rater: trustnet_core::PrincipalId::from_evm_address(self.rater),
            target: trustnet_core::PrincipalId::from_evm_address(self.target),
            context_id: self.context_id,
            level,
            updated_at_u64,
            evidence_hash: B256::ZERO,
            source: EdgeSource::TrustGraph,
            chain_id: Some(chain_id),
            block_number: Some(self.block_number),
            tx_index: Some(self.tx_index),
            log_index: Some(self.log_index),
            tx_hash: Some(self.tx_hash),
            server_seq: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustnet_core::types::Level;

    #[test]
    fn test_to_edge_record() {
        let event = NewFeedbackEvent {
            feedback_for: Address::repeat_byte(0x01),
            feedback_by: Address::repeat_byte(0x02),
            context_id: ContextId::from([0u8; 32]),
            score: 85,
            metadata: trustnet_core::TAG_TRUSTNET_V1.as_slice().to_vec(),
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            tx_hash: B256::repeat_byte(0xaa),
        };

        // Core quantizer uses [80, 60, 40, 20] buckets:
        // 80-100 → +2
        let edge = event.to_edge_record(11155111, 123).unwrap().unwrap();

        assert_eq!(
            edge.rater,
            trustnet_core::PrincipalId::from_evm_address(event.feedback_by)
        );
        assert_eq!(
            edge.target,
            trustnet_core::PrincipalId::from_evm_address(event.feedback_for)
        );
        assert_eq!(edge.context_id, event.context_id);
        assert_eq!(edge.level, Level::strong_positive());
        assert_eq!(edge.chain_id, Some(11155111));
        assert_eq!(edge.block_number, Some(100));
        assert_eq!(edge.tx_index, Some(5));
        assert_eq!(edge.log_index, Some(2));
        assert_eq!(edge.source, EdgeSource::Erc8004);
        assert_eq!(edge.tx_hash, Some(event.tx_hash));
        assert_eq!(edge.server_seq, None);
    }

    #[test]
    fn test_to_edge_record_guard_rejects_untagged() {
        let event = NewFeedbackEvent {
            feedback_for: Address::repeat_byte(0x01),
            feedback_by: Address::repeat_byte(0x02),
            context_id: ContextId::from([0u8; 32]),
            score: 85,
            metadata: vec![0u8; 32],
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            tx_hash: B256::repeat_byte(0xaa),
        };

        assert!(event.to_edge_record(1, 1).unwrap().is_none());
    }

    #[test]
    fn test_edge_rated_to_edge_record() {
        let event = EdgeRatedEvent {
            rater: Address::repeat_byte(0x11),
            target: Address::repeat_byte(0x22),
            level: 2,
            context_id: ContextId::from([0x33u8; 32]),
            block_number: 100,
            tx_index: 1,
            log_index: 2,
            tx_hash: B256::repeat_byte(0xaa),
        };

        let edge = event.to_edge_record(11155111, 123).unwrap();
        assert_eq!(edge.level, Level::strong_positive());
        assert_eq!(edge.source, EdgeSource::TrustGraph);
        assert_eq!(edge.chain_id, Some(11155111));
    }
}
