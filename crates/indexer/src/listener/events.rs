//! Event type definitions for ERC-8004 NewFeedback events.

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
    pub fn to_edge_record(&self) -> Result<EdgeRecord> {
        let level = trustnet_core::quantizer::quantize(self.score)?;

        let ingested_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("Failed to get current timestamp")?
            .as_secs() as i64;

        Ok(EdgeRecord {
            rater: self.feedback_by,
            target: self.feedback_for,
            context_id: self.context_id,
            level,
            block_number: self.block_number,
            tx_index: self.tx_index,
            log_index: self.log_index,
            ingested_at,
            source: EdgeSource::Erc8004,
            tx_hash: Some(self.tx_hash),
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
            metadata: vec![],
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            tx_hash: B256::repeat_byte(0xaa),
        };

        // Core quantizer uses [80, 60, 40, 20] buckets:
        // 80-100 → +2
        let edge = event.to_edge_record().unwrap();

        assert_eq!(edge.rater, event.feedback_by);
        assert_eq!(edge.target, event.feedback_for);
        assert_eq!(edge.context_id, event.context_id);
        assert_eq!(edge.level, Level::strong_positive());
        assert_eq!(edge.block_number, 100);
        assert_eq!(edge.tx_index, 5);
        assert_eq!(edge.log_index, 2);
        assert_eq!(edge.source, EdgeSource::Erc8004);
        assert_eq!(edge.tx_hash, Some(event.tx_hash));
    }
}
