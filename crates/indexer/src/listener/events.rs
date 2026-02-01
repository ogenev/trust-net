//! Event type definitions for on-chain TrustNet signals.

use alloy::primitives::{Address, B256, U256};
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
        uint256 indexed agentId,
        address indexed clientAddress,
        uint8 score,
        bytes32 indexed tag1,
        bytes32 tag2,
        string fileuri,
        bytes32 filehash
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
    /// Agent identifier (ERC-8004 identity registry).
    pub agent_id: U256,

    /// Source of the feedback (client address / rater).
    pub client_address: Address,

    /// Context identifier for the rating (tag1).
    pub context_id: ContextId,

    /// Score from 0 to 100
    pub score: u8,

    /// Guard tag (tag2). Only tagged feedback is ingested.
    pub tag2: B256,

    /// Evidence URI (not committed).
    pub evidence_uri: String,

    /// Evidence hash (committed in v0.4 leafValue).
    pub evidence_hash: B256,

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

        // Convert tag1 from bytes32 to ContextId.
        let context_id = ContextId::from(event_data.tag1.0);
        let tag2 = B256::from(event_data.tag2.0);

        Ok(Self {
            agent_id: event_data.agentId,
            client_address: event_data.clientAddress,
            context_id,
            score: event_data.score,
            tag2,
            evidence_uri: event_data.fileuri.to_string(),
            evidence_hash: B256::from(event_data.filehash.0),
            block_number,
            tx_index,
            log_index,
            tx_hash,
        })
    }

    /// Convert this event to an EdgeRecord using the core quantizer.
    ///
    /// Returns `Ok(None)` when the TrustNet guard tag is missing (`tag2 != keccak256("trustnet:v1")`).
    pub fn to_edge_record(
        &self,
        chain_id: u64,
        updated_at_u64: u64,
        erc8004_namespace: Address,
    ) -> Result<Option<EdgeRecord>> {
        // Guard: only ingest feedback explicitly tagged for TrustNet semantics.
        if self.tag2 != trustnet_core::TAG_TRUSTNET_V1 {
            return Ok(None);
        }

        let level = trustnet_core::quantizer::quantize(self.score)?;

        // Stable agent identity: use AgentKey(chainId, namespace, agentId) as the PrincipalId.
        let agent_id_bytes: [u8; 32] = self.agent_id.to_be_bytes();
        let agent_key = trustnet_core::hashing::compute_agent_key(
            chain_id,
            &erc8004_namespace,
            &agent_id_bytes,
        );

        Ok(Some(EdgeRecord {
            rater: trustnet_core::PrincipalId::from_evm_address(self.client_address),
            target: trustnet_core::PrincipalId::from(*agent_key.inner()),
            context_id: self.context_id,
            level,
            updated_at_u64,
            evidence_hash: self.evidence_hash,
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
            agent_id: U256::from(1u64),
            client_address: Address::repeat_byte(0x02),
            context_id: ContextId::from([0u8; 32]),
            score: 85,
            tag2: trustnet_core::TAG_TRUSTNET_V1,
            evidence_uri: "ipfs://example".to_string(),
            evidence_hash: B256::repeat_byte(0x11),
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            tx_hash: B256::repeat_byte(0xaa),
        };

        // Core quantizer uses [80, 60, 40, 20] buckets:
        // 80-100 → +2
        let chain_id = 11155111;
        let namespace = Address::repeat_byte(0x33);
        let edge = event
            .to_edge_record(chain_id, 123, namespace)
            .unwrap()
            .unwrap();

        assert_eq!(
            edge.rater,
            trustnet_core::PrincipalId::from_evm_address(event.client_address)
        );
        let agent_id_bytes: [u8; 32] = event.agent_id.to_be_bytes();
        let expected_agent_key =
            trustnet_core::hashing::compute_agent_key(chain_id, &namespace, &agent_id_bytes);
        assert_eq!(
            edge.target,
            trustnet_core::PrincipalId::from(*expected_agent_key.inner())
        );
        assert_eq!(edge.context_id, event.context_id);
        assert_eq!(edge.level, Level::strong_positive());
        assert_eq!(edge.chain_id, Some(chain_id));
        assert_eq!(edge.block_number, Some(100));
        assert_eq!(edge.tx_index, Some(5));
        assert_eq!(edge.log_index, Some(2));
        assert_eq!(edge.source, EdgeSource::Erc8004);
        assert_eq!(edge.tx_hash, Some(event.tx_hash));
        assert_eq!(edge.server_seq, None);
        assert_eq!(edge.evidence_hash, event.evidence_hash);
    }

    #[test]
    fn test_to_edge_record_guard_rejects_untagged() {
        let event = NewFeedbackEvent {
            agent_id: U256::from(1u64),
            client_address: Address::repeat_byte(0x02),
            context_id: ContextId::from([0u8; 32]),
            score: 85,
            tag2: B256::ZERO,
            evidence_uri: "ipfs://example".to_string(),
            evidence_hash: B256::repeat_byte(0x11),
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            tx_hash: B256::repeat_byte(0xaa),
        };

        assert!(event
            .to_edge_record(1, 1, Address::repeat_byte(0x33))
            .unwrap()
            .is_none());
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
