//! Event type definitions for on-chain TrustNet signals.

use alloy::primitives::{Address, B256, U256};
use alloy::rpc::types::Log;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use trustnet_core::hashing::compute_subject_id;
use trustnet_core::types::{ContextId, PrincipalId};

use crate::storage::{
    EdgeRecord, EdgeSource, FeedbackRecord, FeedbackResponseRecord, FeedbackRevocationRecord,
};

// Define the NewFeedback event using Alloy's sol! macro
sol! {
    /// ERC-8004 NewFeedback event
    #[derive(Debug, PartialEq, Eq)]
    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        int128 value,
        uint8 valueDecimals,
        string indexed indexedTag1,
        string tag1,
        string tag2,
        string endpoint,
        string feedbackURI,
        bytes32 feedbackHash
    );

    /// ERC-8004 ResponseAppended event
    #[derive(Debug, PartialEq, Eq)]
    event ResponseAppended(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        address indexed responder,
        string responseURI,
        bytes32 responseHash
    );

    /// ERC-8004 FeedbackRevoked event.
    #[derive(Debug, PartialEq, Eq)]
    event FeedbackRevoked(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 indexed feedbackIndex
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

    /// Feedback index (uint64).
    pub feedback_index: U256,

    /// Raw fixed-point value (int128).
    pub value: i128,

    /// Fixed-point decimals.
    pub value_decimals: u8,

    /// Tag1 string (context or bytes32 hex).
    pub tag1: String,

    /// Tag2 string (guard).
    pub tag2: String,

    /// Endpoint string (guard).
    pub endpoint: String,

    /// Feedback URI (optional).
    pub feedback_uri: Option<String>,

    /// Feedback hash surfaced in Why metadata (not committed in v1.1 leaf value).
    pub feedback_hash: B256,

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

        let value = event_data.value;

        Ok(Self {
            agent_id: event_data.agentId,
            client_address: event_data.clientAddress,
            feedback_index: U256::from(event_data.feedbackIndex),
            value,
            value_decimals: event_data.valueDecimals,
            tag1: event_data.tag1.clone(),
            tag2: event_data.tag2.clone(),
            endpoint: event_data.endpoint.clone(),
            feedback_uri: normalize_optional_string(event_data.feedbackURI.clone()),
            feedback_hash: B256::from(event_data.feedbackHash.0),
            block_number,
            tx_index,
            log_index,
            tx_hash,
        })
    }

    /// Convert this event to an EdgeRecord using the core quantizer.
    ///
    /// Returns `Ok(None)` when the TrustNet guard is missing or malformed.
    pub fn to_edge_record(
        &self,
        chain_id: u64,
        updated_at_u64: u64,
        observed_at_u64: u64,
        erc8004_identity: Option<Address>,
        agent_wallet: Option<Address>,
    ) -> Result<Option<EdgeRecord>> {
        // Guard: only ingest feedback explicitly tagged for TrustNet semantics.
        if !matches_trustnet_tag2_guard(&self.tag2) {
            return Ok(None);
        }

        let Some(context_id) = parse_context_id(&self.tag1) else {
            return Ok(None);
        };

        let Some(score) = score_from_value(self.value, self.value_decimals) else {
            return Ok(None);
        };

        let level = trustnet_core::quantizer::quantize(score)?;

        let agent_id_bytes: [u8; 32] = self.agent_id.to_be_bytes();
        let subject_id = erc8004_identity
            .map(|registry| compute_subject_id(chain_id, &registry, &agent_id_bytes));

        // Whitepaper mapping:
        // - preferred stable target: AgentKey/SubjectId (agent identity)
        // - fallback target: agentWallet(agentId)
        //
        // Using SubjectId when available preserves latest-effective semantics per
        // (rater, agentId, contextTag) even if agentWallet rotates over time.
        let target = match (agent_wallet, subject_id) {
            (_, Some(subject)) => PrincipalId::from(*subject.inner()),
            (Some(wallet), None) => PrincipalId::from_evm_address(wallet),
            (None, None) => return Ok(None),
        };

        Ok(Some(EdgeRecord {
            rater: PrincipalId::from_evm_address(self.client_address),
            target,
            subject_id,
            context_id,
            level,
            updated_at_u64,
            evidence_hash: self.feedback_hash,
            evidence_uri: self.feedback_uri.clone(),
            observed_at_u64,
            source: EdgeSource::Erc8004,
            chain_id: Some(chain_id),
            block_number: Some(self.block_number),
            tx_index: Some(self.tx_index),
            log_index: Some(self.log_index),
            tx_hash: Some(self.tx_hash),
            server_seq: None,
        }))
    }

    /// Convert this event into a raw feedback record for storage.
    pub fn to_feedback_record(
        &self,
        chain_id: u64,
        erc8004_reputation: Address,
        erc8004_identity: Option<Address>,
        observed_at_u64: u64,
    ) -> FeedbackRecord {
        let agent_id_bytes: [u8; 32] = self.agent_id.to_be_bytes();
        let subject_id = erc8004_identity
            .map(|registry| compute_subject_id(chain_id, &registry, &agent_id_bytes));

        FeedbackRecord {
            chain_id,
            erc8004_reputation,
            erc8004_identity,
            agent_id: self.agent_id,
            client_address: self.client_address,
            feedback_index: self.feedback_index,
            value: self.value,
            value_decimals: self.value_decimals,
            tag1: self.tag1.clone(),
            tag2: self.tag2.clone(),
            endpoint: self.endpoint.clone(),
            feedback_uri: self.feedback_uri.clone(),
            feedback_hash: self.feedback_hash,
            subject_id,
            observed_at_u64,
            block_number: Some(self.block_number),
            tx_index: Some(self.tx_index),
            log_index: Some(self.log_index),
            tx_hash: Some(self.tx_hash),
        }
    }
}

/// Parsed ResponseAppended event with block coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseAppendedEvent {
    /// Agent identifier (ERC-8004 identity registry).
    pub agent_id: U256,

    /// Client address that submitted the feedback.
    pub client_address: Address,

    /// Feedback index (uint64).
    pub feedback_index: U256,

    /// Responder address.
    pub responder: Address,

    /// Response URI (optional).
    pub response_uri: Option<String>,

    /// Response hash (committed).
    pub response_hash: B256,

    /// Block number where the event occurred
    pub block_number: u64,

    /// Transaction index within the block
    pub tx_index: u64,

    /// Log index within the transaction
    pub log_index: u64,

    /// Transaction hash
    pub tx_hash: B256,
}

impl ResponseAppendedEvent {
    /// Parse a ResponseAppended event from an Alloy log.
    pub fn from_log(log: &Log) -> Result<Self> {
        let event_data = ResponseAppended::decode_log(log.as_ref(), true)
            .context("Failed to decode ResponseAppended event")?;

        let block_number = log.block_number.context("Log missing block_number")?;
        let tx_index = log
            .transaction_index
            .context("Log missing transaction_index")?;
        let log_index = log.log_index.context("Log missing log_index")?;
        let tx_hash = log
            .transaction_hash
            .context("Log missing transaction_hash")?;

        Ok(Self {
            agent_id: event_data.agentId,
            client_address: event_data.clientAddress,
            feedback_index: U256::from(event_data.feedbackIndex),
            responder: event_data.responder,
            response_uri: normalize_optional_string(event_data.responseURI.clone()),
            response_hash: B256::from(event_data.responseHash.0),
            block_number,
            tx_index,
            log_index,
            tx_hash,
        })
    }

    /// Convert this event into a raw feedback response record for storage.
    pub fn to_feedback_response_record(
        &self,
        chain_id: u64,
        erc8004_reputation: Address,
        observed_at_u64: u64,
    ) -> FeedbackResponseRecord {
        FeedbackResponseRecord {
            chain_id,
            erc8004_reputation,
            agent_id: self.agent_id,
            client_address: self.client_address,
            feedback_index: self.feedback_index,
            responder: self.responder,
            response_uri: self.response_uri.clone(),
            response_hash: self.response_hash,
            observed_at_u64,
            block_number: Some(self.block_number),
            tx_index: Some(self.tx_index),
            log_index: Some(self.log_index),
            tx_hash: Some(self.tx_hash),
        }
    }
}

/// Parsed FeedbackRevoked event with block coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackRevokedEvent {
    /// Agent identifier (ERC-8004 identity registry).
    pub agent_id: U256,

    /// Client address that submitted the feedback.
    pub client_address: Address,

    /// Feedback index (uint64).
    pub feedback_index: U256,

    /// Block number where the event occurred.
    pub block_number: u64,

    /// Transaction index within the block.
    pub tx_index: u64,

    /// Log index within the transaction.
    pub log_index: u64,

    /// Transaction hash.
    pub tx_hash: B256,
}

impl FeedbackRevokedEvent {
    /// Parse a FeedbackRevoked event from an Alloy log.
    pub fn from_log(log: &Log) -> Result<Self> {
        let event_data = FeedbackRevoked::decode_log(log.as_ref(), true)
            .context("Failed to decode FeedbackRevoked event")?;

        let block_number = log.block_number.context("Log missing block_number")?;
        let tx_index = log
            .transaction_index
            .context("Log missing transaction_index")?;
        let log_index = log.log_index.context("Log missing log_index")?;
        let tx_hash = log
            .transaction_hash
            .context("Log missing transaction_hash")?;

        Ok(Self {
            agent_id: event_data.agentId,
            client_address: event_data.clientAddress,
            feedback_index: U256::from(event_data.feedbackIndex),
            block_number,
            tx_index,
            log_index,
            tx_hash,
        })
    }

    /// Convert this event into a raw feedback revocation record for storage.
    pub fn to_feedback_revocation_record(
        &self,
        chain_id: u64,
        erc8004_reputation: Address,
        observed_at_u64: u64,
    ) -> FeedbackRevocationRecord {
        FeedbackRevocationRecord {
            chain_id,
            erc8004_reputation,
            agent_id: self.agent_id,
            client_address: self.client_address,
            feedback_index: self.feedback_index,
            observed_at_u64,
            block_number: Some(self.block_number),
            tx_index: Some(self.tx_index),
            log_index: Some(self.log_index),
            tx_hash: Some(self.tx_hash),
        }
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

    /// Convert this on-chain event into a normalized `EdgeRecord` for storage/root building.
    pub fn to_edge_record(
        &self,
        chain_id: u64,
        updated_at_u64: u64,
        observed_at_u64: u64,
    ) -> Result<EdgeRecord> {
        let level = trustnet_core::types::Level::new(self.level)?;

        Ok(EdgeRecord {
            rater: trustnet_core::PrincipalId::from_evm_address(self.rater),
            target: trustnet_core::PrincipalId::from_evm_address(self.target),
            subject_id: None,
            context_id: self.context_id,
            level,
            updated_at_u64,
            evidence_hash: B256::ZERO,
            evidence_uri: None,
            observed_at_u64,
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

fn normalize_optional_string(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn parse_context_id(tag1: &str) -> Option<ContextId> {
    trustnet_core::context_id_from_tag_v1(tag1).map(ContextId::from)
}

fn matches_trustnet_tag2_guard(tag2: &str) -> bool {
    tag2.trim() == "trustnet:v1"
}

fn score_from_value(value: i128, value_decimals: u8) -> Option<u8> {
    if value_decimals != 0 {
        return None;
    }
    if value < 0 {
        return None;
    }

    let score = u8::try_from(value).ok()?;
    if score > 100 {
        return None;
    }
    Some(score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordering::observed_at_for_chain;
    use trustnet_core::hashing::keccak256;
    use trustnet_core::types::Level;

    fn base_event() -> NewFeedbackEvent {
        NewFeedbackEvent {
            agent_id: U256::from(1u64),
            client_address: Address::repeat_byte(0x02),
            feedback_index: U256::from(7u64),
            value: 85,
            value_decimals: 0,
            tag1: "trustnet:ctx:code-exec:v1".to_string(),
            tag2: "trustnet:v1".to_string(),
            endpoint: "trustnet".to_string(),
            feedback_uri: Some("ipfs://example".to_string()),
            feedback_hash: B256::repeat_byte(0x11),
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            tx_hash: B256::repeat_byte(0xaa),
        }
    }

    #[test]
    fn test_to_edge_record_prefers_subject_id_target() {
        let event = base_event();

        // Core quantizer uses [80, 60, 40, 20] buckets:
        // 80-100 → +2
        let chain_id = 11155111;
        let identity_registry = Address::repeat_byte(0x33);
        let agent_wallet = Address::repeat_byte(0x44);
        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);
        let edge = event
            .to_edge_record(
                chain_id,
                123,
                observed_at_u64,
                Some(identity_registry),
                Some(agent_wallet),
            )
            .unwrap()
            .unwrap();

        assert_eq!(
            edge.rater,
            PrincipalId::from_evm_address(event.client_address)
        );
        let expected_context = ContextId::from(keccak256(event.tag1.as_bytes()));
        assert_eq!(edge.context_id, expected_context);
        let expected_subject =
            compute_subject_id(chain_id, &identity_registry, &event.agent_id.to_be_bytes());
        assert_eq!(edge.subject_id, Some(expected_subject));
        assert_eq!(edge.target, PrincipalId::from(*expected_subject.inner()));
        assert_eq!(edge.level, Level::strong_positive());
        assert_eq!(edge.chain_id, Some(chain_id));
        assert_eq!(edge.block_number, Some(100));
        assert_eq!(edge.tx_index, Some(5));
        assert_eq!(edge.log_index, Some(2));
        assert_eq!(edge.source, EdgeSource::Erc8004);
        assert_eq!(edge.tx_hash, Some(event.tx_hash));
        assert_eq!(edge.server_seq, None);
        assert_eq!(edge.evidence_hash, event.feedback_hash);
        assert_eq!(edge.evidence_uri, event.feedback_uri);
        assert_eq!(edge.observed_at_u64, observed_at_u64);
    }

    #[test]
    fn test_to_edge_record_guard_rejects_untagged() {
        let mut event = base_event();
        event.tag2 = "not-trustnet".to_string();

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_to_edge_record_guard_ignores_endpoint() {
        let mut event = base_event();
        event.endpoint = "not-trustnet".to_string();

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_to_edge_record_guard_rejects_hashed_tag2() {
        let mut event = base_event();
        event.tag2 = format!(
            "0x{}",
            hex::encode(trustnet_core::TAG_TRUSTNET_V1.as_slice())
        );

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_to_edge_record_guard_accepts_literal_tag2() {
        let mut event = base_event();
        event.tag2 = "trustnet:v1".to_string();

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_to_edge_record_rejects_nonzero_value_decimals() {
        let mut event = base_event();
        event.value_decimals = 2;

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_to_edge_record_rejects_value_out_of_range() {
        let mut event = base_event();
        event.value = 101;

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_to_edge_record_accepts_custom_context_string_v1() {
        let mut event = base_event();
        event.tag1 = "trustnet:ctx:agent-collab:code-exec:v1".to_string();

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_to_edge_record_rejects_hex_context_id_tag() {
        let mut event = base_event();
        event.tag1 = format!("0x{}", hex::encode(trustnet_core::CTX_CODE_EXEC.as_slice()));

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(
                1,
                1,
                observed_at_u64,
                Some(Address::repeat_byte(0x33)),
                Some(Address::repeat_byte(0x44)),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_to_edge_record_falls_back_to_subject_id_when_wallet_missing() {
        let event = base_event();
        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        let chain_id = 1u64;
        let identity_registry = Address::repeat_byte(0x33);
        let edge = event
            .to_edge_record(chain_id, 1, observed_at_u64, Some(identity_registry), None)
            .unwrap()
            .unwrap();

        let expected_subject =
            compute_subject_id(chain_id, &identity_registry, &event.agent_id.to_be_bytes());
        assert_eq!(edge.subject_id, Some(expected_subject));
        assert_eq!(edge.target, PrincipalId::from(*expected_subject.inner()));
    }

    #[test]
    fn test_to_edge_record_falls_back_to_wallet_without_subject_binding() {
        let event = base_event();
        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);
        let agent_wallet = Address::repeat_byte(0x44);

        let edge = event
            .to_edge_record(1, 1, observed_at_u64, None, Some(agent_wallet))
            .unwrap()
            .unwrap();

        assert_eq!(edge.subject_id, None);
        assert_eq!(edge.target, PrincipalId::from_evm_address(agent_wallet));
    }

    #[test]
    fn test_to_edge_record_requires_binding_source() {
        let event = base_event();
        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);

        assert!(event
            .to_edge_record(1, 1, observed_at_u64, None, None)
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

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);
        let edge = event
            .to_edge_record(11155111, 123, observed_at_u64)
            .unwrap();
        assert_eq!(edge.level, Level::strong_positive());
        assert_eq!(edge.source, EdgeSource::TrustGraph);
        assert_eq!(edge.chain_id, Some(11155111));
    }

    #[test]
    fn test_feedback_revoked_to_feedback_revocation_record() {
        let event = FeedbackRevokedEvent {
            agent_id: U256::from(123u64),
            client_address: Address::repeat_byte(0x22),
            feedback_index: U256::from(7u64),
            block_number: 101,
            tx_index: 3,
            log_index: 1,
            tx_hash: B256::repeat_byte(0xbb),
        };

        let observed_at_u64 =
            observed_at_for_chain(event.block_number, event.tx_index, event.log_index);
        let record = event.to_feedback_revocation_record(
            11155111,
            Address::repeat_byte(0x44),
            observed_at_u64,
        );

        assert_eq!(record.chain_id, 11155111);
        assert_eq!(record.agent_id, U256::from(123u64));
        assert_eq!(record.client_address, Address::repeat_byte(0x22));
        assert_eq!(record.feedback_index, U256::from(7u64));
        assert_eq!(record.observed_at_u64, observed_at_u64);
        assert_eq!(record.block_number, Some(101));
        assert_eq!(record.tx_index, Some(3));
        assert_eq!(record.log_index, Some(1));
        assert_eq!(record.tx_hash, Some(B256::repeat_byte(0xbb)));
    }
}
