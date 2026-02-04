//! Database types for the indexer storage layer.

use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use trustnet_core::types::{ContextId, Level, PrincipalId, SubjectId};

/// An edge record as stored in the database.
///
/// This represents the **latest-wins** edge for a canonical key:
/// `(rater_pid, target_pid, context_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeRecord {
    /// The rater (decider/curator) principal id (bytes32)
    pub rater: PrincipalId,

    /// The target (endorser/agent) principal id (bytes32)
    pub target: PrincipalId,

    /// Optional stable subject identity (bytes32).
    pub subject_id: Option<SubjectId>,

    /// Context ID (capability namespace)
    pub context_id: ContextId,

    /// Trust level (-2 to +2)
    pub level: Level,

    /// Updated-at timestamp committed in the leaf value (unix seconds).
    pub updated_at_u64: u64,

    /// Evidence hash committed in the leaf value (bytes32, zero if none).
    pub evidence_hash: B256,

    /// Evidence URI (not committed; optional).
    pub evidence_uri: Option<String>,

    /// Observed ordering key (monotonic-ish).
    pub observed_at_u64: u64,

    /// Source of the edge: "trust_graph" or "erc8004"
    pub source: EdgeSource,

    /// Chain id (required for chain sources, nullable for server mode).
    pub chain_id: Option<u64>,

    /// Block number where this edge was emitted (chain sources).
    pub block_number: Option<u64>,

    /// Transaction index within the block (chain sources).
    pub tx_index: Option<u64>,

    /// Log index within the transaction (chain sources).
    pub log_index: Option<u64>,

    /// Transaction hash where this edge was emitted (chain sources).
    pub tx_hash: Option<B256>,

    /// Server sequence ordering key (server mode).
    pub server_seq: Option<u64>,
}

/// ERC-8004 feedback record (raw ingestion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackRecord {
    /// Chain id.
    pub chain_id: u64,
    /// ERC-8004 Reputation contract address.
    pub erc8004_reputation: Address,
    /// ERC-8004 Identity contract address (optional).
    pub erc8004_identity: Option<Address>,
    /// Agent id (uint256).
    pub agent_id: U256,
    /// Client address.
    pub client_address: Address,
    /// Feedback index (uint256).
    pub feedback_index: U256,
    /// Raw value (int128, fixed-point).
    pub value: i128,
    /// Value decimals.
    pub value_decimals: u8,
    /// Tag1 string.
    pub tag1: String,
    /// Tag2 string.
    pub tag2: String,
    /// Endpoint string.
    pub endpoint: String,
    /// Feedback URI (optional).
    pub feedback_uri: Option<String>,
    /// Feedback hash (bytes32).
    pub feedback_hash: B256,
    /// Derived subject id (optional).
    pub subject_id: Option<SubjectId>,
    /// Observed ordering key.
    pub observed_at_u64: u64,
    /// Block number.
    pub block_number: Option<u64>,
    /// Transaction index.
    pub tx_index: Option<u64>,
    /// Log index.
    pub log_index: Option<u64>,
    /// Transaction hash.
    pub tx_hash: Option<B256>,
}

/// ERC-8004 response record (public verification stamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackResponseRecord {
    /// Chain id.
    pub chain_id: u64,
    /// ERC-8004 Reputation contract address.
    pub erc8004_reputation: Address,
    /// Agent id (uint256).
    pub agent_id: U256,
    /// Client address.
    pub client_address: Address,
    /// Feedback index (uint256).
    pub feedback_index: U256,
    /// Responder address.
    pub responder: Address,
    /// Response URI (optional).
    pub response_uri: Option<String>,
    /// Response hash (bytes32).
    pub response_hash: B256,
    /// Observed ordering key.
    pub observed_at_u64: u64,
    /// Block number.
    pub block_number: Option<u64>,
    /// Transaction index.
    pub tx_index: Option<u64>,
    /// Log index.
    pub log_index: Option<u64>,
    /// Transaction hash.
    pub tx_hash: Option<B256>,
}

/// Verified feedback stamp (ResponseAppended with valid TrustNet verification payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackVerifiedRecord {
    /// Chain id.
    pub chain_id: u64,
    /// ERC-8004 Reputation contract address.
    pub erc8004_reputation: Address,
    /// Agent id (uint256).
    pub agent_id: U256,
    /// Client address.
    pub client_address: Address,
    /// Feedback index (uint256).
    pub feedback_index: U256,
    /// Responder address.
    pub responder: Address,
    /// Response hash (bytes32).
    pub response_hash: B256,
    /// Observed ordering key.
    pub observed_at_u64: u64,
}

/// Source of an edge event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeSource {
    /// EdgeRated event from TrustGraph contract
    TrustGraph,

    /// NewFeedback event from ERC-8004 Reputation contract
    Erc8004,

    /// Private append-only log event (server mode)
    PrivateLog,
}

impl EdgeSource {
    /// Convert to database string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeSource::TrustGraph => "trust_graph",
            EdgeSource::Erc8004 => "erc8004",
            EdgeSource::PrivateLog => "private_log",
        }
    }
}

impl std::str::FromStr for EdgeSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trust_graph" => Ok(EdgeSource::TrustGraph),
            "erc8004" => Ok(EdgeSource::Erc8004),
            "private_log" => Ok(EdgeSource::PrivateLog),
            _ => Err(format!("Unknown edge source: {}", s)),
        }
    }
}

/// An epoch record as stored in the database.
///
/// Represents a published Merkle root commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRecord {
    /// Epoch number (monotonically increasing)
    pub epoch: u64,

    /// Sparse Merkle Map root hash
    pub graph_root: B256,

    /// Block number at which this epoch was published
    pub published_at_block: u64,

    /// Unix timestamp of publication
    pub published_at: i64,

    /// Transaction hash of the publishRoot call
    pub tx_hash: Option<B256>,

    /// Number of edges included in this epoch
    pub edge_count: u64,

    /// Canonical Root Manifest JSON (RFC 8785 JCS), when available.
    ///
    /// v0.4 uses this for reproducible root recomputation.
    pub manifest_json: Option<String>,

    /// `keccak256(canonical_manifest_json_bytes)` when available.
    pub manifest_hash: Option<B256>,

    /// Root publisher signature (server-mode authenticity), when available.
    ///
    /// v0.4: signature over `epoch || graphRoot || manifestHash` (see spec §10.5 / §16.2).
    pub publisher_sig: Option<Vec<u8>>,

    /// Unix timestamp (seconds) when the root was built (not necessarily published), when available.
    pub created_at_u64: Option<u64>,
}

/// Sync state record (singleton).
///
/// Tracks the indexer's progress through the blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    /// Last fully processed block number
    pub last_block_number: u64,

    /// Hash of the last processed block (for reorg detection)
    pub last_block_hash: B256,

    /// Unix timestamp of last update
    pub updated_at: i64,

    /// Chain ID (for safety)
    pub chain_id: u64,
}

/// A block record for reorg detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord {
    /// Block number
    pub block_number: u64,

    /// Block hash
    pub block_hash: B256,

    /// Parent block hash
    pub parent_hash: B256,

    /// Block timestamp
    pub timestamp: u64,

    /// Number of relevant events in this block
    pub event_count: u64,

    /// When this block was indexed
    pub indexed_at: i64,
}

/// Block coordinates for ordering events (latest-wins).
///
/// Used to determine which event is "latest" when multiple events
/// exist for the same (rater, target, context_id) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockCoordinates {
    /// Block number
    pub block_number: u64,

    /// Transaction index within block
    pub tx_index: u64,

    /// Log index within transaction
    pub log_index: u64,
}

impl BlockCoordinates {
    /// Create new block coordinates.
    pub fn new(block_number: u64, tx_index: u64, log_index: u64) -> Self {
        Self {
            block_number,
            tx_index,
            log_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_source_str_conversion() {
        assert_eq!(EdgeSource::TrustGraph.as_str(), "trust_graph");
        assert_eq!(EdgeSource::Erc8004.as_str(), "erc8004");
        assert_eq!(EdgeSource::PrivateLog.as_str(), "private_log");

        assert_eq!(
            "trust_graph".parse::<EdgeSource>().unwrap(),
            EdgeSource::TrustGraph
        );
        assert_eq!(
            "erc8004".parse::<EdgeSource>().unwrap(),
            EdgeSource::Erc8004
        );
        assert_eq!(
            "private_log".parse::<EdgeSource>().unwrap(),
            EdgeSource::PrivateLog
        );
        assert!("invalid".parse::<EdgeSource>().is_err());
    }

    #[test]
    fn test_block_coordinates_ordering() {
        let coord1 = BlockCoordinates::new(100, 5, 2);
        let coord2 = BlockCoordinates::new(100, 5, 3);
        let coord3 = BlockCoordinates::new(100, 6, 0);
        let coord4 = BlockCoordinates::new(101, 0, 0);

        assert!(coord1 < coord2);
        assert!(coord2 < coord3);
        assert!(coord3 < coord4);
    }
}
