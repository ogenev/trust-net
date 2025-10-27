//! Database types for the indexer storage layer.

use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use trustnet_core::types::{ContextId, Level};

/// An edge record as stored in the database.
///
/// This represents a trust rating from one address to another
/// within a specific context, with block coordinates for latest-wins ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeRecord {
    /// The rater (observer/curator) address
    pub rater: Address,

    /// The target (hinge/agent) address
    pub target: Address,

    /// Context ID (capability namespace)
    pub context_id: ContextId,

    /// Trust level (-2 to +2)
    pub level: Level,

    /// Block number where this edge was emitted
    pub block_number: u64,

    /// Transaction index within the block
    pub tx_index: u64,

    /// Log index within the transaction
    pub log_index: u64,

    /// When this edge was ingested (Unix timestamp)
    pub ingested_at: i64,

    /// Source of the edge: "trust_graph" or "erc8004"
    pub source: EdgeSource,

    /// Transaction hash where this edge was emitted
    pub tx_hash: Option<B256>,
}

/// Source of an edge event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeSource {
    /// EdgeRated event from TrustGraph contract
    TrustGraph,

    /// NewFeedback event from ERC-8004 Reputation contract
    Erc8004,
}

impl EdgeSource {
    /// Convert to database string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeSource::TrustGraph => "trust_graph",
            EdgeSource::Erc8004 => "erc8004",
        }
    }

    /// Parse from database string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "trust_graph" => Some(EdgeSource::TrustGraph),
            "erc8004" => Some(EdgeSource::Erc8004),
            _ => None,
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

    /// Root manifest JSON (for reproducibility)
    pub manifest: Option<String>,
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

        assert_eq!(EdgeSource::from_str("trust_graph"), Some(EdgeSource::TrustGraph));
        assert_eq!(EdgeSource::from_str("erc8004"), Some(EdgeSource::Erc8004));
        assert_eq!(EdgeSource::from_str("invalid"), None);
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
