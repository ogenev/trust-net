//! Root Manifest generation (TrustNet v1.1 spec).
//!
//! The Root Manifest provides enough data for third parties to recompute a
//! published `graphRoot` deterministically.

use alloy::primitives::{Address, B256};
use serde::Serialize;
use trustnet_core::types::ContextId;

fn hex_b256(v: &B256) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}

fn hex_addr(v: &Address) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}

/// Chain-mode manifest inputs (minimum required for reproducible chain roots).
#[derive(Debug, Clone)]
pub struct ChainManifestConfigV1 {
    /// Chain ID (EIP-155).
    pub chain_id: u64,
    /// TrustGraph contract address.
    pub trust_graph: Address,
    /// ERC-8004 Reputation contract address.
    pub erc8004_reputation: Address,
    /// ERC-8004 Identity contract address (optional).
    pub erc8004_identity: Option<Address>,
    /// ERC-8004 Validation contract address (optional).
    pub erc8004_validation: Option<Address>,
    /// RootRegistry contract address.
    pub root_registry: Address,
    /// Starting block used by the indexer.
    pub start_block: u64,
    /// Confirmations used for "safe block" determination.
    pub confirmations: u64,
}

/// Root Manifest (TrustNet v1.1 spec).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootManifestV1 {
    /// Manifest schema version.
    pub version: String,

    /// Chain ID when root is sourced from chain-mode events.
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// Contract addresses for chain-mode roots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contracts: Option<ManifestContractsV1>,

    /// Block window for chain-mode roots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<ManifestWindowV1>,

    /// Server stream details for server-mode roots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<ManifestServerV1>,

    /// TrustNet ingestion policy and context registry.
    pub trustnet: ManifestTrustnetV1,

    /// Sparse Merkle Tree hashing policy.
    pub smt: ManifestSmtV1,

    /// Optional implementation metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<ManifestSoftwareV1>,
}

/// Contract addresses included in a chain-mode manifest.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestContractsV1 {
    /// TrustGraph contract address.
    pub trust_graph: String,
    /// ERC-8004 Reputation contract address.
    pub reputation_registry: String,
    /// ERC-8004 Identity contract address (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_registry: Option<String>,
    /// ERC-8004 Validation contract address (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_registry: Option<String>,
    /// RootRegistry contract address.
    pub root_registry: String,
}

/// Block window for chain-mode roots.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestWindowV1 {
    /// Inclusive start block.
    pub from_block: u64,
    /// Inclusive end block.
    pub to_block: u64,
    /// Hash of `to_block`.
    pub to_block_hash: String,
    /// Confirmation depth used by the indexer.
    pub confirmations: u64,
}

/// Server-mode stream source metadata.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestServerV1 {
    /// Logical stream identifier (implementation-defined).
    pub stream_id: String,
    /// Starting sequence number included in this root.
    pub from_seq: u64,
    /// Ending sequence number included in this root.
    pub to_seq: u64,
    /// Stream hash commitment.
    pub stream_hash: String,
}

/// TrustNet ingestion policy section.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestTrustnetV1 {
    /// Required literal tag2.
    pub tag2: String,
    /// Allowed context tags.
    pub contexts: Vec<String>,
    /// Quantizer bucket cutoffs.
    pub quantizer: Vec<u8>,
    /// Required value decimals.
    pub value_decimals: u8,
}

/// Sparse Merkle tree policy section.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSmtV1 {
    /// Tree depth.
    pub depth: u16,
    /// Leaf hash algorithm.
    pub hash_leaf: String,
    /// Internal node hash algorithm.
    pub hash_node: String,
    /// Empty subtree hash algorithm.
    pub hash_empty: String,
}

/// Optional software metadata.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSoftwareV1 {
    /// Software identifier and version.
    pub version: String,
    /// RFC3339 timestamp for when the manifest/root was built.
    pub created_at: String,
}

/// Resolve TTL seconds for a context id using default TrustNet v1 policy.
///
/// Whitepaper v1.1 does not define per-context expiry, so this resolves to 0.
pub fn ttl_seconds_for_context_id(context_id: &ContextId) -> u64 {
    trustnet_core::ttl_seconds_for_context_id_v1(context_id.inner()).unwrap_or(0)
}

/// Build a chain-mode Root Manifest (TrustNet v1.1 schema).
pub fn build_chain_root_manifest_v1(
    config: &ChainManifestConfigV1,
    _epoch: u64,
    _graph_root: &B256,
    built_at_block: u64,
    to_block_hash: Option<B256>,
    created_at: String,
) -> RootManifestV1 {
    let to_block_hash = to_block_hash.unwrap_or(B256::ZERO);

    RootManifestV1 {
        version: "trustnet-v1.1".to_string(),
        chain_id: Some(config.chain_id),
        contracts: Some(ManifestContractsV1 {
            trust_graph: hex_addr(&config.trust_graph),
            reputation_registry: hex_addr(&config.erc8004_reputation),
            identity_registry: config.erc8004_identity.as_ref().map(hex_addr),
            validation_registry: config.erc8004_validation.as_ref().map(hex_addr),
            root_registry: hex_addr(&config.root_registry),
        }),
        window: Some(ManifestWindowV1 {
            from_block: config.start_block,
            to_block: built_at_block,
            to_block_hash: hex_b256(&to_block_hash),
            confirmations: config.confirmations,
        }),
        server: None,
        trustnet: ManifestTrustnetV1 {
            tag2: "trustnet:v1".to_string(),
            contexts: trustnet_core::CANONICAL_CONTEXTS_V1
                .iter()
                .map(|(name, _)| (*name).to_string())
                .collect(),
            quantizer: vec![80, 60, 40, 20],
            value_decimals: 0,
        },
        smt: ManifestSmtV1 {
            depth: 256,
            hash_leaf: "keccak256(0x00||K||V)".to_string(),
            hash_node: "keccak256(0x01||L||R)".to_string(),
            hash_empty: "keccak256(0x02)".to_string(),
        },
        software: Some(ManifestSoftwareV1 {
            version: format!("trustnet-indexer@{}", env!("CARGO_PKG_VERSION")),
            created_at,
        }),
    }
}

/// Build a server-mode Root Manifest (TrustNet v1.1 schema).
pub fn build_server_root_manifest_v1(
    _epoch: u64,
    _graph_root: &B256,
    stream_id: String,
    from_seq: u64,
    to_seq: u64,
    stream_hash: Option<B256>,
    created_at: String,
) -> RootManifestV1 {
    let stream_hash = stream_hash.unwrap_or(B256::ZERO);

    RootManifestV1 {
        version: "trustnet-v1.1".to_string(),
        chain_id: None,
        contracts: None,
        window: None,
        server: Some(ManifestServerV1 {
            stream_id,
            from_seq,
            to_seq,
            stream_hash: hex_b256(&stream_hash),
        }),
        trustnet: ManifestTrustnetV1 {
            tag2: "trustnet:v1".to_string(),
            contexts: trustnet_core::CANONICAL_CONTEXTS_V1
                .iter()
                .map(|(name, _)| (*name).to_string())
                .collect(),
            quantizer: vec![80, 60, 40, 20],
            value_decimals: 0,
        },
        smt: ManifestSmtV1 {
            depth: 256,
            hash_leaf: "keccak256(0x00||K||V)".to_string(),
            hash_node: "keccak256(0x01||L||R)".to_string(),
            hash_empty: "keccak256(0x02)".to_string(),
        },
        software: Some(ManifestSoftwareV1 {
            version: format!("trustnet-server@{}", env!("CARGO_PKG_VERSION")),
            created_at,
        }),
    }
}

/// Canonicalize a manifest using RFC 8785 JSON Canonicalization Scheme (JCS).
pub fn canonicalize_manifest(manifest: &RootManifestV1) -> Vec<u8> {
    serde_jcs::to_vec(manifest).expect("JCS serialization")
}
