//! Root Manifest generation (TrustNet spec v0.4).
//!
//! The Root Manifest provides enough data for third parties to recompute a published `graphRoot`.

use alloy::primitives::{Address, B256};
use serde::Serialize;
use std::collections::BTreeMap;
use trustnet_core::types::ContextId;

fn hex_b256(v: &B256) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}

fn hex_addr(v: &Address) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}

/// Chain-mode manifest inputs (the minimum needed for reproducible chain roots).
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

    /// RootRegistry contract address.
    pub root_registry: Address,

    /// Starting block used by the indexer.
    pub start_block: u64,

    /// Confirmations used for "safe block" determination.
    pub confirmations: u64,
}

/// Root Manifest (v0.6 MVP).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootManifestV1 {
    /// Spec version string (e.g., "trustnet-spec-0.6").
    pub spec_version: String,

    /// Epoch number for this root (monotonic).
    pub epoch: u64,

    /// Graph root as `0x`-prefixed bytes32 hex.
    pub graph_root: String,

    /// Source mode ("local" | "server" | "chain").
    pub source_mode: SourceModeV1,

    /// Source metadata required to reproduce the root.
    pub sources: ManifestSourcesV1,

    /// Hash of the canonical context registry (see spec §10.3).
    pub context_registry_hash: String,

    /// Guard for ERC-8004 TrustNet edges (required when ingesting ERC-8004 edges).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erc8004_trust_edge_guard: Option<Erc8004TrustEdgeGuardV1>,

    /// Binding policy for ERC-8004 subject → principal (required when ingesting ERC-8004 edges).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erc8004_target_binding_policy: Option<Erc8004TargetBindingPolicyV1>,

    /// Quantization policy used for mapping ERC-8004 signals into levels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erc8004_quantization_policy: Option<QuantizationPolicyV1>,

    /// TTL policy used to prune stale edges during root building.
    pub ttl_policy: TtlPolicyV1,

    /// Leaf value format identifier (e.g., "levelUpdatedAtEvidenceV1").
    pub leaf_value_format: String,

    /// Default edge value (neutral).
    pub default_edge_value: DefaultEdgeValueV1,

    /// Software version/build id.
    pub software_version: String,

    /// RFC3339 timestamp for when this manifest/root was built.
    pub created_at: String,
}

/// Root source mode (v0.4).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceModeV1 {
    /// Local mode (single machine; no network required).
    Local,
    /// Server mode (private append-only log; roots are signed).
    Server,
    /// Chain mode (signals and/or roots anchored on-chain).
    Chain,
}

/// Root sources object (varies by mode).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ManifestSourcesV1 {
    /// Chain-mode sources.
    Chain(ManifestChainSourcesV1),
    /// Server-mode sources.
    Server(ManifestServerSourcesV1),
}

/// Chain-mode sources section.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestChainSourcesV1 {
    /// Chain id.
    pub chain_id: u64,

    /// Contract addresses used as sources.
    pub contracts: ManifestContractsV1,

    /// Block window covered by this root.
    pub window: ManifestWindowV1,

    /// Confirmation depth used by the indexer.
    pub confirmations: u64,
}

/// Server-mode sources section.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestServerSourcesV1 {
    /// Logical stream identifier (implementation-defined).
    pub stream_id: String,

    /// Starting sequence number included in this root.
    pub from_seq: u64,

    /// Ending sequence number included in this root.
    pub to_seq: u64,

    /// Stream hash commitment (implementation-defined; MVP may be zero).
    pub stream_hash: String,
}

/// Contract addresses included in a chain-mode manifest.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestContractsV1 {
    /// TrustGraph contract address.
    pub trust_graph: String,

    /// ERC-8004 Reputation contract address.
    pub erc8004_reputation: String,

    /// ERC-8004 Identity contract address (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erc8004_identity: Option<String>,

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

    /// Hash of `to_block` (or zero if unknown in MVP).
    pub to_block_hash: String,
}

/// Guard for ERC-8004 TrustNet edges.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc8004TrustEdgeGuardV1 {
    /// Required endpoint string.
    pub endpoint: String,
    /// Required tag2 string.
    pub tag2: String,
    /// Accepted tag1 formats (e.g., "contextString", "bytes32Hex").
    pub tag1_formats: Vec<String>,
}

/// Binding policy for ERC-8004 agentId → agentWallet.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc8004TargetBindingPolicyV1 {
    /// Policy type (e.g., "agentWalletAtBlock").
    pub r#type: String,
    /// ERC-8004 Identity Registry address.
    pub identity_registry: String,
    /// Block height at which binding is resolved.
    pub at_block: u64,
}

/// Quantization policy (v0.4 MVP uses buckets).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuantizationPolicyV1 {
    /// Policy type ("buckets").
    pub r#type: String,

    /// Score bucket cutoffs (0-100) used to map to levels.
    pub buckets: Vec<u8>,
}

/// TTL policy entry for a context.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TtlPolicyEntryV1 {
    /// Time-to-live in seconds (0 disables pruning).
    pub ttl_seconds: u64,
}

/// TTL policy keyed by canonical context strings.
pub type TtlPolicyV1 = BTreeMap<String, TtlPolicyEntryV1>;

/// Default edge value committed by the sparse map (neutral).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultEdgeValueV1 {
    /// Default trust level (MVP: 0).
    pub level: i8,
}

/// Compute the `contextRegistryHash` for the canonical registry used by this implementation.
///
/// This is `keccak256(JCS(contextStrings[]))`.
pub fn build_context_registry_hash_v1() -> B256 {
    // Canonical ordering must not change across versions.
    let contexts: Vec<&str> = trustnet_core::CANONICAL_CONTEXTS_V0_7
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let canonical = serde_jcs::to_vec(&contexts).expect("JCS serialization");
    trustnet_core::hashing::keccak256(&canonical)
}

/// Default TTL policy (MVP).
///
/// Represented as a JSON object keyed by canonical context strings.
pub fn default_ttl_policy_v1() -> TtlPolicyV1 {
    let mut policy = TtlPolicyV1::new();
    for (context, context_id) in trustnet_core::CANONICAL_CONTEXTS_V0_7 {
        let ttl_seconds = trustnet_core::ttl_seconds_for_context_id_v0_7(&context_id).unwrap_or(0);
        policy.insert(context.to_string(), TtlPolicyEntryV1 { ttl_seconds });
    }
    policy
}

/// Resolve TTL seconds for a context id using the default policy.
pub fn ttl_seconds_for_context_id(context_id: &ContextId) -> u64 {
    trustnet_core::ttl_seconds_for_context_id_v0_7(context_id.inner()).unwrap_or(0)
}

/// Build a chain-mode Root Manifest (v0.4).
pub fn build_chain_root_manifest_v1(
    config: &ChainManifestConfigV1,
    epoch: u64,
    graph_root: &B256,
    built_at_block: u64,
    to_block_hash: Option<B256>,
    created_at: String,
) -> RootManifestV1 {
    let context_registry_hash = build_context_registry_hash_v1();
    let to_block_hash = to_block_hash.unwrap_or(B256::ZERO);

    RootManifestV1 {
        spec_version: "trustnet-spec-0.6".to_string(),
        epoch,
        graph_root: hex_b256(graph_root),
        source_mode: SourceModeV1::Chain,
        sources: ManifestSourcesV1::Chain(ManifestChainSourcesV1 {
            chain_id: config.chain_id,
            contracts: ManifestContractsV1 {
                trust_graph: hex_addr(&config.trust_graph),
                erc8004_reputation: hex_addr(&config.erc8004_reputation),
                erc8004_identity: config.erc8004_identity.as_ref().map(hex_addr),
                root_registry: hex_addr(&config.root_registry),
            },
            window: ManifestWindowV1 {
                from_block: config.start_block,
                to_block: built_at_block,
                to_block_hash: hex_b256(&to_block_hash),
            },
            confirmations: config.confirmations,
        }),
        context_registry_hash: hex_b256(&context_registry_hash),
        erc8004_trust_edge_guard: Some(Erc8004TrustEdgeGuardV1 {
            endpoint: "trustnet".to_string(),
            tag2: "trustnet:v1".to_string(),
            tag1_formats: vec!["contextString".to_string(), "bytes32Hex".to_string()],
        }),
        erc8004_target_binding_policy: config.erc8004_identity.as_ref().map(|addr| {
            Erc8004TargetBindingPolicyV1 {
                r#type: "agentWalletAtBlock".to_string(),
                identity_registry: hex_addr(addr),
                at_block: built_at_block,
            }
        }),
        erc8004_quantization_policy: Some(QuantizationPolicyV1 {
            r#type: "buckets".to_string(),
            buckets: vec![80, 60, 40, 20],
        }),
        ttl_policy: default_ttl_policy_v1(),
        leaf_value_format: "levelUpdatedAtEvidenceV1".to_string(),
        default_edge_value: DefaultEdgeValueV1 { level: 0 },
        software_version: format!("trustnet-indexer@{}", env!("CARGO_PKG_VERSION")),
        created_at,
    }
}

/// Build a server-mode Root Manifest (v0.4).
pub fn build_server_root_manifest_v1(
    epoch: u64,
    graph_root: &B256,
    stream_id: String,
    from_seq: u64,
    to_seq: u64,
    stream_hash: Option<B256>,
    created_at: String,
) -> RootManifestV1 {
    let context_registry_hash = build_context_registry_hash_v1();
    let stream_hash = stream_hash.unwrap_or(B256::ZERO);

    RootManifestV1 {
        spec_version: "trustnet-spec-0.6".to_string(),
        epoch,
        graph_root: hex_b256(graph_root),
        source_mode: SourceModeV1::Server,
        sources: ManifestSourcesV1::Server(ManifestServerSourcesV1 {
            stream_id,
            from_seq,
            to_seq,
            stream_hash: hex_b256(&stream_hash),
        }),
        context_registry_hash: hex_b256(&context_registry_hash),
        erc8004_trust_edge_guard: None,
        erc8004_target_binding_policy: None,
        erc8004_quantization_policy: None,
        ttl_policy: default_ttl_policy_v1(),
        leaf_value_format: "levelUpdatedAtEvidenceV1".to_string(),
        default_edge_value: DefaultEdgeValueV1 { level: 0 },
        software_version: format!("trustnet-server@{}", env!("CARGO_PKG_VERSION")),
        created_at,
    }
}

/// Canonicalize a manifest using RFC 8785 JSON Canonicalization Scheme (JCS).
pub fn canonicalize_manifest(manifest: &RootManifestV1) -> Vec<u8> {
    serde_jcs::to_vec(manifest).expect("JCS serialization")
}
