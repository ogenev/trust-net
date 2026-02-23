//! Server-mode root building utilities.
//!
//! This module provides reusable logic for computing and inserting signed
//! server-mode roots from `edges_latest`.

use alloy::signers::Signer;
use anyhow::{Context, Result};
use trustnet_core::hashing::{compute_edge_key, compute_root_signature_hash, keccak256};
use trustnet_core::{LeafValueV1, B256};
use trustnet_smm::SmmBuilder;

use crate::root_manifest::{
    build_server_root_manifest_v1, canonicalize_manifest, ServerManifestConfigV1,
};
use crate::storage::{DeploymentMode, EdgeRecord, EpochRecord, Storage};

/// Input parameters for server-mode root building.
#[derive(Debug, Clone)]
pub struct BuildServerRootInput {
    /// Database URL (for example: `sqlite://trustnet.db`).
    pub database_url: String,
    /// Publisher private key as 32-byte hex (with or without `0x`).
    pub publisher_key: String,
    /// Stream identifier to embed in the manifest.
    pub stream_id: String,
    /// Optional stream hash (`0x`-prefixed bytes32).
    pub stream_hash: Option<String>,
    /// Optional epoch override. Must be greater than latest stored epoch.
    pub epoch: Option<u64>,
    /// If true, do not insert an epoch record.
    pub dry_run: bool,
}

/// Result of a server-mode root build operation.
#[derive(Debug, Clone)]
pub struct BuildServerRootOutput {
    /// Epoch number for the root.
    pub epoch: u64,
    /// Built sparse Merkle root.
    pub graph_root: B256,
    /// Number of committed edges.
    pub edge_count: u64,
    /// Canonicalized manifest hash.
    pub manifest_hash: B256,
    /// Root publisher signature bytes.
    pub publisher_sig: Vec<u8>,
    /// Minimum private-log sequence included in the manifest.
    pub from_seq: u64,
    /// Maximum private-log sequence included in the manifest.
    pub to_seq: u64,
    /// Whether the epoch was inserted into storage.
    pub inserted: bool,
}

fn edge_is_expired(edge: &EdgeRecord, as_of_u64: u64) -> bool {
    let ttl_seconds = crate::root_manifest::ttl_seconds_for_context_id(&edge.context_id);
    if ttl_seconds == 0 {
        return false;
    }

    if edge.updated_at_u64 == 0 {
        return true;
    }

    edge.updated_at_u64.saturating_add(ttl_seconds) < as_of_u64
}

async fn server_seq_range(storage: &Storage) -> Result<(u64, u64)> {
    let row: (Option<i64>, Option<i64>) = sqlx::query_as(
        r#"
        SELECT MIN(server_seq), MAX(server_seq)
        FROM edges_raw
        WHERE source = 'private_log'
        "#,
    )
    .fetch_one(storage.pool())
    .await
    .context("Failed to query server_seq range")?;

    let min = row.0.unwrap_or(0).max(0) as u64;
    let max = row.1.unwrap_or(0).max(0) as u64;
    Ok((min, max))
}

fn parse_b256(input: &str) -> Result<B256> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32-byte hex");
    Ok(B256::from_slice(&bytes))
}

/// Build a server-mode root, sign it, and optionally insert it into storage.
pub async fn build_server_root(input: &BuildServerRootInput) -> Result<BuildServerRootOutput> {
    let storage = Storage::new(&input.database_url, None, None)
        .await
        .context("Failed to connect to database")?;
    storage
        .run_migrations()
        .await
        .context("Failed to run migrations")?;
    storage
        .enforce_deployment_mode(DeploymentMode::Server)
        .await
        .context("Database is not configured for server deployment mode")?;

    let now_u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let mut edges = storage
        .get_all_edges_latest()
        .await
        .context("Failed to fetch edges_latest")?;

    edges.retain(|edge| !edge_is_expired(edge, now_u64));
    edges.sort_by_key(|edge| compute_edge_key(&edge.rater, &edge.target, &edge.context_id));

    let mut builder = SmmBuilder::new();
    for edge in &edges {
        let key = compute_edge_key(&edge.rater, &edge.target, &edge.context_id);
        let leaf_value = LeafValueV1 { level: edge.level }.encode().to_vec();
        builder
            .insert(key, leaf_value)
            .context("Failed to insert edge into SMM builder")?;
    }

    let smm = builder.build();
    let root = smm.root();
    let edge_count = edges.len() as u64;

    let latest_epoch = storage.get_latest_epoch().await?;
    let next_epoch = latest_epoch.as_ref().map(|e| e.epoch + 1).unwrap_or(1);
    let epoch = input.epoch.unwrap_or(next_epoch);
    if epoch <= latest_epoch.as_ref().map(|e| e.epoch).unwrap_or(0) {
        anyhow::bail!("epoch {} must be greater than latest", epoch);
    }

    let (from_seq, to_seq) = server_seq_range(&storage).await?;
    let stream_hash = match input.stream_hash.as_deref() {
        Some(value) => Some(parse_b256(value)?),
        None => None,
    };

    let created_at = chrono::Utc::now().to_rfc3339();
    let registered_contexts = storage.get_registered_context_tags().await?;
    let manifest = build_server_root_manifest_v1(
        epoch,
        &root,
        ServerManifestConfigV1 {
            stream_id: input.stream_id.clone(),
            from_seq,
            to_seq,
            stream_hash,
            registered_contexts,
            created_at,
        },
    );

    let canonical = canonicalize_manifest(&manifest);
    let manifest_hash = keccak256(&canonical);

    let signer = input
        .publisher_key
        .trim_start_matches("0x")
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .context("Failed to parse publisher key")?;

    let digest = compute_root_signature_hash(epoch, &root, &manifest_hash);
    let signature = signer
        .sign_hash(&digest)
        .await
        .context("Failed to sign root digest")?;
    let publisher_sig = signature.as_bytes().to_vec();

    if !input.dry_run {
        let epoch_record = EpochRecord {
            epoch,
            graph_root: root,
            published_at_block: 0,
            published_at: now_u64 as i64,
            tx_hash: None,
            edge_count,
            manifest_json: Some(
                String::from_utf8(canonical).context("Manifest must be valid UTF-8")?,
            ),
            manifest_uri: None,
            manifest_hash: Some(manifest_hash),
            publisher_sig: Some(publisher_sig.clone()),
            created_at_u64: Some(now_u64),
        };

        storage
            .insert_epoch(&epoch_record)
            .await
            .context("Failed to insert epoch")?;
    }

    Ok(BuildServerRootOutput {
        epoch,
        graph_root: root,
        edge_count,
        manifest_hash,
        publisher_sig,
        from_seq,
        to_seq,
        inserted: !input.dry_run,
    })
}
