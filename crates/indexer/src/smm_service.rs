//! Sparse Merkle Map service for TrustNet indexer.
//!
//! This module provides a service that periodically builds SMMs from stored edges
//! and caches the root for fast access during root publishing.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};
use trustnet_core::hashing::compute_edge_key;
use trustnet_smm::SmmBuilder;

use crate::storage::Storage;

fn ttl_seconds_for_context_id(context_id: &trustnet_core::types::ContextId) -> u64 {
    // Default: no TTL pruning for unknown contexts (MVP-safe).
    let id = context_id.inner();
    if *id == trustnet_core::CTX_PAYMENTS {
        return 30 * 24 * 60 * 60; // 30 days
    }
    if *id == trustnet_core::CTX_CODE_EXEC {
        return 7 * 24 * 60 * 60; // 7 days
    }
    if *id == trustnet_core::CTX_WRITES {
        return 7 * 24 * 60 * 60; // 7 days
    }
    if *id == trustnet_core::CTX_MESSAGING {
        return 7 * 24 * 60 * 60; // 7 days
    }
    0
}

fn edge_is_expired(edge: &crate::storage::EdgeRecord, as_of_u64: u64) -> bool {
    let ttl_seconds = ttl_seconds_for_context_id(&edge.context_id);
    if ttl_seconds == 0 {
        return false;
    }

    if edge.updated_at_u64 == 0 {
        // If we can't prove freshness, treat as expired for TTL-pruned contexts.
        return true;
    }

    edge.updated_at_u64.saturating_add(ttl_seconds) < as_of_u64
}

/// Cached SMM state.
#[derive(Debug, Clone)]
pub struct SmmState {
    /// The Merkle root of the SMM.
    pub root: alloy::primitives::B256,
    /// Number of edges included in this SMM.
    pub edge_count: u64,
    /// Block number at which this SMM was built.
    pub built_at_block: u64,
    /// Timestamp when this SMM was built (Unix timestamp).
    pub built_at: i64,
}

/// Periodic SMM builder that rebuilds the tree at a configured interval.
///
/// This builder runs in a background task and periodically:
/// 1. Fetches all edges from storage
/// 2. Builds a complete SMM
/// 3. Caches the root for fast access
///
/// Root publishers and other components can read the cached state
/// without blocking or rebuilding.
#[derive(Clone)]
pub struct PeriodicSmmBuilder {
    storage: Storage,
    interval: Duration,
    current_state: Arc<RwLock<Option<SmmState>>>,
}

impl PeriodicSmmBuilder {
    /// Create a new periodic SMM builder.
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage instance to fetch edges from
    /// * `interval` - How often to rebuild the SMM
    pub fn new(storage: Storage, interval: Duration) -> Self {
        Self {
            storage,
            interval,
            current_state: Arc::new(RwLock::new(None)),
        }
    }

    /// Run the periodic builder loop.
    ///
    /// This method runs indefinitely, building the SMM at the configured interval.
    /// It should be spawned as a background task.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage operations fail
    /// - SMM building fails
    pub async fn run(&self) -> Result<()> {
        info!("SMM builder starting with interval: {:?}", self.interval);

        // Build immediately on startup
        if let Err(e) = self.rebuild_smm().await {
            warn!("Initial SMM build failed: {}", e);
            // Continue anyway - will retry on next interval
        }

        // Then rebuild periodically
        let mut interval = tokio::time::interval(self.interval);
        interval.tick().await; // First tick completes immediately, skip it

        loop {
            interval.tick().await;

            if let Err(e) = self.rebuild_smm().await {
                warn!("SMM rebuild failed: {}", e);
                // Continue running - will retry on next interval
            }
        }
    }

    /// Get the current cached SMM state.
    ///
    /// Returns `None` if no SMM has been built yet.
    pub async fn get_current_state(&self) -> Option<SmmState> {
        self.current_state.read().await.clone()
    }

    /// Manually rebuild the SMM immediately.
    /// This is used for manual operations without requiring the background task.
    pub async fn rebuild_now(&self) -> Result<()> {
        self.rebuild_smm().await
    }

    /// Rebuild the SMM from current storage state.
    async fn rebuild_smm(&self) -> Result<()> {
        info!("Building SMM from current edges...");

        let built_at_u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Fetch all edges
        let mut edges = self
            .storage
            .get_all_edges_latest()
            .await
            .context("Failed to fetch edges from storage")?;

        // Apply v0.4 root-builder normalization:
        // - TTL pruning per context (manifested)
        // - treat neutral edges (level 0) as absence
        edges.retain(|e| e.level.value() != 0);
        edges.retain(|e| !edge_is_expired(e, built_at_u64));

        if edges.is_empty() {
            info!("No edges found, SMM root will be default empty-tree root");
            let empty_root = trustnet_smm::SmmBuilder::new().build().root();
            let state = SmmState {
                root: empty_root,
                edge_count: 0,
                built_at_block: self.storage.get_sync_state().await?.last_block_number,
                built_at: built_at_u64 as i64,
            };
            *self.current_state.write().await = Some(state);
            return Ok(());
        }

        info!("Building SMM from {} edges", edges.len());

        // Build SMM
        // Sort by edgeKey for deterministic construction (even though the map structure is order-independent).
        edges.sort_by_key(|edge| compute_edge_key(&edge.rater, &edge.target, &edge.context_id));

        let mut builder = SmmBuilder::new();
        for edge in &edges {
            let key = compute_edge_key(&edge.rater, &edge.target, &edge.context_id);
            let leaf_value = trustnet_core::LeafValueV1 {
                level: edge.level,
                updated_at_u64: edge.updated_at_u64,
                evidence_hash: edge.evidence_hash,
            }
            .encode()
            .to_vec();
            builder
                .insert(key, leaf_value)
                .context("Failed to insert edge into SMM builder")?;
        }

        let smm = builder.build();
        let root = smm.root();

        // Get current block number
        let sync_state = self.storage.get_sync_state().await?;

        // Create and cache state
        let state = SmmState {
            root,
            edge_count: edges.len() as u64,
            built_at_block: sync_state.last_block_number,
            built_at: built_at_u64 as i64,
        };

        info!(
            "SMM built successfully: root=0x{}, edges={}, block={}",
            hex::encode(state.root),
            state.edge_count,
            state.built_at_block
        );

        // Update cached state
        *self.current_state.write().await = Some(state);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::EdgeRecord;
    use tempfile::NamedTempFile;
    use trustnet_core::types::{ContextId, Level, PrincipalId};

    async fn setup_storage_with_edges() -> (Storage, NamedTempFile) {
        let temp_db = NamedTempFile::new().unwrap();
        let storage = Storage::new_with_path(temp_db.path(), None, None)
            .await
            .unwrap();
        storage.run_migrations().await.unwrap();

        // Insert some test edges
        let rater1 = PrincipalId::from([0x11; 32]);
        let rater2 = PrincipalId::from([0x22; 32]);
        let target1 = PrincipalId::from([0xaa; 32]);
        let target2 = PrincipalId::from([0xbb; 32]);
        let context = ContextId::from([0x01; 32]);

        let edge1 = EdgeRecord {
            rater: rater1,
            target: target1,
            subject_id: None,
            context_id: context,
            level: Level::positive(),
            updated_at_u64: 1234567890,
            evidence_hash: alloy::primitives::B256::ZERO,
            evidence_uri: None,
            observed_at_u64: 1234567890,
            source: crate::storage::EdgeSource::TrustGraph,
            chain_id: Some(1),
            block_number: Some(100),
            tx_index: Some(0),
            log_index: Some(0),
            tx_hash: Some(alloy::primitives::B256::repeat_byte(0xaa)),
            server_seq: None,
        };

        let edge2 = EdgeRecord {
            rater: rater2,
            target: target2,
            subject_id: None,
            context_id: context,
            level: Level::strong_positive(),
            updated_at_u64: 1234567891,
            evidence_hash: alloy::primitives::B256::ZERO,
            evidence_uri: None,
            observed_at_u64: 1234567891,
            source: crate::storage::EdgeSource::TrustGraph,
            chain_id: Some(1),
            block_number: Some(101),
            tx_index: Some(0),
            log_index: Some(0),
            tx_hash: Some(alloy::primitives::B256::repeat_byte(0xbb)),
            server_seq: None,
        };

        storage.append_edge_raw(&edge1).await.unwrap();
        storage.upsert_edge_latest(&edge1).await.unwrap();
        storage.append_edge_raw(&edge2).await.unwrap();
        storage.upsert_edge_latest(&edge2).await.unwrap();

        (storage, temp_db)
    }

    #[tokio::test]
    async fn test_builder_empty_edges() {
        let temp_db = NamedTempFile::new().unwrap();
        let storage = Storage::new_with_path(temp_db.path(), None, None)
            .await
            .unwrap();
        storage.run_migrations().await.unwrap();

        let builder = PeriodicSmmBuilder::new(storage.clone(), Duration::from_secs(60));

        // Build with no edges
        builder.rebuild_smm().await.unwrap();

        let state = builder.get_current_state().await.unwrap();
        let expected_root = trustnet_smm::SmmBuilder::new().build().root();
        assert_eq!(state.root, expected_root);
        assert_eq!(state.edge_count, 0);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_builder_with_edges() {
        let (storage, _temp_db) = setup_storage_with_edges().await;

        let builder = PeriodicSmmBuilder::new(storage.clone(), Duration::from_secs(60));

        // Build with edges
        builder.rebuild_smm().await.unwrap();

        let state = builder.get_current_state().await.unwrap();
        assert_ne!(state.root, alloy::primitives::B256::ZERO);
        assert_eq!(state.edge_count, 2);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_builder_deterministic() {
        let (storage, _temp_db) = setup_storage_with_edges().await;

        let builder = PeriodicSmmBuilder::new(storage.clone(), Duration::from_secs(60));

        // Build twice
        builder.rebuild_smm().await.unwrap();
        let state1 = builder.get_current_state().await.unwrap();

        builder.rebuild_smm().await.unwrap();
        let state2 = builder.get_current_state().await.unwrap();

        // Should produce same root
        assert_eq!(state1.root, state2.root);
        assert_eq!(state1.edge_count, state2.edge_count);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_get_state_before_build() {
        let temp_db = NamedTempFile::new().unwrap();
        let storage = Storage::new_with_path(temp_db.path(), None, None)
            .await
            .unwrap();
        storage.run_migrations().await.unwrap();

        let builder = PeriodicSmmBuilder::new(storage.clone(), Duration::from_secs(60));

        // Should return None before first build
        assert!(builder.get_current_state().await.is_none());

        storage.close().await;
    }

    #[tokio::test]
    async fn test_builder_updates_after_new_edges() {
        let (storage, _temp_db) = setup_storage_with_edges().await;

        let builder = PeriodicSmmBuilder::new(storage.clone(), Duration::from_secs(60));

        // Initial build
        builder.rebuild_smm().await.unwrap();
        let state1 = builder.get_current_state().await.unwrap();
        assert_eq!(state1.edge_count, 2);

        // Add another edge
        let edge3 = EdgeRecord {
            rater: PrincipalId::from([0x33; 32]),
            target: PrincipalId::from([0xcc; 32]),
            subject_id: None,
            context_id: ContextId::from([0x01; 32]),
            level: Level::negative(),
            updated_at_u64: 1234567892,
            evidence_hash: alloy::primitives::B256::ZERO,
            evidence_uri: None,
            observed_at_u64: 1234567892,
            source: crate::storage::EdgeSource::TrustGraph,
            chain_id: Some(1),
            block_number: Some(102),
            tx_index: Some(0),
            log_index: Some(0),
            tx_hash: Some(alloy::primitives::B256::repeat_byte(0xcc)),
            server_seq: None,
        };
        storage.append_edge_raw(&edge3).await.unwrap();
        storage.upsert_edge_latest(&edge3).await.unwrap();

        // Rebuild
        builder.rebuild_smm().await.unwrap();
        let state2 = builder.get_current_state().await.unwrap();

        // Should have new edge count and different root
        assert_eq!(state2.edge_count, 3);
        assert_ne!(state1.root, state2.root);

        storage.close().await;
    }
}
