//! SMM cache for proof generation.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use trustnet_core::{compute_edge_key, Address, ContextId, Level, B256};
use trustnet_smm::{Smm, SmmBuilder};

/// Raw edge tuple from database: (rater, target, context_id, level)
/// Serializable for epoch snapshot persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEdge(pub Vec<u8>, pub Vec<u8>, pub Vec<u8>, pub i32);

/// Simple cache for the Sparse Merkle Map.
///
/// Holds the current SMM tree in memory for proof generation.
/// The cache tracks the root hash it was built from to detect staleness
/// when the database is updated by the indexer.
///
/// Epoch snapshots are persisted to disk so that we can rebuild the
/// SMM for any published epoch even after new edges are ingested.
///
/// The SMM is stored behind an Arc so that multiple readers can
/// access it concurrently without cloning the entire tree.
#[derive(Clone)]
pub struct SmmCache {
    smm: Arc<RwLock<Option<Arc<Smm>>>>,
    /// The root hash that the current SMM was built from.
    /// Used to detect if the database has changed.
    cached_root: Arc<RwLock<Option<B256>>>,
    /// Directory where epoch snapshots are stored
    cache_dir: PathBuf,
}

impl SmmCache {
    /// Create a new empty SMM cache with the specified cache directory.
    ///
    /// The cache directory will be created if it doesn't exist.
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        Self {
            smm: Arc::new(RwLock::new(None)),
            cached_root: Arc::new(RwLock::new(None)),
            cache_dir: cache_dir.as_ref().to_path_buf(),
        }
    }

    /// Get the path to the epoch snapshot file for a given root hash.
    fn epoch_snapshot_path(&self, root: &B256) -> PathBuf {
        self.cache_dir
            .join(format!("epoch_{}.snapshot", hex::encode(root)))
    }

    /// Save the edge list for an epoch to disk.
    ///
    /// This allows us to rebuild the SMM for this epoch even after
    /// new edges are ingested into the database.
    async fn save_epoch_snapshot(&self, root: &B256, edges: &[RawEdge]) -> anyhow::Result<()> {
        // Ensure cache directory exists
        fs::create_dir_all(&self.cache_dir).await?;

        let snapshot_path = self.epoch_snapshot_path(root);

        // Serialize edges as JSON for simplicity (could use bincode for efficiency)
        let json = serde_json::to_vec(edges)?;

        // Write atomically using a temp file
        let temp_path = snapshot_path.with_extension("tmp");
        fs::write(&temp_path, json).await?;
        fs::rename(&temp_path, &snapshot_path).await?;

        Ok(())
    }

    /// Load the edge list for an epoch from disk.
    ///
    /// Returns None if no snapshot exists for this epoch.
    async fn load_epoch_snapshot(&self, root: &B256) -> anyhow::Result<Option<Vec<RawEdge>>> {
        let snapshot_path = self.epoch_snapshot_path(root);

        if !snapshot_path.exists() {
            return Ok(None);
        }

        let json = fs::read(&snapshot_path).await?;
        let edges: Vec<RawEdge> = serde_json::from_slice(&json)?;

        Ok(Some(edges))
    }

    /// Get a reference to the current SMM.
    ///
    /// Returns an Arc to the SMM, which is cheap to clone (just increments
    /// a reference count). This avoids deep-copying the entire tree on
    /// every proof request.
    ///
    /// Returns None if the SMM hasn't been built yet.
    pub async fn get(&self) -> Option<Arc<Smm>> {
        self.smm.read().await.clone()
    }

    /// Get the cached root hash.
    ///
    /// Returns the root hash that the current SMM was built from.
    /// Returns None if no SMM has been built yet.
    pub async fn get_cached_root(&self) -> Option<B256> {
        *self.cached_root.read().await
    }

    /// Check if the cache is stale compared to the database.
    ///
    /// Returns true if the database root differs from the cached root,
    /// indicating that the cache needs to be rebuilt.
    pub async fn is_stale(&self, db_root: B256) -> bool {
        match self.get_cached_root().await {
            Some(cached) => cached != db_root,
            None => true, // No cache yet, consider stale
        }
    }

    /// Try to rebuild the cache for a specific published epoch.
    ///
    /// This method first attempts to load the epoch snapshot from disk.
    /// If no snapshot exists, it builds from the provided edges (which may
    /// fail if the edges table contains newer data than the published epoch).
    ///
    /// On successful build that matches the published root, the snapshot
    /// is saved to disk for future rebuilds.
    ///
    /// Returns Ok(true) if the cache was successfully rebuilt and stored.
    /// Returns Ok(false) if the rebuild produced a different root (data not yet published).
    /// Returns Err if there was an error during the rebuild.
    pub async fn try_rebuild_for_epoch(
        &self,
        edges: Vec<RawEdge>,
        published_root: B256,
    ) -> anyhow::Result<bool> {
        // First, try to load from persisted snapshot
        if let Some(snapshot_edges) = self.load_epoch_snapshot(&published_root).await? {
            // We have a cached snapshot for this epoch - build from it
            let smm = self.build_smm_from_edges(&snapshot_edges)?;
            let actual_root = smm.root();

            if actual_root == published_root {
                *self.smm.write().await = Some(Arc::new(smm));
                *self.cached_root.write().await = Some(actual_root);
                return Ok(true);
            } else {
                // Snapshot is corrupted or incorrect - fall through to rebuild
            }
        }

        // No snapshot or snapshot failed - build from provided edges
        let smm = self.build_smm_from_edges(&edges)?;
        let actual_root = smm.root();

        // Only store if the root matches the published epoch
        if actual_root == published_root {
            // Save snapshot for future rebuilds
            if let Err(e) = self.save_epoch_snapshot(&published_root, &edges).await {
                // Log error but don't fail the rebuild
                eprintln!("Warning: Failed to save epoch snapshot: {}", e);
            }

            *self.smm.write().await = Some(Arc::new(smm));
            *self.cached_root.write().await = Some(actual_root);
            Ok(true)
        } else {
            // Root mismatch - edges table is newer than published epoch
            // Don't update cache
            Ok(false)
        }
    }

    /// Build an SMM from a list of edges.
    ///
    /// Helper method used by try_rebuild_for_epoch.
    fn build_smm_from_edges(&self, edges: &[RawEdge]) -> anyhow::Result<Smm> {
        let mut builder = SmmBuilder::new();

        for edge in edges {
            let RawEdge(rater_bytes, target_bytes, context_bytes, level_i32) = edge;

            // Parse addresses and context
            if rater_bytes.len() != 20 || target_bytes.len() != 20 || context_bytes.len() != 32 {
                continue; // Skip malformed entries
            }

            let rater = Address::from_slice(rater_bytes);
            let target = Address::from_slice(target_bytes);
            let context = ContextId::new(B256::from_slice(context_bytes));

            // Convert level to SMM value
            if let Ok(level) = Level::new(*level_i32 as i8) {
                let key = compute_edge_key(&rater, &target, &context);
                let smm_value = level.to_smm_value();
                builder.insert(key, smm_value)?;
            }
        }

        Ok(builder.build())
    }
}
