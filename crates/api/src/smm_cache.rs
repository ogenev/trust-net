//! Sparse Merkle Map cache for proof generation (spec v1.1).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use trustnet_smm::{Smm, SmmBuilder};

/// A leaf entry snapshot sufficient to rebuild an epoch tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotLeaf {
    /// Sparse Merkle Map key (edgeKey).
    pub key: trustnet_core::B256,
    /// Leaf value bytes (v1.1 encoding).
    #[serde(with = "serde_bytes")]
    pub leaf_value: Vec<u8>,
}

/// Simple cache for the Sparse Merkle Map.
///
/// Stores the current published epoch's tree in memory, and persists per-epoch snapshots to disk
/// keyed by `graphRoot` so the API can continue to serve proofs even after new edges are ingested.
#[derive(Clone)]
pub struct SmmCache {
    smm: Arc<RwLock<Option<Arc<Smm>>>>,
    cached_root: Arc<RwLock<Option<trustnet_core::B256>>>,
    cache_dir: PathBuf,
}

impl SmmCache {
    /// Create a new cache rooted at `cache_dir`.
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        Self {
            smm: Arc::new(RwLock::new(None)),
            cached_root: Arc::new(RwLock::new(None)),
            cache_dir: cache_dir.as_ref().to_path_buf(),
        }
    }

    fn epoch_snapshot_path(&self, root: &trustnet_core::B256) -> PathBuf {
        self.cache_dir
            .join(format!("epoch_{}.snapshot", hex::encode(root.as_slice())))
    }

    async fn save_epoch_snapshot(
        &self,
        root: &trustnet_core::B256,
        leaves: &[SnapshotLeaf],
    ) -> anyhow::Result<()> {
        fs::create_dir_all(&self.cache_dir).await?;
        let snapshot_path = self.epoch_snapshot_path(root);

        let json = serde_json::to_vec(leaves)?;
        let temp_path = snapshot_path.with_extension("tmp");
        fs::write(&temp_path, json).await?;
        fs::rename(&temp_path, &snapshot_path).await?;
        Ok(())
    }

    async fn load_epoch_snapshot(
        &self,
        root: &trustnet_core::B256,
    ) -> anyhow::Result<Option<Vec<SnapshotLeaf>>> {
        let snapshot_path = self.epoch_snapshot_path(root);
        if !snapshot_path.exists() {
            return Ok(None);
        }

        let json = fs::read(&snapshot_path).await?;
        let leaves: Vec<SnapshotLeaf> = serde_json::from_slice(&json)?;
        Ok(Some(leaves))
    }

    /// Get the current cached SMM (if any).
    pub async fn get(&self) -> Option<Arc<Smm>> {
        self.smm.read().await.clone()
    }

    /// Return the root that the cache was built for.
    pub async fn get_cached_root(&self) -> Option<trustnet_core::B256> {
        *self.cached_root.read().await
    }

    /// Whether the cache is stale for the given published root.
    pub async fn is_stale(&self, published_root: trustnet_core::B256) -> bool {
        match self.get_cached_root().await {
            Some(cached) => cached != published_root,
            None => true,
        }
    }

    /// Try to rebuild the cache for the given epoch root.
    ///
    /// Returns:
    /// - `Ok(true)` if cache now matches `published_root`.
    /// - `Ok(false)` if the provided leaves produce a different root (edges are ahead of epoch).
    pub async fn try_rebuild_for_epoch(
        &self,
        leaves: Vec<SnapshotLeaf>,
        published_root: trustnet_core::B256,
    ) -> anyhow::Result<bool> {
        // Prefer persisted snapshot for this root.
        if let Some(snapshot) = self.load_epoch_snapshot(&published_root).await? {
            let smm = build_smm_from_leaves(&snapshot)?;
            if smm.root() == published_root {
                *self.smm.write().await = Some(Arc::new(smm));
                *self.cached_root.write().await = Some(published_root);
                return Ok(true);
            }
        }

        // Build from provided leaves and store if it matches.
        let smm = build_smm_from_leaves(&leaves)?;
        if smm.root() == published_root {
            let _ = self.save_epoch_snapshot(&published_root, &leaves).await;
            *self.smm.write().await = Some(Arc::new(smm));
            *self.cached_root.write().await = Some(published_root);
            return Ok(true);
        }

        Ok(false)
    }
}

fn build_smm_from_leaves(leaves: &[SnapshotLeaf]) -> anyhow::Result<Smm> {
    let mut builder = SmmBuilder::new();
    for leaf in leaves {
        builder.insert(leaf.key, leaf.leaf_value.clone())?;
    }
    Ok(builder.build())
}
