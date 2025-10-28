//! Sync engine for historical and live block processing.

use anyhow::{Context, Result};
use std::time::Duration;
use tracing::{info, warn};

use super::RpcProvider;
use crate::config::SyncConfig;
use crate::storage::Storage;

/// Sync engine manages historical catch-up and live block synchronization.
pub struct SyncEngine {
    provider: RpcProvider,
    storage: Storage,
    config: SyncConfig,
}

impl SyncEngine {
    /// Create a new sync engine.
    pub fn new(provider: RpcProvider, storage: Storage, config: SyncConfig) -> Self {
        Self {
            provider,
            storage,
            config,
        }
    }

    /// Run the sync loop (historical + live).
    ///
    /// This method runs indefinitely, processing historical blocks in batches
    /// until caught up, then switching to live polling mode.
    pub async fn run(&self) -> Result<()> {
        info!("Sync engine starting...");

        loop {
            // Get current state
            let sync_state = self.storage.get_sync_state().await?;
            let current_block = self.provider.get_block_number().await?;
            let safe_block = current_block.saturating_sub(self.config.confirmations);

            let last_synced = sync_state.last_block_number;

            info!(
                "Sync status: last={}, current={}, safe={}, confirmations={}",
                last_synced, current_block, safe_block, self.config.confirmations
            );

            // Determine how far behind we are
            let blocks_behind = safe_block.saturating_sub(last_synced);

            if blocks_behind == 0 {
                // Caught up, wait for new blocks
                info!(
                    "Caught up, waiting {} seconds for new blocks...",
                    self.config.poll_interval_secs
                );
                tokio::time::sleep(Duration::from_secs(self.config.poll_interval_secs)).await;
                continue;
            }

            if blocks_behind > self.config.batch_size {
                // Historical mode: batch sync
                self.sync_historical_batch(last_synced, safe_block).await?;
            } else {
                // Live mode: process remaining blocks
                self.sync_live(last_synced, safe_block).await?;

                // Sleep before next poll
                tokio::time::sleep(Duration::from_secs(self.config.poll_interval_secs)).await;
            }
        }
    }

    /// Sync a batch of historical blocks.
    async fn sync_historical_batch(&self, from: u64, to: u64) -> Result<()> {
        let batch_end = (from + self.config.batch_size).min(to);

        info!(
            "Historical sync: processing blocks {} to {} ({} blocks)",
            from + 1,
            batch_end,
            batch_end - from
        );

        // Fetch all logs for the batch
        let events = self
            .provider
            .get_logs(from + 1, batch_end)
            .await
            .with_context(|| {
                format!(
                    "Failed to fetch logs for blocks {} to {}",
                    from + 1,
                    batch_end
                )
            })?;

        info!("Found {} NewFeedback events in batch", events.len());

        // Process each event
        let mut processed = 0;
        let mut skipped = 0;

        for event in events {
            // Convert event to edge record
            match event.to_edge_record() {
                Ok(edge) => {
                    // Upsert with latest-wins semantics
                    match self.storage.upsert_edge(&edge).await {
                        Ok(updated) => {
                            if updated {
                                processed += 1;
                            } else {
                                skipped += 1;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to upsert edge: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to convert event to edge: {}", e);
                }
            }
        }

        info!(
            "Batch complete: {} edges updated, {} skipped (stale)",
            processed, skipped
        );

        // Update sync state
        let mut state = self.storage.get_sync_state().await?;
        state.last_block_number = batch_end;
        state.last_block_hash = alloy::primitives::B256::ZERO; // TODO: Get actual block hash
        state.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        self.storage.update_sync_state(&state).await?;

        Ok(())
    }

    /// Sync live blocks (block by block for precise progress).
    async fn sync_live(&self, from: u64, to: u64) -> Result<()> {
        if from >= to {
            return Ok(());
        }

        info!("Live sync: processing blocks {} to {}", from + 1, to);

        // Process block by block for live mode
        for block_num in (from + 1)..=to {
            let events = self
                .provider
                .get_logs(block_num, block_num)
                .await
                .with_context(|| format!("Failed to fetch logs for block {}", block_num))?;

            if !events.is_empty() {
                info!(
                    "Block {}: found {} NewFeedback events",
                    block_num,
                    events.len()
                );
            }

            // Process events
            for event in events {
                match event.to_edge_record() {
                    Ok(edge) => {
                        if let Err(e) = self.storage.upsert_edge(&edge).await {
                            warn!("Failed to upsert edge: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to convert event to edge: {}", e);
                    }
                }
            }

            // Update sync state after each block
            let mut state = self.storage.get_sync_state().await?;
            state.last_block_number = block_num;
            state.last_block_hash = alloy::primitives::B256::ZERO; // TODO: Get actual block hash
            state.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;

            self.storage.update_sync_state(&state).await?;
        }

        Ok(())
    }
}
