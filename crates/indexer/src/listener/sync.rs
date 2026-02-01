//! Sync engine for historical and live block processing.

use alloy::primitives::Address;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, warn};

use super::provider::ChainEvent;
use super::RpcProvider;
use crate::config::SyncConfig;
use crate::storage::Storage;

/// Sync engine manages historical catch-up and live block synchronization.
pub struct SyncEngine {
    provider: RpcProvider,
    storage: Storage,
    config: SyncConfig,
    chain_id: u64,
    erc8004_namespace: Address,
}

impl SyncEngine {
    /// Create a new sync engine.
    pub fn new(
        provider: RpcProvider,
        storage: Storage,
        config: SyncConfig,
        chain_id: u64,
        erc8004_namespace: Address,
    ) -> Self {
        Self {
            provider,
            storage,
            config,
            chain_id,
            erc8004_namespace,
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

        info!("Found {} chain events in batch", events.len());

        // Process each event
        let mut processed = 0;
        let mut skipped = 0;

        let mut ts_cache: HashMap<u64, u64> = HashMap::new();

        for event in events {
            let block_number = match &event {
                ChainEvent::TrustGraph(ev) => ev.block_number,
                ChainEvent::Erc8004(ev) => ev.block_number,
            };

            let updated_at_u64 = match ts_cache.get(&block_number).copied() {
                Some(ts) => ts,
                None => {
                    let ts = self.provider.get_block_timestamp(block_number).await?;
                    ts_cache.insert(block_number, ts);
                    ts
                }
            };

            let maybe_edge = match event {
                ChainEvent::TrustGraph(ev) => {
                    Some(ev.to_edge_record(self.chain_id, updated_at_u64)?)
                }
                ChainEvent::Erc8004(ev) => {
                    ev.to_edge_record(self.chain_id, updated_at_u64, self.erc8004_namespace)?
                }
            };

            let Some(edge) = maybe_edge else {
                skipped += 1;
                continue;
            };

            if let Err(e) = self.storage.append_edge_raw(&edge).await {
                warn!("Failed to append edges_raw: {}", e);
            }

            match self.storage.upsert_edge_latest(&edge).await {
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
                info!("Block {}: found {} chain events", block_num, events.len());
            }

            // Process events
            let updated_at_u64 = self.provider.get_block_timestamp(block_num).await?;
            for event in events {
                let maybe_edge = match event {
                    ChainEvent::TrustGraph(ev) => {
                        Some(ev.to_edge_record(self.chain_id, updated_at_u64)?)
                    }
                    ChainEvent::Erc8004(ev) => {
                        ev.to_edge_record(self.chain_id, updated_at_u64, self.erc8004_namespace)?
                    }
                };

                let Some(edge) = maybe_edge else {
                    continue;
                };

                if let Err(e) = self.storage.append_edge_raw(&edge).await {
                    warn!("Failed to append edges_raw: {}", e);
                }
                if let Err(e) = self.storage.upsert_edge_latest(&edge).await {
                    warn!("Failed to upsert edges_latest: {}", e);
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
