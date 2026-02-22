//! Root publisher for TrustNet indexer.
//!
//! Publishes Sparse Merkle Map roots to the RootRegistry contract on-chain.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol;
use anyhow::{Context, Result};
use chrono::TimeZone;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{
    fs,
    sync::{Notify, RwLock},
};
use tracing::{info, warn};

use crate::config::PublisherConfig;
use crate::root_manifest::{
    build_chain_root_manifest_v1, canonicalize_manifest, ChainManifestConfigV1,
};
use crate::smm_service::PeriodicSmmBuilder;
use crate::storage::{EpochRecord, Storage};
use trustnet_core::hashing::compute_root_signature_hash;

/// Result of a publish attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishResult {
    /// Transaction was sent and confirmed
    Published {
        /// The epoch number that was published
        epoch: u64,
    },
    /// Publishing was skipped (no changes, too soon, no edges, etc.)
    Skipped {
        /// The reason why publishing was skipped
        reason: SkipReason,
    },
}

/// Reason for skipping a publish
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// No SMM state available
    NoSmmState,
    /// Root unchanged from last publish
    RootUnchanged,
    /// Too soon since last publish
    TooSoon,
    /// No edges in SMM
    NoEdges,
}

// Type alias for the Alloy provider with wallet support
// This complex type is necessary until Alloy provides a simpler abstraction
// See: https://github.com/alloy-rs/alloy/issues/1800
type WalletProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::fillers::WalletFiller<EthereumWallet>,
    >,
    alloy::providers::RootProvider<alloy::transports::http::Http<alloy::transports::http::Client>>,
    alloy::transports::http::Http<alloy::transports::http::Client>,
    alloy::network::Ethereum,
>;

// Generate RootRegistry contract bindings
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract RootRegistry {
        function publishRoot(bytes32 newRoot, uint256 epoch, bytes32 manifestHash, string manifestURI) external;
        function currentEpoch() external view returns (uint256);

        event RootPublished(
            uint256 indexed epoch,
            bytes32 indexed root,
            bytes32 manifestHash,
            string manifestURI,
            address indexed publisher,
            uint256 timestamp
        );
    }
}

/// Publisher state tracking.
#[derive(Debug, Clone, Default)]
pub struct PublisherState {
    /// Last published root hash.
    pub last_published_root: Option<B256>,
    /// Last published epoch number.
    pub last_published_epoch: Option<u64>,
    /// Timestamp of last publish.
    pub last_published_at: Option<Instant>,
    /// Number of successful publishes.
    pub publish_count: u64,
    /// Number of failed publish attempts.
    pub failed_attempts: u64,
}

/// Event-driven root publisher.
pub struct EventDrivenPublisher {
    storage: Storage,
    smm_service: PeriodicSmmBuilder,
    /// The contract instance for RootRegistry interaction
    contract: RootRegistry::RootRegistryInstance<
        alloy::transports::http::Http<alloy::transports::http::Client>,
        WalletProvider,
    >,
    /// The provider for blockchain interaction
    provider: WalletProvider,
    /// Publisher signer (also used for server-mode root signatures).
    signer: PrivateKeySigner,
    /// Root manifest config (chain mode).
    manifest_config: ChainManifestConfigV1,
    config: PublisherConfig,
    state: Arc<RwLock<PublisherState>>,
    rebuild_notify: Arc<Notify>,
}

impl EventDrivenPublisher {
    /// Create a new event-driven publisher.
    pub async fn new(
        storage: Storage,
        smm_service: PeriodicSmmBuilder,
        rpc_url: &str,
        signer: PrivateKeySigner,
        contract_address: Address,
        manifest_config: ChainManifestConfigV1,
        config: PublisherConfig,
    ) -> Result<Self> {
        // Create wallet from signer
        let wallet = EthereumWallet::from(signer.clone());

        // Build provider with wallet
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(rpc_url.parse()?);

        // Create contract instance (clone provider since contract takes ownership)
        let contract = RootRegistry::new(contract_address, provider.clone());

        let publisher = Self {
            storage,
            smm_service,
            contract,
            provider,
            signer,
            manifest_config,
            config,
            state: Arc::new(RwLock::new(PublisherState::default())),
            rebuild_notify: Arc::new(Notify::new()),
        };

        // Initialize state from database to prevent duplicate publishes
        // This is critical for manual publishes which don't run the background task
        if let Err(e) = publisher.initialize_state().await {
            warn!("Failed to initialize publisher state from database: {}", e);
            // Continue anyway - will just mean dedup won't work on first publish
        }

        Ok(publisher)
    }

    /// Get the notify handle for triggering immediate publishes.
    pub fn rebuild_notify(&self) -> Arc<Notify> {
        self.rebuild_notify.clone()
    }

    /// Run the publisher loop.
    pub async fn run(&self) -> Result<()> {
        if !self.config.auto_publish {
            info!("Auto-publishing disabled, waiting for manual triggers only");
            loop {
                self.rebuild_notify.notified().await;
                match self.try_publish("manual").await {
                    Ok(PublishResult::Published { epoch }) => {
                        info!("Manual publish successful: epoch {}", epoch);
                    }
                    Ok(PublishResult::Skipped { reason }) => {
                        info!("Manual publish skipped: {:?}", reason);
                    }
                    Err(e) => {
                        warn!("Manual publish failed: {}", e);
                    }
                }
            }
        }

        info!(
            "Root publisher starting with interval: {}s",
            self.config.publish_interval_secs
        );

        // State already initialized in new(), no need to do it again

        let mut periodic =
            tokio::time::interval(Duration::from_secs(self.config.publish_interval_secs));
        periodic.tick().await; // First tick completes immediately

        loop {
            tokio::select! {
                _ = periodic.tick() => {
                    match self.try_publish("periodic").await {
                        Ok(PublishResult::Published { epoch }) => {
                            info!("Periodic publish successful: epoch {}", epoch);
                        }
                        Ok(PublishResult::Skipped { reason }) => {
                            // Skip reasons are already logged in check_skip_reason, debug level here
                            tracing::debug!("Periodic publish skipped: {:?}", reason);
                        }
                        Err(e) => {
                            warn!("Periodic publish failed: {}", e);
                        }
                    }
                }
                _ = self.rebuild_notify.notified() => {
                    match self.try_publish("rebuild").await {
                        Ok(PublishResult::Published { epoch }) => {
                            info!("Rebuild-triggered publish successful: epoch {}", epoch);
                        }
                        Ok(PublishResult::Skipped { reason }) => {
                            tracing::debug!("Rebuild-triggered publish skipped: {:?}", reason);
                        }
                        Err(e) => {
                            warn!("Rebuild-triggered publish failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Initialize state from storage.
    async fn initialize_state(&self) -> Result<()> {
        // Load the highest epoch from the database to track what we know about
        if let Some(latest_epoch) = self.storage.get_latest_epoch().await? {
            let mut state = self.state.write().await;
            state.last_published_root = Some(latest_epoch.graph_root);
            state.last_published_epoch = Some(latest_epoch.epoch);
            info!(
                "Initialized publisher state from storage: highest epoch={}, root=0x{}",
                latest_epoch.epoch,
                hex::encode(latest_epoch.graph_root)
            );
        } else {
            info!("No previous epochs found in storage, starting fresh");
        }
        Ok(())
    }

    async fn publish_manifest_and_get_uri(
        &self,
        epoch: u64,
        manifest_hash: B256,
        manifest_json: &str,
    ) -> Result<String> {
        let output_dir = self
            .config
            .manifest_output_dir
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot publish epoch {}: publisher.manifest_output_dir is not configured",
                    epoch
                )
            })?
            .trim();
        let public_base_uri = self
            .config
            .manifest_public_base_uri
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot publish epoch {}: publisher.manifest_public_base_uri is not configured",
                    epoch
                )
            })?
            .trim();

        let output_dir = PathBuf::from(output_dir);
        fs::create_dir_all(&output_dir).await.with_context(|| {
            format!(
                "Failed to create manifest output directory: {}",
                output_dir.display()
            )
        })?;

        let manifest_hash_hex = hex::encode(manifest_hash);
        let file_name = format!("epoch-{}-0x{}.json", epoch, manifest_hash_hex);
        let file_path = output_dir.join(&file_name);

        fs::write(&file_path, manifest_json.as_bytes())
            .await
            .with_context(|| format!("Failed to write manifest file: {}", file_path.display()))?;

        let manifest_uri = format!("{}/{}", public_base_uri.trim_end_matches('/'), file_name);
        info!(
            "Published manifest for epoch {} to {} (local: {})",
            epoch,
            manifest_uri,
            file_path.display()
        );

        Ok(manifest_uri)
    }

    /// Try to publish current root if needed.
    async fn try_publish(&self, trigger: &str) -> Result<PublishResult> {
        info!(
            "Checking if root should be published (trigger: {})",
            trigger
        );

        // Get current SMM state
        let Some(smm_state) = self.smm_service.get_current_state().await else {
            info!("No SMM state available, skipping publish");
            return Ok(PublishResult::Skipped {
                reason: SkipReason::NoSmmState,
            });
        };

        // Check if we should publish and whether we're republishing
        let (should_skip, needs_republish) = self.check_skip_reason(&smm_state, trigger).await?;
        if let Some(skip_reason) = should_skip {
            return Ok(PublishResult::Skipped {
                reason: skip_reason,
            });
        }

        // Get next epoch number
        let epoch_num = self.get_next_epoch_number().await?;

        // Determine which root to publish
        let (root_to_publish, edge_count_to_publish, stored_epoch_for_manifest) = if needs_republish
        {
            // When republishing, we must use the stored root for the specific epoch
            // from our database, not the current SMM snapshot
            info!(
                "Republishing mode: loading stored root for epoch {} from database",
                epoch_num
            );

            match self.storage.get_epoch(epoch_num).await? {
                Some(stored_epoch) => {
                    info!(
                        "Found stored root for epoch {}: 0x{} (edges: {})",
                        epoch_num,
                        hex::encode(stored_epoch.graph_root),
                        stored_epoch.edge_count
                    );
                    (
                        stored_epoch.graph_root,
                        stored_epoch.edge_count,
                        Some(stored_epoch),
                    )
                }
                None => {
                    // If we don't have the epoch in our DB, this is a serious issue
                    // We should not publish the current SMM root as it would be wrong
                    return Err(anyhow::anyhow!(
                        "Cannot republish epoch {}: no stored root found in database. \
                        The chain is expecting epoch {} but we don't have it stored. \
                        This may indicate database corruption or a missing migration.",
                        epoch_num,
                        epoch_num
                    ));
                }
            }
        } else {
            // Normal publish: use current SMM snapshot
            (smm_state.root, smm_state.edge_count, None)
        };

        // Build root manifest + signature (v1.1 authenticity envelope).
        //
        // For chain-mode roots we still generate a manifest and signature. Gateways can verify the
        // signature, the on-chain anchor, or both.
        let created_at_u64 = stored_epoch_for_manifest
            .as_ref()
            .and_then(|e| e.created_at_u64)
            .unwrap_or_else(|| smm_state.built_at.max(0) as u64);

        let created_at_rfc3339 = chrono::Utc
            .timestamp_opt(created_at_u64 as i64, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        let to_block_hash = if needs_republish {
            None
        } else {
            self.try_get_block_hash(smm_state.built_at_block).await
        };

        let (manifest_json, manifest_hash, publisher_sig) = if let Some(stored_epoch) =
            stored_epoch_for_manifest.as_ref()
        {
            (
                stored_epoch.manifest_json.clone(),
                stored_epoch.manifest_hash,
                stored_epoch.publisher_sig.clone(),
            )
        } else {
            let manifest = build_chain_root_manifest_v1(
                &self.manifest_config,
                epoch_num,
                &root_to_publish,
                smm_state.built_at_block,
                to_block_hash,
                created_at_rfc3339,
            );
            let canonical = canonicalize_manifest(&manifest);
            let manifest_hash = trustnet_core::hashing::keccak256(&canonical);
            let manifest_json =
                Some(String::from_utf8(canonical).context("Manifest must be valid UTF-8")?);

            let digest = compute_root_signature_hash(epoch_num, &root_to_publish, &manifest_hash);
            let signature = self
                .signer
                .sign_hash(&digest)
                .await
                .context("Failed to sign root digest")?;

            (
                manifest_json,
                Some(manifest_hash),
                Some(signature.as_bytes().to_vec()),
            )
        };

        info!(
            "Publishing root: 0x{} epoch={} (edges: {})",
            hex::encode(root_to_publish),
            epoch_num,
            edge_count_to_publish
        );

        // Call RootRegistry.publishRoot(newRoot, epoch)
        let manifest_hash_value = manifest_hash.ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot publish epoch {}: missing manifestHash (v1.1 required)",
                epoch_num
            )
        })?;
        let manifest_uri_value = if let Some(uri) = stored_epoch_for_manifest
            .as_ref()
            .and_then(|epoch| epoch.manifest_uri.clone())
        {
            uri
        } else {
            let manifest_json_value = manifest_json.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot publish epoch {}: missing manifest JSON for URI publication",
                    epoch_num
                )
            })?;

            self.publish_manifest_and_get_uri(epoch_num, manifest_hash_value, manifest_json_value)
                .await?
        };

        let tx = self
            .contract
            .publishRoot(
                root_to_publish,
                alloy::primitives::U256::from(epoch_num),
                manifest_hash_value,
                manifest_uri_value.clone(),
            )
            .send()
            .await
            .context("Failed to send publishRoot transaction")?;

        info!("Transaction sent: 0x{}", hex::encode(tx.tx_hash()));

        // Wait for transaction receipt
        let receipt = tx
            .get_receipt()
            .await
            .context("Failed to get transaction receipt")?;

        // Check if transaction was successful
        // CRITICAL: We must check receipt status before recording the epoch!
        // status = true (1) means success, false (0) means reverted
        // Without this check, reverted transactions would be recorded as successful,
        // preventing future publishes since the DB would show the root as already published
        let success = receipt.status();
        if !success {
            // Update failure count
            let mut state = self.state.write().await;
            state.failed_attempts += 1;

            warn!(
                "Transaction reverted: 0x{} in block {} (gas used: {})",
                hex::encode(receipt.transaction_hash),
                receipt.block_number.unwrap_or_default(),
                receipt.gas_used
            );

            return Err(anyhow::anyhow!(
                "Transaction reverted: 0x{} in block {} - publishRoot(0x{}, {}, ...) failed on-chain",
                hex::encode(receipt.transaction_hash),
                receipt.block_number.unwrap_or_default(),
                hex::encode(root_to_publish),
                epoch_num
            ));
        }

        let tx_block = receipt
            .block_number
            .ok_or_else(|| anyhow::anyhow!("Transaction receipt missing block number"))?;

        info!(
            "Transaction successful in block {} with {} gas used",
            tx_block, receipt.gas_used
        );

        // Wait for configured confirmations to prevent recording epochs that might be reorged
        if self.config.confirmations > 0 {
            info!(
                "Waiting for {} confirmations before recording epoch...",
                self.config.confirmations
            );

            let start_time = Instant::now();
            let timeout = Duration::from_secs(600); // 10 minute timeout

            // Wait for confirmations
            loop {
                // Check timeout
                if start_time.elapsed() > timeout {
                    return Err(anyhow::anyhow!(
                        "Timeout waiting for {} confirmations after 10 minutes",
                        self.config.confirmations
                    ));
                }

                // Get current block with retry
                let current_block = match self.provider.get_block_number().await {
                    Ok(block) => block,
                    Err(e) => {
                        warn!("Failed to get block number: {}, retrying...", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };

                let confirmations = current_block.saturating_sub(tx_block);

                if confirmations >= self.config.confirmations {
                    info!(
                        "Transaction confirmed with {} blocks (required: {})",
                        confirmations, self.config.confirmations
                    );
                    break;
                }

                info!(
                    "Waiting for confirmations: {}/{} (current block: {}, tx block: {})",
                    confirmations, self.config.confirmations, current_block, tx_block
                );

                // Wait a bit before checking again (roughly one block time)
                tokio::time::sleep(Duration::from_secs(12)).await;
            }
        } else {
            warn!("Confirmations set to 0 - epoch will be recorded immediately (not recommended for production)");
        }

        // Store epoch record with actual on-chain data (only after confirmations)
        // Check if we're republishing an existing epoch (chain catching up to DB)
        let existing_epoch = self.storage.get_epoch(epoch_num).await?;

        if let Some(existing) = existing_epoch {
            // We're republishing an epoch that already exists in our DB
            if existing.graph_root == root_to_publish {
                // Update the transaction metadata to reflect the new publish
                // This is critical for chain reorgs/lag scenarios where the same epoch
                // is published in a different block with a different transaction
                info!(
                    "Epoch {} exists with matching root, updating transaction metadata",
                    epoch_num
                );

                let updated_epoch = EpochRecord {
                    epoch: epoch_num,
                    graph_root: root_to_publish,  // Keep the same root
                    published_at_block: tx_block, // New block number
                    published_at: chrono::Utc::now().timestamp(), // New timestamp
                    tx_hash: Some(receipt.transaction_hash), // New transaction hash
                    edge_count: existing.edge_count, // Keep original edge count
                    manifest_json: existing.manifest_json,
                    manifest_uri: existing
                        .manifest_uri
                        .or_else(|| Some(manifest_uri_value.clone())),
                    manifest_hash: existing.manifest_hash,
                    publisher_sig: existing.publisher_sig,
                    created_at_u64: existing.created_at_u64,
                };

                self.storage.update_epoch_metadata(&updated_epoch).await?;
                info!(
                    "Updated epoch {} metadata: block={}, tx=0x{}",
                    epoch_num,
                    tx_block,
                    hex::encode(receipt.transaction_hash)
                );
            } else {
                // This shouldn't happen - same epoch with different root
                return Err(anyhow::anyhow!(
                    "Epoch {} exists in database with different root! DB: 0x{}, Published: 0x{}",
                    epoch_num,
                    hex::encode(existing.graph_root),
                    hex::encode(root_to_publish)
                ));
            }
        } else {
            // Normal case - new epoch to record
            let epoch = EpochRecord {
                epoch: epoch_num,
                graph_root: root_to_publish,
                published_at_block: tx_block,
                published_at: chrono::Utc::now().timestamp(),
                tx_hash: Some(receipt.transaction_hash),
                edge_count: edge_count_to_publish,
                manifest_json,
                manifest_uri: Some(manifest_uri_value),
                manifest_hash,
                publisher_sig,
                created_at_u64: Some(created_at_u64),
            };

            self.storage.insert_epoch(&epoch).await?;
            info!("Epoch {} recorded in database", epoch_num);
        }

        // Update state
        // IMPORTANT: When republishing older epochs, we must not downgrade last_published_epoch
        // to avoid breaking the catch-up logic for multiple missing epochs
        let mut state = self.state.write().await;

        if needs_republish {
            // When republishing, only update the epoch if it's higher than what we track
            // This ensures we continue to detect that more epochs need republishing
            let should_update = match state.last_published_epoch {
                None => true,
                Some(last) => epoch_num > last,
            };

            if should_update {
                state.last_published_epoch = Some(epoch_num);
                state.last_published_root = Some(root_to_publish);
            }
            info!(
                "Republished epoch {} (tracking highest: {:?})",
                epoch_num, state.last_published_epoch
            );
        } else {
            // Normal publish: always update to the new epoch
            state.last_published_root = Some(root_to_publish);
            state.last_published_epoch = Some(epoch_num);
        }

        state.last_published_at = Some(Instant::now());
        state.publish_count += 1;

        info!("Successfully recorded epoch {}", epoch_num);
        Ok(PublishResult::Published { epoch: epoch_num })
    }

    /// Check if we should skip publishing the current root.
    /// Returns (Some(reason), needs_republish) where:
    /// - Some(reason) if we should skip, None if we should publish
    /// - needs_republish is true if we need to republish due to chain lag
    async fn check_skip_reason(
        &self,
        smm_state: &crate::smm_service::SmmState,
        trigger: &str,
    ) -> Result<(Option<SkipReason>, bool)> {
        let state = self.state.read().await;

        // Query the contract's current epoch
        let contract_epoch_result = self
            .contract
            .currentEpoch()
            .call()
            .await
            .context("Failed to query current epoch from RootRegistry")?;

        let contract_epoch_u256 = contract_epoch_result._0;
        let contract_current_epoch: u64 = contract_epoch_u256
            .try_into()
            .map_err(|_| anyhow::anyhow!("Contract epoch too large: {}", contract_epoch_u256))?;

        // Get the highest epoch from our database to detect if contract is behind
        // We use the database as the source of truth, not our state tracking
        let db_latest_epoch = self.storage.get_latest_epoch().await?;

        // Check if the contract is behind our database (needs republishing)
        let needs_republish = if let Some(db_latest) = &db_latest_epoch {
            // If contract is behind our DB, we need to republish
            if contract_current_epoch < db_latest.epoch {
                warn!(
                    "Contract is behind database! Contract epoch: {}, DB highest epoch: {}. Will republish to catch up.",
                    contract_current_epoch, db_latest.epoch
                );
                true
            } else {
                false
            }
        } else {
            false
        };

        // Skip if same root as last published (unless we need to republish to catch up the chain)
        if !needs_republish && Some(smm_state.root) == state.last_published_root {
            info!("Skipping publish ({}): root unchanged", trigger);
            return Ok((Some(SkipReason::RootUnchanged), false));
        } else if needs_republish {
            info!("Will republish to catch up chain (trigger: {})", trigger);
            // Note: we return needs_republish=true but don't skip
            // The actual root to publish will be loaded from the database
        }

        // Check minimum interval (except for manual triggers or republish)
        if trigger != "manual" && !needs_republish {
            if let Some(last_published) = state.last_published_at {
                let elapsed = last_published.elapsed();
                let min_interval = Duration::from_secs(self.config.min_interval_secs);
                if elapsed < min_interval {
                    info!(
                        "Skipping publish ({}): too soon ({}s < {}s)",
                        trigger,
                        elapsed.as_secs(),
                        min_interval.as_secs()
                    );
                    return Ok((Some(SkipReason::TooSoon), false));
                }
            }
        }

        // Skip if no edges (unless republishing)
        if smm_state.edge_count == 0 && !needs_republish {
            info!("Skipping publish ({}): no edges in SMM", trigger);
            return Ok((Some(SkipReason::NoEdges), false));
        }

        Ok((None, needs_republish))
    }

    /// Get the next epoch number from on-chain contract state.
    /// This ensures we always use the correct epoch even if our database is out of sync.
    async fn get_next_epoch_number(&self) -> Result<u64> {
        // Always check the contract's current epoch to ensure we're in sync
        let contract_epoch_result = self
            .contract
            .currentEpoch()
            .call()
            .await
            .context("Failed to query current epoch from RootRegistry")?;

        // Extract the U256 value (it's returned as a single unnamed field)
        let contract_epoch_u256 = contract_epoch_result._0;

        // Convert U256 to u64 (safe for epoch numbers)
        let current_epoch: u64 = contract_epoch_u256
            .try_into()
            .map_err(|_| anyhow::anyhow!("Contract epoch too large: {}", contract_epoch_u256))?;

        // Check if our database is out of sync
        if let Some(latest) = self.storage.get_latest_epoch().await? {
            if latest.epoch != current_epoch {
                warn!(
                    "Database out of sync with contract! DB epoch: {}, Contract epoch: {}",
                    latest.epoch, current_epoch
                );

                // If contract is ahead, we might have missed some epochs
                if current_epoch > latest.epoch {
                    warn!(
                        "Contract is {} epochs ahead of database - possible missed publishes or DB restore",
                        current_epoch - latest.epoch
                    );
                }
                // If database is ahead, we might have unpublished epochs or a reorg occurred
                else {
                    warn!(
                        "Database is {} epochs ahead of contract - possible reorg or failed publishes",
                        latest.epoch - current_epoch
                    );
                }
            }
        } else if current_epoch > 0 {
            warn!(
                "No epochs in database but contract already at epoch {} - database might be rebuilt",
                current_epoch
            );
        }

        // Always use contract state as source of truth
        let next_epoch = current_epoch + 1;
        info!(
            "Next epoch will be {} (contract currentEpoch: {})",
            next_epoch, current_epoch
        );

        Ok(next_epoch)
    }

    /// Manually trigger a root publish.
    /// Note: This only sends a notification. Requires a background task running `run()` to consume it.
    pub async fn trigger_publish(&self) -> Result<()> {
        self.rebuild_notify.notify_one();
        Ok(())
    }

    /// Immediately publish the current SMM root if available.
    /// This is used for manual publishing without requiring background tasks.
    pub async fn publish_now(&self) -> Result<PublishResult> {
        info!("Manual publish requested");

        // First, trigger SMM rebuild to ensure we have latest state
        if let Err(e) = self.smm_service.rebuild_now().await {
            warn!("Failed to rebuild SMM: {}", e);
        }

        // Now try to publish
        self.try_publish("manual").await
    }

    /// Get current publisher state.
    pub async fn get_state(&self) -> PublisherState {
        self.state.read().await.clone()
    }

    async fn try_get_block_hash(&self, block_number: u64) -> Option<B256> {
        use alloy::rpc::types::{BlockNumberOrTag, BlockTransactionsKind};

        let from_rpc = match self
            .provider
            .get_block_by_number(
                BlockNumberOrTag::Number(block_number),
                BlockTransactionsKind::Hashes,
            )
            .await
        {
            Ok(Some(block)) => Some(block.header.hash),
            Ok(None) => None,
            Err(e) => {
                warn!("Failed to fetch block hash for {}: {}", block_number, e);
                None
            }
        };

        if from_rpc.is_some() {
            return from_rpc;
        }

        match self.storage.get_sync_state().await {
            Ok(state) if state.last_block_number == block_number => {
                if state.last_block_hash != B256::ZERO {
                    return Some(state.last_block_hash);
                }
                None
            }
            _ => None,
        }
    }
}
