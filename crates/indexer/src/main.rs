//! TrustNet Indexer - ERC-8004 and EdgeRated event ingestion
//!
//! This binary provides:
//! - Event listening from Ethereum (TrustGraph + ERC-8004 Reputation)
//! - Edge storage with latest-wins semantics
//! - Sparse Merkle Map building
//! - Root publishing to RootRegistry
//!
//! Note: The HTTP API is provided by the separate `trustnet-api` service

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use trustnet_indexer::publisher::PublishResult;

#[derive(Parser)]
#[command(name = "trustnet-indexer")]
#[command(version, about = "TrustNet indexer for ERC-8004 and EdgeRated events", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "indexer.toml")]
    config: String,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the indexer service (sync + API server)
    Run,

    /// Publish current root to RootRegistry (manual trigger)
    PublishRoot,

    /// Show indexer status and sync progress
    Status,

    /// Initialize the database
    InitDb {
        /// Database URL
        #[arg(long, default_value = "sqlite://trustnet.db")]
        database_url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(cli.debug)?;

    info!("TrustNet Indexer starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Execute command
    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => run_indexer(&cli.config).await?,
        Commands::PublishRoot => publish_root_manual(&cli.config).await?,
        Commands::Status => show_status(&cli.config).await?,
        Commands::InitDb { database_url } => init_database(&database_url).await?,
    }

    Ok(())
}

/// Initialize tracing subscriber for logging
fn init_logging(debug: bool) -> Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter = if debug {
        EnvFilter::new("trustnet_indexer=debug,tower_http=debug,sqlx=debug")
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("trustnet_indexer=info,tower_http=info"))
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true).with_line_number(true))
        .init();

    Ok(())
}

/// Main indexer service - runs event sync and root publishing
async fn run_indexer(config_path: &str) -> Result<()> {
    use trustnet_indexer::config::Config;
    use trustnet_indexer::storage::Storage;

    info!("Starting indexer service with config: {}", config_path);

    // Load configuration
    let config = Config::from_file(config_path).context("Failed to load configuration")?;

    info!("Configuration loaded successfully");
    info!("  Chain ID: {}", config.network.chain_id);
    info!("  RPC URL: {}", config.network.rpc_url);
    info!("  Database: {}", config.database.url);
    info!("  Start block: {}", config.sync.start_block);

    // Initialize database with configured pool settings
    let storage = Storage::new(
        &config.database.url,
        Some(config.database.max_connections),
        Some(config.database.min_connections),
    )
    .await
    .context("Failed to connect to database")?;

    storage
        .run_migrations()
        .await
        .context("Failed to run migrations")?;

    info!("Database initialized");

    // Initialize sync state if this is a fresh database
    let sync_state = storage.get_sync_state().await?;
    if sync_state.last_block_number == 0 && sync_state.chain_id == 0 {
        // Set last_block to (start_block - 1) so the first sync loop processes start_block
        // Since sync engine fetches logs starting at (last_synced + 1), this ensures
        // the configured start_block is included in the first batch.
        let initial_block = config.sync.start_block.saturating_sub(1);
        info!(
            "Fresh database detected, initializing sync state with chain_id={} initial_block={} (will start syncing from block {})",
            config.network.chain_id, initial_block, config.sync.start_block
        );
        storage
            .initialize_sync_state(
                config.network.chain_id,
                initial_block,
                alloy::primitives::B256::ZERO,
            )
            .await
            .context("Failed to initialize sync state")?;
        info!("Sync state initialized");
    } else {
        info!(
            "Existing sync state found: chain_id={} last_block={}",
            sync_state.chain_id, sync_state.last_block_number
        );
    }

    // Create RPC provider
    use trustnet_indexer::listener::{RpcProvider, SyncEngine};
    let provider = RpcProvider::new(
        &config.network.rpc_url,
        config.contracts.trust_graph,
        config.contracts.erc8004_reputation,
    )
    .await
    .context("Failed to create RPC provider")?;

    info!("RPC provider initialized");

    // Create sync engine (uses core quantizer with fixed buckets)
    let sync_engine = SyncEngine::new(
        provider,
        storage.clone(),
        config.sync.clone(),
        config.network.chain_id,
    );

    // Spawn event listener task
    let sync_handle = tokio::spawn(async move { sync_engine.run().await });

    info!("Event listener started");

    // Create and spawn SMM service task
    use trustnet_indexer::smm_service::PeriodicSmmBuilder;
    let smm_service = PeriodicSmmBuilder::new(
        storage.clone(),
        std::time::Duration::from_secs(config.builder.rebuild_interval_secs),
    );
    let smm_handle = tokio::spawn({
        let smm_service = smm_service.clone();
        async move { smm_service.run().await }
    });

    info!(
        "SMM service started (rebuild interval: {}s)",
        config.builder.rebuild_interval_secs
    );

    // Create and spawn root publisher task
    use alloy::signers::local::PrivateKeySigner;
    use trustnet_indexer::publisher::EventDrivenPublisher;
    use trustnet_indexer::root_manifest::ChainManifestConfigV1;

    // Parse private key
    let signer = config
        .publisher
        .private_key
        .trim_start_matches("0x")
        .parse::<PrivateKeySigner>()
        .context("Failed to parse publisher private key")?;

    let publisher = EventDrivenPublisher::new(
        storage.clone(),
        smm_service.clone(),
        &config.network.rpc_url,
        signer,
        config.contracts.root_registry,
        ChainManifestConfigV1 {
            chain_id: config.network.chain_id,
            trust_graph: config.contracts.trust_graph,
            erc8004_reputation: config.contracts.erc8004_reputation,
            erc8004_identity: config.contracts.erc8004_identity,
            root_registry: config.contracts.root_registry,
            start_block: config.sync.start_block,
            confirmations: config.sync.confirmations,
        },
        config.publisher.clone(),
    )
    .await
    .context("Failed to create root publisher")?;

    // Connect rebuild notifications (for future use)
    let _rebuild_notify = publisher.rebuild_notify();

    let publisher_handle = if config.publisher.auto_publish {
        info!(
            "Root publisher started (interval: {}s)",
            config.publisher.publish_interval_secs
        );
        Some(tokio::spawn(async move { publisher.run().await }))
    } else {
        info!("Auto-publishing disabled, use 'publish-root' command to publish manually");
        None
    };

    info!("Indexer is running. Press Ctrl+C to stop.");
    info!("For API queries, run the trustnet-api service separately.");

    // Wait for either Ctrl+C or task failures
    if let Some(publisher_handle) = publisher_handle {
        // Auto-publishing enabled, monitor all tasks
        tokio::select! {
            result = sync_handle => {
                // Sync task completed (either error or unexpected exit)
                storage.close().await;
                match result {
                    Ok(Ok(())) => {
                        warn!("Sync engine exited unexpectedly");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        Err(e).context("Sync engine failed")
                    }
                    Err(e) => {
                        Err(anyhow::anyhow!("Sync task panicked: {}", e))
                    }
                }
            }
            result = smm_handle => {
                // SMM service task completed (either error or unexpected exit)
                storage.close().await;
                match result {
                    Ok(Ok(())) => {
                        warn!("SMM service exited unexpectedly");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        Err(e).context("SMM service failed")
                    }
                    Err(e) => {
                        Err(anyhow::anyhow!("SMM service task panicked: {}", e))
                    }
                }
            }
            result = publisher_handle => {
                // Publisher task completed (either error or unexpected exit)
                storage.close().await;
                match result {
                    Ok(Ok(())) => {
                        warn!("Publisher exited unexpectedly");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        Err(e).context("Publisher failed")
                    }
                    Err(e) => {
                        Err(anyhow::anyhow!("Publisher task panicked: {}", e))
                    }
                }
            }
            result = tokio::signal::ctrl_c() => {
                result.context("Failed to listen for Ctrl+C")?;
                info!("Received shutdown signal, gracefully shutting down...");
                storage.close().await;
                Ok(())
            }
        }
    } else {
        // Auto-publishing disabled, monitor only sync and SMM tasks
        tokio::select! {
            result = sync_handle => {
                // Sync task completed (either error or unexpected exit)
                storage.close().await;
                match result {
                    Ok(Ok(())) => {
                        warn!("Sync engine exited unexpectedly");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        Err(e).context("Sync engine failed")
                    }
                    Err(e) => {
                        Err(anyhow::anyhow!("Sync task panicked: {}", e))
                    }
                }
            }
            result = smm_handle => {
                // SMM service task completed (either error or unexpected exit)
                storage.close().await;
                match result {
                    Ok(Ok(())) => {
                        warn!("SMM service exited unexpectedly");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        Err(e).context("SMM service failed")
                    }
                    Err(e) => {
                        Err(anyhow::anyhow!("SMM service task panicked: {}", e))
                    }
                }
            }
            result = tokio::signal::ctrl_c() => {
                result.context("Failed to listen for Ctrl+C")?;
                info!("Received shutdown signal, gracefully shutting down...");
                storage.close().await;
                Ok(())
            }
        }
    }
}

/// Manually trigger root publishing
async fn publish_root_manual(config_path: &str) -> Result<()> {
    use alloy::signers::local::PrivateKeySigner;
    use trustnet_indexer::config::Config;
    use trustnet_indexer::publisher::EventDrivenPublisher;
    use trustnet_indexer::smm_service::PeriodicSmmBuilder;
    use trustnet_indexer::storage::Storage;

    info!("Manual root publishing triggered");

    // Load configuration
    let config = Config::from_file(config_path).context("Failed to load configuration")?;

    info!("Configuration loaded successfully");

    // Connect to database with configured pool settings
    let storage = Storage::new(
        &config.database.url,
        Some(config.database.max_connections),
        Some(config.database.min_connections),
    )
    .await
    .context("Failed to connect to database")?;

    storage
        .run_migrations()
        .await
        .context("Failed to run migrations")?;

    info!("Database connected");

    // Build SMM from current edges
    let smm_service = PeriodicSmmBuilder::new(
        storage.clone(),
        std::time::Duration::from_secs(300), // Not used for manual publish
    );

    // Build SMM immediately
    info!("Building SMM from current edges...");
    let state = smm_service.get_current_state().await;

    if state.is_none() {
        // Need to build first
        info!("No cached SMM state, building now...");
        // Can't easily rebuild from here, so we create a temporary builder
        let edges = storage.get_all_edges_latest().await?;
        info!("Found {} edges", edges.len());

        // Build SMM manually (even if empty - let the publisher decide if it should publish)
        let mut builder = trustnet_smm::SmmBuilder::new();
        for edge in &edges {
            let key = trustnet_core::hashing::compute_edge_key(
                &edge.rater,
                &edge.target,
                &edge.context_id,
            );
            let leaf_value = trustnet_core::LeafValueV1 {
                level: edge.level,
                updated_at_u64: edge.updated_at_u64,
                evidence_hash: edge.evidence_hash,
            }
            .encode()
            .to_vec();
            builder.insert(key, leaf_value)?;
        }
        let smm = builder.build();
        let root = smm.root();

        info!("SMM built with root: 0x{}", hex::encode(root));

        // Parse private key
        let signer = config
            .publisher
            .private_key
            .trim_start_matches("0x")
            .parse::<PrivateKeySigner>()
            .context("Failed to parse publisher private key")?;

        use trustnet_indexer::root_manifest::ChainManifestConfigV1;

        // Create publisher
        let publisher = EventDrivenPublisher::new(
            storage.clone(),
            smm_service,
            &config.network.rpc_url,
            signer,
            config.contracts.root_registry,
            ChainManifestConfigV1 {
                chain_id: config.network.chain_id,
                trust_graph: config.contracts.trust_graph,
                erc8004_reputation: config.contracts.erc8004_reputation,
                erc8004_identity: config.contracts.erc8004_identity,
                root_registry: config.contracts.root_registry,
                start_block: config.sync.start_block,
                confirmations: config.sync.confirmations,
            },
            config.publisher.clone(),
        )
        .await
        .context("Failed to create root publisher")?;

        // Publish immediately (builds SMM and publishes in one call)
        info!("Publishing root to chain...");
        match publisher.publish_now().await {
            Ok(PublishResult::Published { epoch }) => {
                info!("Root published successfully to epoch {}", epoch);
            }
            Ok(PublishResult::Skipped { reason }) => {
                info!("Root publish skipped: {:?}", reason);
            }
            Err(e) => {
                error!("Failed to publish root: {}", e);
                storage.close().await;
                return Err(e);
            }
        }
    } else {
        info!("Using cached SMM state");

        // Parse private key
        let signer = config
            .publisher
            .private_key
            .trim_start_matches("0x")
            .parse::<PrivateKeySigner>()
            .context("Failed to parse publisher private key")?;

        use trustnet_indexer::root_manifest::ChainManifestConfigV1;

        // Create publisher
        let publisher = EventDrivenPublisher::new(
            storage.clone(),
            smm_service,
            &config.network.rpc_url,
            signer,
            config.contracts.root_registry,
            ChainManifestConfigV1 {
                chain_id: config.network.chain_id,
                trust_graph: config.contracts.trust_graph,
                erc8004_reputation: config.contracts.erc8004_reputation,
                erc8004_identity: config.contracts.erc8004_identity,
                root_registry: config.contracts.root_registry,
                start_block: config.sync.start_block,
                confirmations: config.sync.confirmations,
            },
            config.publisher.clone(),
        )
        .await
        .context("Failed to create root publisher")?;

        // Publish immediately (builds SMM and publishes in one call)
        info!("Publishing root to chain...");
        match publisher.publish_now().await {
            Ok(PublishResult::Published { epoch }) => {
                info!("Root published successfully to epoch {}", epoch);
            }
            Ok(PublishResult::Skipped { reason }) => {
                info!("Root publish skipped: {:?}", reason);
            }
            Err(e) => {
                error!("Failed to publish root: {}", e);
                storage.close().await;
                return Err(e);
            }
        }
    }

    storage.close().await;

    Ok(())
}

/// Show indexer status and sync progress
async fn show_status(config_path: &str) -> Result<()> {
    use trustnet_indexer::config::Config;
    use trustnet_indexer::storage::Storage;

    info!("Checking indexer status");

    // Try to load configuration, fall back to default database ONLY if file doesn't exist
    let (database_url, max_conn, min_conn) = match Config::from_file(config_path) {
        Ok(config) => {
            info!("Using database from config: {}", config.database.url);
            (
                config.database.url,
                Some(config.database.max_connections),
                Some(config.database.min_connections),
            )
        }
        Err(e) => {
            // Check if the root cause is a "file not found" error
            // We need to walk the error chain because Config::from_file wraps errors with context
            let is_not_found = e.chain().any(|cause| {
                if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
                    io_err.kind() == std::io::ErrorKind::NotFound
                } else {
                    false
                }
            });

            if is_not_found {
                info!("Config file not found, using default database: sqlite://trustnet.db");
                ("sqlite://trustnet.db".to_string(), None, None)
            } else {
                // Other errors (permission denied, parse errors, validation errors, etc.)
                return Err(e).context("Failed to load config file");
            }
        }
    };

    // Connect to database with configured pool settings
    let storage = Storage::new(&database_url, max_conn, min_conn)
        .await
        .context("Failed to connect to database")?;

    // Run migrations to ensure schema exists (handles fresh database)
    storage
        .run_migrations()
        .await
        .context("Failed to run migrations")?;

    // Get sync state
    let sync_state = storage.get_sync_state().await?;
    let stats = storage.stats().await?;
    let latest_epoch = storage.get_latest_epoch().await?;

    // Display status
    println!("\n=== TrustNet Indexer Status ===\n");
    println!("Sync Progress:");
    println!("  Chain ID: {}", sync_state.chain_id);
    println!("  Last Block: {}", sync_state.last_block_number);
    println!(
        "  Last Block Hash: 0x{}",
        hex::encode(sync_state.last_block_hash)
    );
    println!(
        "  Last Updated: {}",
        chrono::DateTime::from_timestamp(sync_state.updated_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string())
    );

    println!("\nDatabase Statistics:");
    println!("  Total Edges: {}", stats.edge_count);
    println!("  Total Epochs: {}", stats.epoch_count);
    println!("  Indexed Blocks: {}", stats.block_count);

    if let Some(epoch) = latest_epoch {
        println!("\nLatest Published Epoch:");
        println!("  Epoch Number: {}", epoch.epoch);
        println!("  Graph Root: 0x{}", hex::encode(epoch.graph_root));
        println!("  Published at Block: {}", epoch.published_at_block);
        println!("  Edge Count: {}", epoch.edge_count);
        if let Some(tx_hash) = epoch.tx_hash {
            println!("  TX Hash: 0x{}", hex::encode(tx_hash));
        }
    } else {
        println!("\nNo epochs published yet.");
    }

    println!();

    storage.close().await;

    Ok(())
}

/// Initialize the database
async fn init_database(database_url: &str) -> Result<()> {
    use trustnet_indexer::storage::Storage;

    info!("Initializing database: {}", database_url);

    // Connect to database with default pool settings
    let storage = Storage::new(database_url, None, None)
        .await
        .context("Failed to connect to database")?;

    // Run migrations
    storage
        .run_migrations()
        .await
        .context("Failed to run migrations")?;

    // Verify database is working
    storage
        .health_check()
        .await
        .context("Database health check failed")?;

    // Display stats
    let stats = storage.stats().await?;
    info!("Database initialized successfully!");
    info!("  Edges: {}", stats.edge_count);
    info!("  Epochs: {}", stats.epoch_count);
    info!("  Blocks: {}", stats.block_count);
    info!("  Last block: {}", stats.last_block_number);

    storage.close().await;

    Ok(())
}
