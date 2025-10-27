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
use tracing::{info, warn};

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
    info!("Starting indexer service with config: {}", config_path);

    // TODO: Load configuration
    // TODO: Initialize database
    // TODO: Spawn event listener task
    // TODO: Spawn root publisher task (hourly + manual trigger)
    // TODO: Wait for shutdown signal

    info!("Indexer is running. Press Ctrl+C to stop.");
    info!("For API queries, run the trustnet-api service separately.");

    // Placeholder: wait for Ctrl+C
    tokio::signal::ctrl_c()
        .await
        .context("Failed to listen for Ctrl+C")?;

    info!("Received shutdown signal, gracefully shutting down...");

    Ok(())
}

/// Manually trigger root publishing
async fn publish_root_manual(config_path: &str) -> Result<()> {
    info!("Manual root publishing triggered");
    info!("Config: {}", config_path);

    // TODO: Load configuration
    // TODO: Connect to database
    // TODO: Build SMM from current edges
    // TODO: Publish root to RootRegistry

    warn!("Manual root publishing not yet implemented");

    Ok(())
}

/// Show indexer status and sync progress
async fn show_status(_config_path: &str) -> Result<()> {
    use trustnet_indexer::storage::Storage;

    info!("Checking indexer status");

    // TODO: Load configuration (for now, use default database)
    let database_url = "sqlite://trustnet.db";

    // Connect to database
    let storage = Storage::new(database_url)
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

    // Connect to database
    let storage = Storage::new(database_url)
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
