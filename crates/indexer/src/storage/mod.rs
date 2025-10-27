//! Storage layer for the TrustNet indexer.
//!
//! This module provides database operations for:
//! - Edges (trust ratings with latest-wins semantics)
//! - Epochs (published Merkle roots)
//! - Sync state (indexer progress tracking)
//! - Blocks (for reorg detection)

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::str::FromStr;
use tracing::info;

pub mod edge;
pub mod epoch;
pub mod sync;
pub mod types;

pub use types::*;

/// Database storage for the indexer.
///
/// Provides async access to SQLite database with connection pooling.
#[derive(Debug, Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    /// Create a new storage instance with the given database URL.
    ///
    /// This will create the database file if it doesn't exist and run migrations.
    ///
    /// # Arguments
    /// * `database_url` - SQLite database URL (e.g., "sqlite://trustnet.db")
    ///
    /// # Example
    /// ```no_run
    /// # use trustnet_indexer::storage::Storage;
    /// # async fn example() -> anyhow::Result<()> {
    /// let storage = Storage::new("sqlite://trustnet.db").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(database_url: &str) -> Result<Self> {
        info!("Connecting to database: {}", database_url);

        // Parse connection options
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true);

        // Create connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .min_connections(1)
            .connect_with(options)
            .await
            .context("Failed to connect to database")?;

        info!("Database connection established");

        Ok(Self { pool })
    }

    /// Create a new storage instance with a specific file path.
    ///
    /// # Arguments
    /// * `path` - Path to the SQLite database file
    pub async fn new_with_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let database_url = format!("sqlite://{}", path.display());
        Self::new(&database_url).await
    }

    /// Run database migrations.
    ///
    /// This should be called once during initialization to ensure the schema is up to date.
    pub async fn run_migrations(&self) -> Result<()> {
        info!("Running database migrations");

        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run migrations")?;

        info!("Migrations completed successfully");

        Ok(())
    }

    /// Get a reference to the connection pool.
    ///
    /// This is useful for custom queries or transactions.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Close the database connection pool.
    pub async fn close(&self) {
        info!("Closing database connection");
        self.pool.close().await;
    }

    /// Get database statistics.
    pub async fn stats(&self) -> Result<DatabaseStats> {
        let edge_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges")
            .fetch_one(&self.pool)
            .await?;

        let epoch_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM epochs")
            .fetch_one(&self.pool)
            .await?;

        let block_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks")
            .fetch_one(&self.pool)
            .await?;

        let sync_state = self.get_sync_state().await?;

        Ok(DatabaseStats {
            edge_count: edge_count as u64,
            epoch_count: epoch_count as u64,
            block_count: block_count as u64,
            last_block_number: sync_state.last_block_number,
        })
    }

    /// Check database health.
    pub async fn health_check(&self) -> Result<()> {
        // Simple query to check if database is responsive
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .context("Database health check failed")?;

        Ok(())
    }
}

/// Database statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseStats {
    /// Total number of edges
    pub edge_count: u64,

    /// Total number of published epochs
    pub epoch_count: u64,

    /// Total number of indexed blocks
    pub block_count: u64,

    /// Last processed block number
    pub last_block_number: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_storage_creation() {
        let _temp_db = NamedTempFile::new().unwrap();
        let db_path = _temp_db.path();

        let storage = Storage::new_with_path(db_path).await.unwrap();
        storage.run_migrations().await.unwrap();

        // Verify connection works
        storage.health_check().await.unwrap();

        storage.close().await;
    }

    #[tokio::test]
    async fn test_database_stats() {
        let _temp_db = NamedTempFile::new().unwrap();
        let db_path = _temp_db.path();

        let storage = Storage::new_with_path(db_path).await.unwrap();
        storage.run_migrations().await.unwrap();

        let stats = storage.stats().await.unwrap();
        assert_eq!(stats.edge_count, 0);
        assert_eq!(stats.epoch_count, 0);
        assert_eq!(stats.block_count, 0);
        assert_eq!(stats.last_block_number, 0);

        storage.close().await;
    }
}
