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
pub mod feedback;
pub mod sync;
pub mod types;

pub use types::*;

/// Deployment mode used to prevent mixed-source roots in a single DB (spec §9.3 MVP simplification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Chain-only mode: ingest on-chain signals and build chain roots.
    Chain,
    /// Server-only mode: ingest private log signals and build server roots.
    Server,
}

impl DeploymentMode {
    fn as_str(&self) -> &'static str {
        match self {
            DeploymentMode::Chain => "chain",
            DeploymentMode::Server => "server",
        }
    }
}

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
    /// * `max_connections` - Maximum number of connections in the pool (default: 5)
    /// * `min_connections` - Minimum number of connections in the pool (default: 1)
    ///
    /// # Example
    /// ```no_run
    /// # use trustnet_indexer::storage::Storage;
    /// # async fn example() -> anyhow::Result<()> {
    /// let storage = Storage::new("sqlite://trustnet.db", None, None).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(
        database_url: &str,
        max_connections: Option<u32>,
        min_connections: Option<u32>,
    ) -> Result<Self> {
        let max_conn = max_connections.unwrap_or(5);
        let min_conn = min_connections.unwrap_or(1);

        info!("Connecting to database: {}", database_url);
        info!("Pool settings: max={}, min={}", max_conn, min_conn);

        // Parse connection options
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true);

        // Create connection pool with configured limits
        let pool = SqlitePoolOptions::new()
            .max_connections(max_conn)
            .min_connections(min_conn)
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
    /// * `max_connections` - Maximum number of connections in the pool (default: 5)
    /// * `min_connections` - Minimum number of connections in the pool (default: 1)
    pub async fn new_with_path<P: AsRef<Path>>(
        path: P,
        max_connections: Option<u32>,
        min_connections: Option<u32>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let database_url = format!("sqlite://{}", path.display());
        Self::new(&database_url, max_connections, min_connections).await
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

    /// Enforce a single-source deployment mode in this database.
    ///
    /// This is a hard guardrail against mixed-source roots (chain + private log) which require
    /// a formalized cross-source `observedAt` ordering.
    pub async fn enforce_deployment_mode(&self, expected: DeploymentMode) -> Result<()> {
        let expected = expected.as_str();

        // First writer wins: claim the mode if unset.
        sqlx::query(
            r#"
            INSERT INTO deployment_mode (id, mode)
            VALUES (1, ?)
            ON CONFLICT(id) DO NOTHING
            "#,
        )
        .bind(expected)
        .execute(&self.pool)
        .await
        .context("Failed to claim deployment_mode")?;

        let current: Option<String> =
            sqlx::query_scalar("SELECT mode FROM deployment_mode WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .context("Failed to read deployment_mode")?;

        let Some(current) = current else {
            anyhow::bail!("deployment_mode missing row (id=1)");
        };

        if current != expected {
            anyhow::bail!(
                "deployment_mode mismatch: expected '{}', got '{}'. Use separate DBs per mode.",
                expected,
                current
            );
        }

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
        let edge_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges_latest")
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

        let storage = Storage::new_with_path(db_path, None, None).await.unwrap();
        storage.run_migrations().await.unwrap();

        // Verify connection works
        storage.health_check().await.unwrap();

        storage.close().await;
    }

    #[tokio::test]
    async fn test_database_stats() {
        let _temp_db = NamedTempFile::new().unwrap();
        let db_path = _temp_db.path();

        let storage = Storage::new_with_path(db_path, None, None).await.unwrap();
        storage.run_migrations().await.unwrap();

        let stats = storage.stats().await.unwrap();
        assert_eq!(stats.edge_count, 0);
        assert_eq!(stats.epoch_count, 0);
        assert_eq!(stats.block_count, 0);
        assert_eq!(stats.last_block_number, 0);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_enforce_deployment_mode_first_writer_wins() {
        let _temp_db = NamedTempFile::new().unwrap();
        let db_path = _temp_db.path();

        let storage = Storage::new_with_path(db_path, None, None).await.unwrap();
        storage.run_migrations().await.unwrap();

        storage
            .enforce_deployment_mode(DeploymentMode::Chain)
            .await
            .unwrap();

        let err = storage
            .enforce_deployment_mode(DeploymentMode::Server)
            .await
            .unwrap_err();

        let msg = format!("{:#}", err);
        assert!(msg.contains("deployment_mode mismatch"));

        storage.close().await;
    }
}
