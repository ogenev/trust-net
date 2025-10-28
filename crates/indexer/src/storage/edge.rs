//! Edge storage operations with latest-wins semantics.

use super::{EdgeRecord, EdgeSource, Storage};
use alloy::primitives::{Address, B256};
use anyhow::{Context, Result};
use sqlx::Row;
use trustnet_core::types::{ContextId, Level};

impl Storage {
    /// Insert or update an edge with latest-wins semantics.
    ///
    /// If an edge already exists for the same (rater, target, context_id),
    /// it will only be updated if the new edge has later block coordinates.
    ///
    /// Returns `true` if the edge was inserted/updated, `false` if it was older.
    pub async fn upsert_edge(&self, edge: &EdgeRecord) -> Result<bool> {
        let rater_bytes = edge.rater.as_slice();
        let target_bytes = edge.target.as_slice();
        let context_bytes = edge.context_id.as_bytes().as_slice();
        let tx_hash_bytes = edge.tx_hash.as_ref().map(|h| h.as_slice());

        // Use INSERT ... ON CONFLICT with WHERE clause for latest-wins.
        // The WHERE clause ensures UPDATE only happens when the new edge is newer.
        // If the edge is stale, no UPDATE occurs and rows_affected = 0.
        let result = sqlx::query(
            r#"
            INSERT INTO edges (
                rater, target, context_id, level,
                block_number, tx_index, log_index,
                ingested_at, source, tx_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rater, target, context_id)
            DO UPDATE SET
                level = excluded.level,
                block_number = excluded.block_number,
                tx_index = excluded.tx_index,
                log_index = excluded.log_index,
                ingested_at = excluded.ingested_at,
                source = excluded.source,
                tx_hash = excluded.tx_hash
            WHERE (excluded.block_number > edges.block_number)
               OR (excluded.block_number = edges.block_number AND excluded.tx_index > edges.tx_index)
               OR (excluded.block_number = edges.block_number AND excluded.tx_index = edges.tx_index AND excluded.log_index > edges.log_index)
            "#,
        )
        .bind(rater_bytes)
        .bind(target_bytes)
        .bind(context_bytes)
        .bind(edge.level.value() as i32)
        .bind(edge.block_number as i64)
        .bind(edge.tx_index as i64)
        .bind(edge.log_index as i64)
        .bind(edge.ingested_at)
        .bind(edge.source.as_str())
        .bind(tx_hash_bytes)
        .execute(&self.pool)
        .await
        .context("Failed to upsert edge")?;

        // rows_affected > 0 means either:
        // - New edge inserted (no conflict), or
        // - Edge updated (conflict + WHERE clause passed)
        // rows_affected = 0 means:
        // - Edge is stale (conflict + WHERE clause failed)
        Ok(result.rows_affected() > 0)
    }

    /// Get an edge by rater, target, and context.
    pub async fn get_edge(
        &self,
        rater: &Address,
        target: &Address,
        context_id: &ContextId,
    ) -> Result<Option<EdgeRecord>> {
        let rater_bytes = rater.as_slice();
        let target_bytes = target.as_slice();
        let context_bytes = context_id.as_bytes().as_slice();

        let row = sqlx::query(
            r#"
            SELECT rater, target, context_id, level,
                   block_number, tx_index, log_index,
                   ingested_at, source, tx_hash
            FROM edges
            WHERE rater = ? AND target = ? AND context_id = ?
            "#,
        )
        .bind(rater_bytes)
        .bind(target_bytes)
        .bind(context_bytes)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_edge_record(row)?)),
            None => Ok(None),
        }
    }

    /// Get all edges from a specific rater in a context.
    pub async fn get_edges_from_rater(
        &self,
        rater: &Address,
        context_id: &ContextId,
    ) -> Result<Vec<EdgeRecord>> {
        let rater_bytes = rater.as_slice();
        let context_bytes = context_id.as_bytes().as_slice();

        let rows = sqlx::query(
            r#"
            SELECT rater, target, context_id, level,
                   block_number, tx_index, log_index,
                   ingested_at, source, tx_hash
            FROM edges
            WHERE rater = ? AND context_id = ?
            ORDER BY block_number DESC, tx_index DESC, log_index DESC
            "#,
        )
        .bind(rater_bytes)
        .bind(context_bytes)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_edge_record).collect()
    }

    /// Get all edges to a specific target in a context.
    pub async fn get_edges_to_target(
        &self,
        target: &Address,
        context_id: &ContextId,
    ) -> Result<Vec<EdgeRecord>> {
        let target_bytes = target.as_slice();
        let context_bytes = context_id.as_bytes().as_slice();

        let rows = sqlx::query(
            r#"
            SELECT rater, target, context_id, level,
                   block_number, tx_index, log_index,
                   ingested_at, source, tx_hash
            FROM edges
            WHERE target = ? AND context_id = ?
            ORDER BY block_number DESC, tx_index DESC, log_index DESC
            "#,
        )
        .bind(target_bytes)
        .bind(context_bytes)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_edge_record).collect()
    }

    /// Get all edges in a specific context.
    pub async fn get_all_edges_in_context(
        &self,
        context_id: &ContextId,
    ) -> Result<Vec<EdgeRecord>> {
        let context_bytes = context_id.as_bytes().as_slice();

        let rows = sqlx::query(
            r#"
            SELECT rater, target, context_id, level,
                   block_number, tx_index, log_index,
                   ingested_at, source, tx_hash
            FROM edges
            WHERE context_id = ?
            ORDER BY block_number DESC, tx_index DESC, log_index DESC
            "#,
        )
        .bind(context_bytes)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_edge_record).collect()
    }

    /// Get all edges (for building the complete SMM).
    pub async fn get_all_edges(&self) -> Result<Vec<EdgeRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT rater, target, context_id, level,
                   block_number, tx_index, log_index,
                   ingested_at, source, tx_hash
            FROM edges
            ORDER BY block_number DESC, tx_index DESC, log_index DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_edge_record).collect()
    }

    /// Count total edges in the database.
    pub async fn count_edges(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges")
            .fetch_one(&self.pool)
            .await?;

        Ok(count as u64)
    }

    /// Delete edges older than a certain block number (for cleanup).
    pub async fn delete_edges_before_block(&self, block_number: u64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM edges WHERE block_number < ?")
            .bind(block_number as i64)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Helper function to convert a database row to an EdgeRecord.
    fn row_to_edge_record(row: sqlx::sqlite::SqliteRow) -> Result<EdgeRecord> {
        let rater_bytes: Vec<u8> = row.get("rater");
        let target_bytes: Vec<u8> = row.get("target");
        let context_bytes: Vec<u8> = row.get("context_id");
        let level: i32 = row.get("level");
        let source_str: String = row.get("source");
        let tx_hash_bytes: Option<Vec<u8>> = row.get("tx_hash");

        let rater = Address::from_slice(&rater_bytes);
        let target = Address::from_slice(&target_bytes);
        let context_id = ContextId::from(<[u8; 32]>::try_from(context_bytes.as_slice())?);
        let level = Level::new(level as i8)?;
        let source = source_str
            .parse::<EdgeSource>()
            .map_err(|e| anyhow::anyhow!("Invalid edge source in database: {}", e))?;
        let tx_hash = tx_hash_bytes.map(|bytes| B256::from_slice(&bytes));

        Ok(EdgeRecord {
            rater,
            target,
            context_id,
            level,
            block_number: row.get::<i64, _>("block_number") as u64,
            tx_index: row.get::<i64, _>("tx_index") as u64,
            log_index: row.get::<i64, _>("log_index") as u64,
            ingested_at: row.get("ingested_at"),
            source,
            tx_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use tempfile::NamedTempFile;

    async fn setup_storage() -> (Storage, NamedTempFile) {
        let temp_db = NamedTempFile::new().unwrap();
        let storage = Storage::new_with_path(temp_db.path(), None, None)
            .await
            .unwrap();
        storage.run_migrations().await.unwrap();
        (storage, temp_db) // Keep temp_db alive
    }

    #[tokio::test]
    async fn test_upsert_edge() {
        let (storage, _temp_db) = setup_storage().await;

        let rater = Address::from(hex!("1111111111111111111111111111111111111111"));
        let target = Address::from(hex!("2222222222222222222222222222222222222222"));
        let context_id = ContextId::from(hex!(
            "430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b"
        ));

        let edge = EdgeRecord {
            rater,
            target,
            context_id,
            level: Level::positive(),
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            ingested_at: 1234567890,
            source: EdgeSource::TrustGraph,
            tx_hash: None,
        };

        // Insert new edge
        let inserted = storage.upsert_edge(&edge).await.unwrap();
        assert!(inserted);

        // Retrieve and verify
        let retrieved = storage
            .get_edge(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.level, edge.level);
        assert_eq!(retrieved.block_number, 100);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_latest_wins_semantics() {
        let (storage, _temp_db) = setup_storage().await;

        let rater = Address::from(hex!("1111111111111111111111111111111111111111"));
        let target = Address::from(hex!("2222222222222222222222222222222222222222"));
        let context_id = ContextId::from(hex!(
            "430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b"
        ));

        // Insert initial edge at block 100
        let edge1 = EdgeRecord {
            rater,
            target,
            context_id,
            level: Level::positive(),
            block_number: 100,
            tx_index: 5,
            log_index: 2,
            ingested_at: 1234567890,
            source: EdgeSource::TrustGraph,
            tx_hash: None,
        };
        let inserted = storage.upsert_edge(&edge1).await.unwrap();
        assert!(inserted, "First edge should be inserted");

        // Try to insert older edge at block 99 (should be rejected)
        let edge2 = EdgeRecord {
            level: Level::negative(),
            block_number: 99,
            tx_index: 10,
            log_index: 0,
            ingested_at: 1234567891,
            ..edge1.clone()
        };
        let updated = storage.upsert_edge(&edge2).await.unwrap();
        assert!(!updated, "Older edge should be rejected (return false)");

        // Should still have the first edge
        let retrieved = storage
            .get_edge(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.level, Level::positive());
        assert_eq!(retrieved.block_number, 100);

        // Insert newer edge at block 101 (should replace)
        let edge3 = EdgeRecord {
            level: Level::strong_positive(),
            block_number: 101,
            tx_index: 0,
            log_index: 0,
            ingested_at: 1234567892,
            ..edge1.clone()
        };
        let updated = storage.upsert_edge(&edge3).await.unwrap();
        assert!(updated, "Newer edge should be accepted (return true)");

        // Should have the new edge
        let retrieved = storage
            .get_edge(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.level, Level::strong_positive());
        assert_eq!(retrieved.block_number, 101);

        // Try same coordinates again (should be rejected)
        let edge4 = EdgeRecord {
            level: Level::negative(),
            ..edge3.clone()
        };
        let updated = storage.upsert_edge(&edge4).await.unwrap();
        assert!(!updated, "Same block coordinates should be rejected");

        storage.close().await;
    }

    #[tokio::test]
    async fn test_get_edges_from_rater() {
        let (storage, _temp_db) = setup_storage().await;

        let rater = Address::from(hex!("1111111111111111111111111111111111111111"));
        let target1 = Address::from(hex!("2222222222222222222222222222222222222222"));
        let target2 = Address::from(hex!("3333333333333333333333333333333333333333"));
        let context_id = ContextId::from(hex!(
            "430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b"
        ));

        // Insert two edges from same rater
        let edge1 = EdgeRecord {
            rater,
            target: target1,
            context_id,
            level: Level::positive(),
            block_number: 100,
            tx_index: 0,
            log_index: 0,
            ingested_at: 1234567890,
            source: EdgeSource::TrustGraph,
            tx_hash: None,
        };
        storage.upsert_edge(&edge1).await.unwrap();

        let edge2 = EdgeRecord {
            target: target2,
            level: Level::strong_positive(),
            ..edge1.clone()
        };
        storage.upsert_edge(&edge2).await.unwrap();

        // Query edges from rater
        let edges = storage
            .get_edges_from_rater(&rater, &context_id)
            .await
            .unwrap();
        assert_eq!(edges.len(), 2);

        storage.close().await;
    }
}
