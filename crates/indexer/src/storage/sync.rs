//! Sync state storage operations.

use super::{BlockRecord, Storage, SyncState};
use alloy::primitives::B256;
use anyhow::{Context, Result};
use sqlx::Row;

impl Storage {
    /// Get the current sync state.
    pub async fn get_sync_state(&self) -> Result<SyncState> {
        let row = sqlx::query(
            r#"
            SELECT last_block_number, last_block_hash, updated_at, chain_id
            FROM sync_state
            WHERE id = 1
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to fetch sync state")?;

        let hash_bytes: Vec<u8> = row.get("last_block_hash");

        Ok(SyncState {
            last_block_number: row.get::<i64, _>("last_block_number") as u64,
            last_block_hash: B256::from_slice(&hash_bytes),
            updated_at: row.get("updated_at"),
            chain_id: row.get::<i64, _>("chain_id") as u64,
        })
    }

    /// Update the sync state.
    pub async fn update_sync_state(&self, state: &SyncState) -> Result<()> {
        let hash_bytes = state.last_block_hash.as_slice();

        sqlx::query(
            r#"
            UPDATE sync_state
            SET last_block_number = ?,
                last_block_hash = ?,
                updated_at = ?,
                chain_id = ?
            WHERE id = 1
            "#,
        )
        .bind(state.last_block_number as i64)
        .bind(hash_bytes)
        .bind(state.updated_at)
        .bind(state.chain_id as i64)
        .execute(&self.pool)
        .await
        .context("Failed to update sync state")?;

        Ok(())
    }

    /// Initialize sync state for a new chain.
    pub async fn initialize_sync_state(
        &self,
        chain_id: u64,
        start_block: u64,
        block_hash: B256,
    ) -> Result<()> {
        let hash_bytes = block_hash.as_slice();
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            r#"
            UPDATE sync_state
            SET last_block_number = ?,
                last_block_hash = ?,
                updated_at = ?,
                chain_id = ?
            WHERE id = 1
            "#,
        )
        .bind(start_block as i64)
        .bind(hash_bytes)
        .bind(now)
        .bind(chain_id as i64)
        .execute(&self.pool)
        .await
        .context("Failed to initialize sync state")?;

        Ok(())
    }

    /// Insert a block record.
    pub async fn insert_block(&self, block: &BlockRecord) -> Result<()> {
        let hash_bytes = block.block_hash.as_slice();
        let parent_bytes = block.parent_hash.as_slice();

        sqlx::query(
            r#"
            INSERT INTO blocks (
                block_number, block_hash, parent_hash,
                timestamp, event_count, indexed_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(block_number) DO UPDATE SET
                block_hash = excluded.block_hash,
                parent_hash = excluded.parent_hash,
                timestamp = excluded.timestamp,
                event_count = excluded.event_count,
                indexed_at = excluded.indexed_at
            "#,
        )
        .bind(block.block_number as i64)
        .bind(hash_bytes)
        .bind(parent_bytes)
        .bind(block.timestamp as i64)
        .bind(block.event_count as i64)
        .bind(block.indexed_at)
        .execute(&self.pool)
        .await
        .context("Failed to insert block")?;

        Ok(())
    }

    /// Get a block by number.
    pub async fn get_block(&self, block_number: u64) -> Result<Option<BlockRecord>> {
        let row = sqlx::query(
            r#"
            SELECT block_number, block_hash, parent_hash,
                   timestamp, event_count, indexed_at
            FROM blocks
            WHERE block_number = ?
            "#,
        )
        .bind(block_number as i64)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_block_record(row)?)),
            None => Ok(None),
        }
    }

    /// Get a block by hash.
    pub async fn get_block_by_hash(&self, block_hash: &B256) -> Result<Option<BlockRecord>> {
        let hash_bytes = block_hash.as_slice();

        let row = sqlx::query(
            r#"
            SELECT block_number, block_hash, parent_hash,
                   timestamp, event_count, indexed_at
            FROM blocks
            WHERE block_hash = ?
            "#,
        )
        .bind(hash_bytes)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_block_record(row)?)),
            None => Ok(None),
        }
    }

    /// Check if a reorg occurred by validating parent hash.
    ///
    /// Returns true if the parent hash of the given block doesn't match
    /// the stored hash for the previous block.
    pub async fn check_for_reorg(
        &self,
        block_number: u64,
        expected_parent_hash: &B256,
    ) -> Result<bool> {
        if block_number == 0 {
            return Ok(false);
        }

        let prev_block = self.get_block(block_number - 1).await?;

        match prev_block {
            Some(prev) => Ok(prev.block_hash != *expected_parent_hash),
            None => Ok(false), // No previous block stored yet
        }
    }

    /// Delete blocks after a certain number (for reorg handling).
    pub async fn delete_blocks_after(&self, block_number: u64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM blocks WHERE block_number > ?")
            .bind(block_number as i64)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Helper function to convert a database row to a BlockRecord.
    fn row_to_block_record(row: sqlx::sqlite::SqliteRow) -> Result<BlockRecord> {
        let hash_bytes: Vec<u8> = row.get("block_hash");
        let parent_bytes: Vec<u8> = row.get("parent_hash");

        Ok(BlockRecord {
            block_number: row.get::<i64, _>("block_number") as u64,
            block_hash: B256::from_slice(&hash_bytes),
            parent_hash: B256::from_slice(&parent_bytes),
            timestamp: row.get::<i64, _>("timestamp") as u64,
            event_count: row.get::<i64, _>("event_count") as u64,
            indexed_at: row.get("indexed_at"),
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
        (storage, temp_db)
    }

    #[tokio::test]
    async fn test_sync_state_operations() {
        let (storage, _temp_db) = setup_storage().await;

        // Get initial state (created by migration)
        let state = storage.get_sync_state().await.unwrap();
        assert_eq!(state.last_block_number, 0);
        assert_eq!(state.chain_id, 0);

        // Initialize for Sepolia
        let block_hash = B256::from(hex!(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ));
        storage
            .initialize_sync_state(11155111, 1000, block_hash)
            .await
            .unwrap();

        // Verify updated state
        let state = storage.get_sync_state().await.unwrap();
        assert_eq!(state.last_block_number, 1000);
        assert_eq!(state.chain_id, 11155111);
        assert_eq!(state.last_block_hash, block_hash);

        // Update to new block
        let new_hash = B256::from(hex!(
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        ));
        let new_state = SyncState {
            last_block_number: 1001,
            last_block_hash: new_hash,
            updated_at: chrono::Utc::now().timestamp(),
            chain_id: 11155111,
        };
        storage.update_sync_state(&new_state).await.unwrap();

        let state = storage.get_sync_state().await.unwrap();
        assert_eq!(state.last_block_number, 1001);
        assert_eq!(state.last_block_hash, new_hash);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_block_operations() {
        let (storage, _temp_db) = setup_storage().await;

        let block = BlockRecord {
            block_number: 100,
            block_hash: B256::from([1u8; 32]),
            parent_hash: B256::from([0u8; 32]),
            timestamp: 1234567890,
            event_count: 5,
            indexed_at: chrono::Utc::now().timestamp(),
        };

        // Insert block
        storage.insert_block(&block).await.unwrap();

        // Get by number
        let retrieved = storage.get_block(100).await.unwrap().unwrap();
        assert_eq!(retrieved.block_number, 100);
        assert_eq!(retrieved.event_count, 5);

        // Get by hash
        let by_hash = storage
            .get_block_by_hash(&block.block_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_hash.block_number, 100);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_reorg_detection() {
        let (storage, _temp_db) = setup_storage().await;

        // Insert block 99
        let block99 = BlockRecord {
            block_number: 99,
            block_hash: B256::from([99u8; 32]),
            parent_hash: B256::from([98u8; 32]),
            timestamp: 1234567890,
            event_count: 0,
            indexed_at: chrono::Utc::now().timestamp(),
        };
        storage.insert_block(&block99).await.unwrap();

        // Check for reorg with correct parent (no reorg)
        let reorg = storage
            .check_for_reorg(100, &B256::from([99u8; 32]))
            .await
            .unwrap();
        assert!(!reorg);

        // Check for reorg with incorrect parent (reorg detected)
        let reorg = storage
            .check_for_reorg(100, &B256::from([88u8; 32]))
            .await
            .unwrap();
        assert!(reorg);

        storage.close().await;
    }
}
