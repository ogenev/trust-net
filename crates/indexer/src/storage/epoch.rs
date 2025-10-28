//! Epoch storage operations.

use super::{EpochRecord, Storage};
use alloy::primitives::B256;
use anyhow::{Context, Result};
use sqlx::Row;

impl Storage {
    /// Insert a new epoch record.
    ///
    /// Epochs must be inserted in order (monotonically increasing).
    pub async fn insert_epoch(&self, epoch: &EpochRecord) -> Result<()> {
        let root_bytes = epoch.graph_root.as_slice();
        let tx_hash_bytes = epoch.tx_hash.as_ref().map(|h| h.as_slice());

        sqlx::query(
            r#"
            INSERT INTO epochs (
                epoch, graph_root, published_at_block,
                published_at, tx_hash, edge_count, manifest
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(epoch.epoch as i64)
        .bind(root_bytes)
        .bind(epoch.published_at_block as i64)
        .bind(epoch.published_at)
        .bind(tx_hash_bytes)
        .bind(epoch.edge_count as i64)
        .bind(&epoch.manifest)
        .execute(&self.pool)
        .await
        .context("Failed to insert epoch")?;

        Ok(())
    }

    /// Get the latest epoch.
    pub async fn get_latest_epoch(&self) -> Result<Option<EpochRecord>> {
        let row = sqlx::query(
            r#"
            SELECT epoch, graph_root, published_at_block,
                   published_at, tx_hash, edge_count, manifest
            FROM epochs
            ORDER BY epoch DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_epoch_record(row)?)),
            None => Ok(None),
        }
    }

    /// Get a specific epoch by number.
    pub async fn get_epoch(&self, epoch_number: u64) -> Result<Option<EpochRecord>> {
        let row = sqlx::query(
            r#"
            SELECT epoch, graph_root, published_at_block,
                   published_at, tx_hash, edge_count, manifest
            FROM epochs
            WHERE epoch = ?
            "#,
        )
        .bind(epoch_number as i64)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_epoch_record(row)?)),
            None => Ok(None),
        }
    }

    /// Get an epoch by its root hash.
    pub async fn get_epoch_by_root(&self, root: &B256) -> Result<Option<EpochRecord>> {
        let root_bytes = root.as_slice();

        let row = sqlx::query(
            r#"
            SELECT epoch, graph_root, published_at_block,
                   published_at, tx_hash, edge_count, manifest
            FROM epochs
            WHERE graph_root = ?
            "#,
        )
        .bind(root_bytes)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(Self::row_to_epoch_record(row)?)),
            None => Ok(None),
        }
    }

    /// Get all epochs in descending order.
    pub async fn get_all_epochs(&self) -> Result<Vec<EpochRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT epoch, graph_root, published_at_block,
                   published_at, tx_hash, edge_count, manifest
            FROM epochs
            ORDER BY epoch DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_epoch_record).collect()
    }

    /// Get epochs in a specific range.
    pub async fn get_epochs_range(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<Vec<EpochRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT epoch, graph_root, published_at_block,
                   published_at, tx_hash, edge_count, manifest
            FROM epochs
            WHERE epoch >= ? AND epoch <= ?
            ORDER BY epoch ASC
            "#,
        )
        .bind(start_epoch as i64)
        .bind(end_epoch as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_epoch_record).collect()
    }

    /// Count total epochs.
    pub async fn count_epochs(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM epochs")
            .fetch_one(&self.pool)
            .await?;

        Ok(count as u64)
    }

    /// Helper function to convert a database row to an EpochRecord.
    fn row_to_epoch_record(row: sqlx::sqlite::SqliteRow) -> Result<EpochRecord> {
        let root_bytes: Vec<u8> = row.get("graph_root");
        let tx_hash_bytes: Option<Vec<u8>> = row.get("tx_hash");

        let graph_root = B256::from_slice(&root_bytes);
        let tx_hash = tx_hash_bytes.map(|bytes| B256::from_slice(&bytes));

        Ok(EpochRecord {
            epoch: row.get::<i64, _>("epoch") as u64,
            graph_root,
            published_at_block: row.get::<i64, _>("published_at_block") as u64,
            published_at: row.get("published_at"),
            tx_hash,
            edge_count: row.get::<i64, _>("edge_count") as u64,
            manifest: row.get("manifest"),
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
    async fn test_insert_and_get_epoch() {
        let (storage, _temp_db) = setup_storage().await;

        let epoch = EpochRecord {
            epoch: 1,
            graph_root: B256::from(hex!(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            )),
            published_at_block: 1000,
            published_at: 1234567890,
            tx_hash: Some(B256::from(hex!(
                "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            ))),
            edge_count: 42,
            manifest: Some(r#"{"version": "v1"}"#.to_string()),
        };

        storage.insert_epoch(&epoch).await.unwrap();

        // Get by epoch number
        let retrieved = storage.get_epoch(1).await.unwrap().unwrap();
        assert_eq!(retrieved.epoch, 1);
        assert_eq!(retrieved.graph_root, epoch.graph_root);
        assert_eq!(retrieved.edge_count, 42);

        // Get latest
        let latest = storage.get_latest_epoch().await.unwrap().unwrap();
        assert_eq!(latest.epoch, 1);

        // Get by root
        let by_root = storage
            .get_epoch_by_root(&epoch.graph_root)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_root.epoch, 1);

        storage.close().await;
    }

    #[tokio::test]
    async fn test_multiple_epochs() {
        let (storage, _temp_db) = setup_storage().await;

        // Insert multiple epochs
        for i in 1..=5 {
            let epoch = EpochRecord {
                epoch: i,
                graph_root: B256::from([i as u8; 32]),
                published_at_block: 1000 + (i * 100),
                published_at: 1234567890 + (i as i64 * 3600),
                tx_hash: None,
                edge_count: i * 10,
                manifest: None,
            };
            storage.insert_epoch(&epoch).await.unwrap();
        }

        // Get latest
        let latest = storage.get_latest_epoch().await.unwrap().unwrap();
        assert_eq!(latest.epoch, 5);

        // Get range
        let range = storage.get_epochs_range(2, 4).await.unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].epoch, 2);
        assert_eq!(range[2].epoch, 4);

        // Count
        let count = storage.count_epochs().await.unwrap();
        assert_eq!(count, 5);

        storage.close().await;
    }
}
