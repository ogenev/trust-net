//! Edge storage operations (TrustNet spec v0.6).

use super::{EdgeRecord, EdgeSource, Storage};
use alloy::primitives::B256;
use anyhow::{Context, Result};
use sqlx::Row;
use trustnet_core::types::{ContextId, Level, PrincipalId};

impl Storage {
    /// Append an event to the immutable `edges_raw` table.
    ///
    /// Returns the inserted row id.
    pub async fn append_edge_raw(&self, edge: &EdgeRecord) -> Result<i64> {
        let rater_pid = edge.rater.as_bytes().as_slice();
        let target_pid = edge.target.as_bytes().as_slice();
        let context_id = edge.context_id.as_bytes().as_slice();
        let evidence_hash = edge.evidence_hash.as_slice();
        let evidence_uri = edge.evidence_uri.as_deref();
        let subject_id = edge.subject_id.as_ref().map(|id| id.as_bytes().as_slice());

        let tx_hash_bytes = edge.tx_hash.as_ref().map(|h| h.as_slice());

        let chain_id = edge.chain_id.map(|v| v as i64);
        let block_number = edge.block_number.map(|v| v as i64);
        let tx_index = edge.tx_index.map(|v| v as i64);
        let log_index = edge.log_index.map(|v| v as i64);
        let server_seq = edge.server_seq.map(|v| v as i64);

        let result = sqlx::query(
            r#"
            INSERT INTO edges_raw (
                rater_pid, target_pid, context_id,
                level_i8, updated_at_u64, evidence_hash, evidence_uri,
                source,
                observed_at_u64,
                subject_id,
                chain_id, block_number, tx_index, log_index, tx_hash,
                server_seq
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chain_id, tx_hash, log_index) DO NOTHING
            "#,
        )
        .bind(rater_pid)
        .bind(target_pid)
        .bind(context_id)
        .bind(edge.level.value() as i32)
        .bind(edge.updated_at_u64 as i64)
        .bind(evidence_hash)
        .bind(evidence_uri)
        .bind(edge.source.as_str())
        .bind(edge.observed_at_u64 as i64)
        .bind(subject_id)
        .bind(chain_id)
        .bind(block_number)
        .bind(tx_index)
        .bind(log_index)
        .bind(tx_hash_bytes)
        .bind(server_seq)
        .execute(&self.pool)
        .await
        .context("Failed to append edges_raw")?;

        if result.rows_affected() > 0 {
            return Ok(result.last_insert_rowid());
        }

        // Idempotent replays: return the existing row id.
        let Some(chain_id) = edge.chain_id else {
            anyhow::bail!("edges_raw insert ignored without chain_id");
        };
        let Some(tx_hash) = edge.tx_hash else {
            anyhow::bail!("edges_raw insert ignored without tx_hash");
        };
        let Some(log_index) = edge.log_index else {
            anyhow::bail!("edges_raw insert ignored without log_index");
        };

        let id: i64 = sqlx::query_scalar(
            r#"
            SELECT id
            FROM edges_raw
            WHERE chain_id = ?
              AND tx_hash = ?
              AND log_index = ?
            "#,
        )
        .bind(chain_id as i64)
        .bind(tx_hash.as_slice())
        .bind(log_index as i64)
        .fetch_one(&self.pool)
        .await
        .context("Failed to fetch existing edges_raw id")?;

        Ok(id)
    }

    /// Upsert an edge into `edges_latest` with deterministic latest-wins semantics.
    ///
    /// Returns `true` if inserted/updated, `false` if stale.
    pub async fn upsert_edge_latest(&self, edge: &EdgeRecord) -> Result<bool> {
        match edge.source {
            EdgeSource::PrivateLog => self.upsert_edge_latest_server(edge).await,
            EdgeSource::TrustGraph | EdgeSource::Erc8004 => {
                self.upsert_edge_latest_chain(edge).await
            }
        }
    }

    async fn upsert_edge_latest_chain(&self, edge: &EdgeRecord) -> Result<bool> {
        let Some(chain_id) = edge.chain_id else {
            anyhow::bail!("chain edge missing chain_id");
        };
        let Some(block_number) = edge.block_number else {
            anyhow::bail!("chain edge missing block_number");
        };
        let Some(tx_index) = edge.tx_index else {
            anyhow::bail!("chain edge missing tx_index");
        };
        let Some(log_index) = edge.log_index else {
            anyhow::bail!("chain edge missing log_index");
        };
        let Some(tx_hash) = edge.tx_hash else {
            anyhow::bail!("chain edge missing tx_hash");
        };

        let rater_pid = edge.rater.as_bytes().as_slice();
        let target_pid = edge.target.as_bytes().as_slice();
        let context_id = edge.context_id.as_bytes().as_slice();
        let evidence_hash = edge.evidence_hash.as_slice();
        let evidence_uri = edge.evidence_uri.as_deref();
        let subject_id = edge.subject_id.as_ref().map(|id| id.as_bytes().as_slice());
        let tx_hash_bytes = tx_hash.as_slice();

        let result = sqlx::query(
            r#"
            INSERT INTO edges_latest (
                rater_pid, target_pid, context_id,
                level_i8, updated_at_u64, evidence_hash, evidence_uri, source,
                observed_at_u64,
                subject_id,
                chain_id, block_number, tx_index, log_index, tx_hash,
                server_seq
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(rater_pid, target_pid, context_id)
            DO UPDATE SET
                level_i8 = excluded.level_i8,
                updated_at_u64 = excluded.updated_at_u64,
                evidence_hash = excluded.evidence_hash,
                evidence_uri = excluded.evidence_uri,
                source = excluded.source,
                observed_at_u64 = excluded.observed_at_u64,
                subject_id = excluded.subject_id,
                chain_id = excluded.chain_id,
                block_number = excluded.block_number,
                tx_index = excluded.tx_index,
                log_index = excluded.log_index,
                tx_hash = excluded.tx_hash,
                server_seq = NULL
            WHERE edges_latest.block_number IS NULL
               OR (excluded.block_number > edges_latest.block_number)
               OR (excluded.block_number = edges_latest.block_number AND excluded.tx_index > edges_latest.tx_index)
               OR (excluded.block_number = edges_latest.block_number AND excluded.tx_index = edges_latest.tx_index AND excluded.log_index > edges_latest.log_index)
               OR (excluded.block_number = edges_latest.block_number AND excluded.tx_index = edges_latest.tx_index AND excluded.log_index = edges_latest.log_index AND (edges_latest.tx_hash IS NULL OR excluded.tx_hash > edges_latest.tx_hash))
            "#,
        )
        .bind(rater_pid)
        .bind(target_pid)
        .bind(context_id)
        .bind(edge.level.value() as i32)
        .bind(edge.updated_at_u64 as i64)
        .bind(evidence_hash)
        .bind(evidence_uri)
        .bind(edge.source.as_str())
        .bind(edge.observed_at_u64 as i64)
        .bind(subject_id)
        .bind(chain_id as i64)
        .bind(block_number as i64)
        .bind(tx_index as i64)
        .bind(log_index as i64)
        .bind(tx_hash_bytes)
        .execute(&self.pool)
        .await
        .context("Failed to upsert edges_latest (chain)")?;

        Ok(result.rows_affected() > 0)
    }

    async fn upsert_edge_latest_server(&self, edge: &EdgeRecord) -> Result<bool> {
        let Some(server_seq) = edge.server_seq else {
            anyhow::bail!("server edge missing server_seq");
        };

        let rater_pid = edge.rater.as_bytes().as_slice();
        let target_pid = edge.target.as_bytes().as_slice();
        let context_id = edge.context_id.as_bytes().as_slice();
        let evidence_hash = edge.evidence_hash.as_slice();
        let evidence_uri = edge.evidence_uri.as_deref();
        let subject_id = edge.subject_id.as_ref().map(|id| id.as_bytes().as_slice());

        let result = sqlx::query(
            r#"
            INSERT INTO edges_latest (
                rater_pid, target_pid, context_id,
                level_i8, updated_at_u64, evidence_hash, evidence_uri, source,
                observed_at_u64,
                subject_id,
                chain_id, block_number, tx_index, log_index, tx_hash,
                server_seq
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?)
            ON CONFLICT(rater_pid, target_pid, context_id)
            DO UPDATE SET
                level_i8 = excluded.level_i8,
                updated_at_u64 = excluded.updated_at_u64,
                evidence_hash = excluded.evidence_hash,
                evidence_uri = excluded.evidence_uri,
                source = excluded.source,
                observed_at_u64 = excluded.observed_at_u64,
                subject_id = excluded.subject_id,
                chain_id = NULL,
                block_number = NULL,
                tx_index = NULL,
                log_index = NULL,
                tx_hash = NULL,
                server_seq = excluded.server_seq
            WHERE edges_latest.server_seq IS NULL
               OR (excluded.server_seq > edges_latest.server_seq)
            "#,
        )
        .bind(rater_pid)
        .bind(target_pid)
        .bind(context_id)
        .bind(edge.level.value() as i32)
        .bind(edge.updated_at_u64 as i64)
        .bind(evidence_hash)
        .bind(evidence_uri)
        .bind(edge.source.as_str())
        .bind(edge.observed_at_u64 as i64)
        .bind(subject_id)
        .bind(server_seq as i64)
        .execute(&self.pool)
        .await
        .context("Failed to upsert edges_latest (server)")?;

        Ok(result.rows_affected() > 0)
    }

    /// Fetch a latest-wins edge by key.
    pub async fn get_edge_latest(
        &self,
        rater: &PrincipalId,
        target: &PrincipalId,
        context_id: &ContextId,
    ) -> Result<Option<EdgeRecord>> {
        let row = sqlx::query(
            r#"
            SELECT
                rater_pid, target_pid, context_id,
                level_i8, updated_at_u64, evidence_hash, evidence_uri,
                source,
                observed_at_u64,
                subject_id,
                chain_id, block_number, tx_index, log_index, tx_hash,
                server_seq
            FROM edges_latest
            WHERE rater_pid = ? AND target_pid = ? AND context_id = ?
            "#,
        )
        .bind(rater.as_bytes().as_slice())
        .bind(target.as_bytes().as_slice())
        .bind(context_id.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await?;

        row.map(Self::row_to_edge_record).transpose()
    }

    /// Get all latest-wins edges (for building an SMM).
    pub async fn get_all_edges_latest(&self) -> Result<Vec<EdgeRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT
                rater_pid, target_pid, context_id,
                level_i8, updated_at_u64, evidence_hash, evidence_uri,
                source,
                observed_at_u64,
                subject_id,
                chain_id, block_number, tx_index, log_index, tx_hash,
                server_seq
            FROM edges_latest
            ORDER BY
                -- Prefer chain ordering when present, otherwise server ordering.
                COALESCE(block_number, 0) DESC,
                COALESCE(tx_index, 0) DESC,
                COALESCE(log_index, 0) DESC,
                COALESCE(server_seq, 0) DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(Self::row_to_edge_record).collect()
    }

    /// Count total latest-wins edges.
    pub async fn count_edges_latest(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges_latest")
            .fetch_one(&self.pool)
            .await?;
        Ok(count as u64)
    }

    /// Delete chain edges older than a certain block number (cleanup).
    ///
    /// This deletes both raw and latest rows where the stored chain ordering is below the given
    /// block number. Server-mode edges are not affected.
    pub async fn delete_chain_edges_before_block(&self, block_number: u64) -> Result<u64> {
        let result_raw = sqlx::query(
            "DELETE FROM edges_raw WHERE block_number IS NOT NULL AND block_number < ?",
        )
        .bind(block_number as i64)
        .execute(&self.pool)
        .await?;

        let result_latest = sqlx::query(
            "DELETE FROM edges_latest WHERE block_number IS NOT NULL AND block_number < ?",
        )
        .bind(block_number as i64)
        .execute(&self.pool)
        .await?;

        Ok(result_raw.rows_affected() + result_latest.rows_affected())
    }

    fn row_to_edge_record(row: sqlx::sqlite::SqliteRow) -> Result<EdgeRecord> {
        let rater_pid: Vec<u8> = row.get("rater_pid");
        let target_pid: Vec<u8> = row.get("target_pid");
        let context_id_bytes: Vec<u8> = row.get("context_id");

        let level_i8: i32 = row.get("level_i8");
        let updated_at_u64: i64 = row.get("updated_at_u64");
        let evidence_hash_bytes: Vec<u8> = row.get("evidence_hash");
        let evidence_uri: Option<String> = row.try_get("evidence_uri").unwrap_or(None);
        let source_str: String = row.get("source");
        let observed_at_u64: i64 = row.try_get("observed_at_u64").unwrap_or(0i64);
        let subject_id_bytes: Option<Vec<u8>> = row.try_get("subject_id").unwrap_or(None);

        let chain_id: Option<i64> = row.try_get("chain_id").ok();
        let block_number: Option<i64> = row.try_get("block_number").ok();
        let tx_index: Option<i64> = row.try_get("tx_index").ok();
        let log_index: Option<i64> = row.try_get("log_index").ok();
        let tx_hash_bytes: Option<Vec<u8>> = row.try_get("tx_hash").ok();
        let server_seq: Option<i64> = row.try_get("server_seq").ok();

        let rater_pid = PrincipalId::from(<[u8; 32]>::try_from(rater_pid.as_slice())?);
        let target_pid = PrincipalId::from(<[u8; 32]>::try_from(target_pid.as_slice())?);
        let context_id = ContextId::from(<[u8; 32]>::try_from(context_id_bytes.as_slice())?);

        let level = Level::new(level_i8 as i8)?;
        let source = source_str
            .parse::<EdgeSource>()
            .map_err(|e| anyhow::anyhow!("Invalid edge source in database: {}", e))?;

        let evidence_hash = if evidence_hash_bytes.len() == 32 {
            B256::from_slice(&evidence_hash_bytes)
        } else {
            B256::ZERO
        };

        let subject_id = match subject_id_bytes {
            Some(bytes) if bytes.len() == 32 => Some(trustnet_core::types::SubjectId::from(
                <[u8; 32]>::try_from(bytes.as_slice())?,
            )),
            _ => None,
        };

        let tx_hash = tx_hash_bytes
            .as_ref()
            .and_then(|bytes| (bytes.len() == 32).then(|| B256::from_slice(bytes)));

        Ok(EdgeRecord {
            rater: rater_pid,
            target: target_pid,
            context_id,
            level,
            updated_at_u64: updated_at_u64 as u64,
            evidence_hash,
            evidence_uri,
            observed_at_u64: observed_at_u64 as u64,
            subject_id,
            source,
            chain_id: chain_id.map(|v| v as u64),
            block_number: block_number.map(|v| v as u64),
            tx_index: tx_index.map(|v| v as u64),
            log_index: log_index.map(|v| v as u64),
            tx_hash,
            server_seq: server_seq.map(|v| v as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use trustnet_core::types::{ContextId, Level};

    async fn setup_storage() -> (Storage, NamedTempFile) {
        let temp_db = NamedTempFile::new().unwrap();
        let storage = Storage::new_with_path(temp_db.path(), None, None)
            .await
            .unwrap();
        storage.run_migrations().await.unwrap();
        (storage, temp_db)
    }

    #[tokio::test]
    async fn test_latest_wins_chain_ordering() {
        let (storage, _temp_db) = setup_storage().await;

        let rater = PrincipalId::from([0x11u8; 32]);
        let target = PrincipalId::from([0x22u8; 32]);
        let context_id = ContextId::from([0x33u8; 32]);

        let base = EdgeRecord {
            rater,
            target,
            subject_id: None,
            context_id,
            level: Level::positive(),
            updated_at_u64: 1,
            evidence_hash: B256::ZERO,
            evidence_uri: None,
            observed_at_u64: 1,
            source: EdgeSource::TrustGraph,
            chain_id: Some(1),
            block_number: Some(100),
            tx_index: Some(1),
            log_index: Some(1),
            tx_hash: Some(B256::repeat_byte(0xaa)),
            server_seq: None,
        };

        // Insert base
        storage.append_edge_raw(&base).await.unwrap();
        assert!(storage.upsert_edge_latest(&base).await.unwrap());

        // Older event (stale)
        let mut older = base.clone();
        older.level = Level::strong_positive();
        older.block_number = Some(99);
        older.tx_hash = Some(B256::repeat_byte(0xbb));
        storage.append_edge_raw(&older).await.unwrap();
        assert!(!storage.upsert_edge_latest(&older).await.unwrap());

        // Newer event (wins)
        let mut newer = base.clone();
        newer.level = Level::strong_negative();
        newer.block_number = Some(100);
        newer.tx_index = Some(2);
        newer.tx_hash = Some(B256::repeat_byte(0xcc));
        storage.append_edge_raw(&newer).await.unwrap();
        assert!(storage.upsert_edge_latest(&newer).await.unwrap());

        let got = storage
            .get_edge_latest(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.level, Level::strong_negative());
        assert_eq!(got.block_number, Some(100));
        assert_eq!(got.tx_index, Some(2));
    }

    #[tokio::test]
    async fn test_latest_wins_chain_tie_breaker_by_tx_hash() {
        let (storage, _temp_db) = setup_storage().await;

        let rater = PrincipalId::from([0x11u8; 32]);
        let target = PrincipalId::from([0x22u8; 32]);
        let context_id = ContextId::from([0x33u8; 32]);

        let mut a = EdgeRecord {
            rater,
            target,
            subject_id: None,
            context_id,
            level: Level::positive(),
            updated_at_u64: 1,
            evidence_hash: B256::ZERO,
            evidence_uri: None,
            observed_at_u64: 1,
            source: EdgeSource::TrustGraph,
            chain_id: Some(1),
            block_number: Some(100),
            tx_index: Some(1),
            log_index: Some(1),
            tx_hash: Some(B256::repeat_byte(0x01)),
            server_seq: None,
        };

        let mut b = a.clone();
        b.level = Level::strong_negative();
        b.tx_hash = Some(B256::repeat_byte(0x02));

        storage.append_edge_raw(&a).await.unwrap();
        assert!(storage.upsert_edge_latest(&a).await.unwrap());

        storage.append_edge_raw(&b).await.unwrap();
        assert!(storage.upsert_edge_latest(&b).await.unwrap());

        let got = storage
            .get_edge_latest(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.level, Level::strong_negative());
        assert_eq!(got.tx_hash, Some(B256::repeat_byte(0x02)));

        // Ingesting the lower txHash later must not change the result.
        a.level = Level::strong_positive();
        storage.append_edge_raw(&a).await.unwrap();
        assert!(!storage.upsert_edge_latest(&a).await.unwrap());
        let got = storage
            .get_edge_latest(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.tx_hash, Some(B256::repeat_byte(0x02)));
    }

    #[tokio::test]
    async fn test_append_edge_raw_chain_is_idempotent() {
        let (storage, _temp_db) = setup_storage().await;

        let edge = EdgeRecord {
            rater: PrincipalId::from([0x11u8; 32]),
            target: PrincipalId::from([0x22u8; 32]),
            subject_id: None,
            context_id: ContextId::from([0x33u8; 32]),
            level: Level::positive(),
            updated_at_u64: 1,
            evidence_hash: B256::ZERO,
            evidence_uri: None,
            observed_at_u64: 1,
            source: EdgeSource::TrustGraph,
            chain_id: Some(1),
            block_number: Some(100),
            tx_index: Some(1),
            log_index: Some(1),
            tx_hash: Some(B256::repeat_byte(0xaa)),
            server_seq: None,
        };

        let id1 = storage.append_edge_raw(&edge).await.unwrap();
        let id2 = storage.append_edge_raw(&edge).await.unwrap();
        assert_eq!(id1, id2);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges_raw")
            .fetch_one(storage.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}
