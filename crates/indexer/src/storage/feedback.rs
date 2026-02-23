//! Feedback storage operations (ERC-8004 signals).

use super::{
    EdgeRecord, EdgeSource, FeedbackRecord, FeedbackResponseRecord, FeedbackRevocationRecord,
    FeedbackVerifiedRecord, Storage,
};
use alloy::primitives::B256;
use anyhow::{Context, Result};
use sqlx::Row;
use trustnet_core::types::{ContextId, Level, PrincipalId};

fn u256_to_bytes(value: &alloy::primitives::U256) -> [u8; 32] {
    value.to_be_bytes()
}

fn i128_to_bytes(value: i128) -> [u8; 32] {
    let mut out = [0u8; 32];
    let pad = if value < 0 { 0xFF } else { 0x00 };
    out[..16].fill(pad);
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

impl Storage {
    /// Fetch distinct TrustNet context tags observed in ERC-8004 feedback ingestion.
    pub async fn get_registered_context_tags(&self) -> Result<Vec<String>> {
        let mut tags = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT tag1
            FROM feedback_raw
            WHERE tag2 = 'trustnet:v1'
            ORDER BY tag1 ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch registered context tags")?;

        tags.retain(|tag| trustnet_core::is_valid_context_string_v1(tag));
        Ok(tags)
    }

    /// Append a raw ERC-8004 NewFeedback record.
    ///
    /// Returns the inserted row id (or existing id if idempotent).
    pub async fn append_feedback_raw(&self, record: &FeedbackRecord) -> Result<i64> {
        let agent_id_bytes = u256_to_bytes(&record.agent_id);
        let feedback_index_bytes = u256_to_bytes(&record.feedback_index);
        let value_bytes = i128_to_bytes(record.value);

        let tx_hash_bytes = record.tx_hash.as_ref().map(|h| h.as_slice());

        let result = sqlx::query(
            r#"
            INSERT INTO feedback_raw (
                chain_id,
                erc8004_reputation,
                erc8004_identity,
                agent_id,
                client_address,
                feedback_index,
                value_u256,
                value_decimals,
                tag1,
                tag2,
                endpoint,
                feedback_uri,
                feedback_hash,
                subject_id,
                observed_at_u64,
                block_number,
                tx_index,
                log_index,
                tx_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chain_id, tx_hash, log_index) DO NOTHING
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(record.erc8004_reputation.as_slice())
        .bind(record.erc8004_identity.as_ref().map(|v| v.as_slice()))
        .bind(agent_id_bytes.as_slice())
        .bind(record.client_address.as_slice())
        .bind(feedback_index_bytes.as_slice())
        .bind(value_bytes.as_slice())
        .bind(record.value_decimals as i64)
        .bind(&record.tag1)
        .bind(&record.tag2)
        .bind(&record.endpoint)
        .bind(record.feedback_uri.as_deref())
        .bind(record.feedback_hash.as_slice())
        .bind(record.subject_id.as_ref().map(|s| s.as_bytes().as_slice()))
        .bind(record.observed_at_u64 as i64)
        .bind(record.block_number.map(|v| v as i64))
        .bind(record.tx_index.map(|v| v as i64))
        .bind(record.log_index.map(|v| v as i64))
        .bind(tx_hash_bytes)
        .execute(&self.pool)
        .await
        .context("Failed to append feedback_raw")?;

        if result.rows_affected() > 0 {
            return Ok(result.last_insert_rowid());
        }

        let Some(tx_hash) = record.tx_hash else {
            anyhow::bail!("feedback_raw insert ignored without tx_hash");
        };
        let Some(log_index) = record.log_index else {
            anyhow::bail!("feedback_raw insert ignored without log_index");
        };

        let id: i64 = sqlx::query_scalar(
            r#"
            SELECT id
            FROM feedback_raw
            WHERE chain_id = ?
              AND tx_hash = ?
              AND log_index = ?
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(tx_hash.as_slice())
        .bind(log_index as i64)
        .fetch_one(&self.pool)
        .await
        .context("Failed to fetch existing feedback_raw id")?;

        Ok(id)
    }

    /// Append a raw ERC-8004 FeedbackRevoked record.
    ///
    /// Returns the inserted row id (or existing id if idempotent).
    pub async fn append_feedback_revocation_raw(
        &self,
        record: &FeedbackRevocationRecord,
    ) -> Result<i64> {
        let agent_id_bytes = u256_to_bytes(&record.agent_id);
        let feedback_index_bytes = u256_to_bytes(&record.feedback_index);
        let tx_hash_bytes = record.tx_hash.as_ref().map(|h| h.as_slice());

        let result = sqlx::query(
            r#"
            INSERT INTO feedback_revocations_raw (
                chain_id,
                erc8004_reputation,
                agent_id,
                client_address,
                feedback_index,
                observed_at_u64,
                block_number,
                tx_index,
                log_index,
                tx_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chain_id, tx_hash, log_index) DO NOTHING
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(record.erc8004_reputation.as_slice())
        .bind(agent_id_bytes.as_slice())
        .bind(record.client_address.as_slice())
        .bind(feedback_index_bytes.as_slice())
        .bind(record.observed_at_u64 as i64)
        .bind(record.block_number.map(|v| v as i64))
        .bind(record.tx_index.map(|v| v as i64))
        .bind(record.log_index.map(|v| v as i64))
        .bind(tx_hash_bytes)
        .execute(&self.pool)
        .await
        .context("Failed to append feedback_revocations_raw")?;

        if result.rows_affected() > 0 {
            return Ok(result.last_insert_rowid());
        }

        let Some(tx_hash) = record.tx_hash else {
            anyhow::bail!("feedback_revocations_raw insert ignored without tx_hash");
        };
        let Some(log_index) = record.log_index else {
            anyhow::bail!("feedback_revocations_raw insert ignored without log_index");
        };

        let id: i64 = sqlx::query_scalar(
            r#"
            SELECT id
            FROM feedback_revocations_raw
            WHERE chain_id = ?
              AND tx_hash = ?
              AND log_index = ?
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(tx_hash.as_slice())
        .bind(log_index as i64)
        .fetch_one(&self.pool)
        .await
        .context("Failed to fetch existing feedback_revocations_raw id")?;

        Ok(id)
    }

    /// Recompute affected latest edges after processing a feedback revocation.
    ///
    /// Returns the number of edge keys that were recomputed.
    pub async fn apply_feedback_revocation(
        &self,
        chain_id: u64,
        agent_id: &alloy::primitives::U256,
        client_address: &alloy::primitives::Address,
        feedback_index: &alloy::primitives::U256,
    ) -> Result<u64> {
        let agent_id_bytes = u256_to_bytes(agent_id);
        let feedback_index_bytes = u256_to_bytes(feedback_index);

        let affected_keys = sqlx::query(
            r#"
            SELECT DISTINCT e.rater_pid, e.target_pid, e.context_id
            FROM feedback_raw f
            JOIN edges_raw e
              ON e.source = 'erc8004'
             AND e.chain_id = f.chain_id
             AND e.block_number = f.block_number
             AND e.tx_index = f.tx_index
             AND e.log_index = f.log_index
            WHERE f.chain_id = ?
              AND f.agent_id = ?
              AND f.client_address = ?
              AND f.feedback_index = ?
            "#,
        )
        .bind(chain_id as i64)
        .bind(agent_id_bytes.as_slice())
        .bind(client_address.as_slice())
        .bind(feedback_index_bytes.as_slice())
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch affected edge keys for feedback revocation")?;

        let affected_key_count = affected_keys.len() as u64;

        for row in affected_keys {
            let rater_pid: Vec<u8> = row.get("rater_pid");
            let target_pid: Vec<u8> = row.get("target_pid");
            let context_id: Vec<u8> = row.get("context_id");

            let next_edge = self
                .latest_effective_edge_for_key(&rater_pid, &target_pid, &context_id)
                .await?;
            self.replace_edge_latest_for_key(
                &rater_pid,
                &target_pid,
                &context_id,
                next_edge.as_ref(),
            )
            .await?;
        }

        Ok(affected_key_count)
    }

    /// Append a raw ERC-8004 ResponseAppended record.
    ///
    /// Returns the inserted row id (or existing id if idempotent).
    pub async fn append_feedback_response_raw(
        &self,
        record: &FeedbackResponseRecord,
    ) -> Result<i64> {
        let agent_id_bytes = u256_to_bytes(&record.agent_id);
        let feedback_index_bytes = u256_to_bytes(&record.feedback_index);

        let tx_hash_bytes = record.tx_hash.as_ref().map(|h| h.as_slice());

        let result = sqlx::query(
            r#"
            INSERT INTO feedback_responses_raw (
                chain_id,
                erc8004_reputation,
                agent_id,
                client_address,
                feedback_index,
                responder,
                response_uri,
                response_hash,
                observed_at_u64,
                block_number,
                tx_index,
                log_index,
                tx_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(chain_id, tx_hash, log_index) DO NOTHING
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(record.erc8004_reputation.as_slice())
        .bind(agent_id_bytes.as_slice())
        .bind(record.client_address.as_slice())
        .bind(feedback_index_bytes.as_slice())
        .bind(record.responder.as_slice())
        .bind(record.response_uri.as_deref())
        .bind(record.response_hash.as_slice())
        .bind(record.observed_at_u64 as i64)
        .bind(record.block_number.map(|v| v as i64))
        .bind(record.tx_index.map(|v| v as i64))
        .bind(record.log_index.map(|v| v as i64))
        .bind(tx_hash_bytes)
        .execute(&self.pool)
        .await
        .context("Failed to append feedback_responses_raw")?;

        if result.rows_affected() > 0 {
            return Ok(result.last_insert_rowid());
        }

        let Some(tx_hash) = record.tx_hash else {
            anyhow::bail!("feedback_responses_raw insert ignored without tx_hash");
        };
        let Some(log_index) = record.log_index else {
            anyhow::bail!("feedback_responses_raw insert ignored without log_index");
        };

        let id: i64 = sqlx::query_scalar(
            r#"
            SELECT id
            FROM feedback_responses_raw
            WHERE chain_id = ?
              AND tx_hash = ?
              AND log_index = ?
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(tx_hash.as_slice())
        .bind(log_index as i64)
        .fetch_one(&self.pool)
        .await
        .context("Failed to fetch existing feedback_responses_raw id")?;

        Ok(id)
    }

    /// Append a verified feedback stamp.
    ///
    /// Returns the inserted row id (or existing id if idempotent).
    pub async fn append_feedback_verified(&self, record: &FeedbackVerifiedRecord) -> Result<i64> {
        let agent_id_bytes = u256_to_bytes(&record.agent_id);
        let feedback_index_bytes = u256_to_bytes(&record.feedback_index);

        let result = sqlx::query(
            r#"
            INSERT INTO feedback_verified (
                chain_id,
                erc8004_reputation,
                agent_id,
                client_address,
                feedback_index,
                responder,
                response_hash,
                observed_at_u64
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(record.erc8004_reputation.as_slice())
        .bind(agent_id_bytes.as_slice())
        .bind(record.client_address.as_slice())
        .bind(feedback_index_bytes.as_slice())
        .bind(record.responder.as_slice())
        .bind(record.response_hash.as_slice())
        .bind(record.observed_at_u64 as i64)
        .execute(&self.pool)
        .await
        .context("Failed to append feedback_verified")?;

        if result.rows_affected() > 0 {
            return Ok(result.last_insert_rowid());
        }

        let id: i64 = sqlx::query_scalar(
            r#"
            SELECT id
            FROM feedback_verified
            WHERE chain_id = ?
              AND agent_id = ?
              AND client_address = ?
              AND feedback_index = ?
              AND responder = ?
              AND response_hash = ?
            "#,
        )
        .bind(record.chain_id as i64)
        .bind(agent_id_bytes.as_slice())
        .bind(record.client_address.as_slice())
        .bind(feedback_index_bytes.as_slice())
        .bind(record.responder.as_slice())
        .bind(record.response_hash.as_slice())
        .fetch_one(&self.pool)
        .await
        .context("Failed to fetch existing feedback_verified id")?;

        Ok(id)
    }

    async fn latest_effective_edge_for_key(
        &self,
        rater_pid: &[u8],
        target_pid: &[u8],
        context_id: &[u8],
    ) -> Result<Option<EdgeRecord>> {
        let row = sqlx::query(
            r#"
            SELECT
                e.rater_pid,
                e.target_pid,
                e.context_id,
                e.level_i8,
                e.updated_at_u64,
                e.evidence_hash,
                e.evidence_uri,
                e.source,
                e.observed_at_u64,
                e.subject_id,
                e.chain_id,
                e.block_number,
                e.tx_index,
                e.log_index,
                e.tx_hash,
                e.server_seq
            FROM edges_raw e
            LEFT JOIN feedback_raw f
              ON e.source = 'erc8004'
             AND f.chain_id = e.chain_id
             AND f.block_number = e.block_number
             AND f.tx_index = e.tx_index
             AND f.log_index = e.log_index
            LEFT JOIN feedback_revocations_raw r
              ON f.id IS NOT NULL
             AND r.chain_id = f.chain_id
             AND r.agent_id = f.agent_id
             AND r.client_address = f.client_address
             AND r.feedback_index = f.feedback_index
            WHERE e.rater_pid = ?
              AND e.target_pid = ?
              AND e.context_id = ?
              AND (
                    e.source <> 'erc8004'
                 OR r.id IS NULL
              )
            ORDER BY
                COALESCE(e.block_number, 0) DESC,
                COALESCE(e.tx_index, 0) DESC,
                COALESCE(e.log_index, 0) DESC,
                e.tx_hash DESC,
                e.id DESC
            LIMIT 1
            "#,
        )
        .bind(rater_pid)
        .bind(target_pid)
        .bind(context_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query latest effective edge for key")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let rater_pid_raw: Vec<u8> = row.get("rater_pid");
        let target_pid_raw: Vec<u8> = row.get("target_pid");
        let context_id_raw: Vec<u8> = row.get("context_id");
        let level_i8: i32 = row.get("level_i8");
        let updated_at_u64: i64 = row.get("updated_at_u64");
        let evidence_hash_raw: Vec<u8> = row.get("evidence_hash");
        let evidence_uri: Option<String> = row.try_get("evidence_uri").unwrap_or(None);
        let source_raw: String = row.get("source");
        let observed_at_u64: i64 = row.try_get("observed_at_u64").unwrap_or(0i64);
        let subject_id_raw: Option<Vec<u8>> = row.try_get("subject_id").unwrap_or(None);
        let chain_id: Option<i64> = row.try_get("chain_id").ok();
        let block_number: Option<i64> = row.try_get("block_number").ok();
        let tx_index: Option<i64> = row.try_get("tx_index").ok();
        let log_index: Option<i64> = row.try_get("log_index").ok();
        let tx_hash_raw: Option<Vec<u8>> = row.try_get("tx_hash").ok();
        let server_seq: Option<i64> = row.try_get("server_seq").ok();

        let source = source_raw
            .parse::<EdgeSource>()
            .map_err(|e| anyhow::anyhow!("Invalid edge source in edges_raw: {}", e))?;
        let level = Level::new(level_i8 as i8)?;

        let rater = PrincipalId::from(<[u8; 32]>::try_from(rater_pid_raw.as_slice())?);
        let target = PrincipalId::from(<[u8; 32]>::try_from(target_pid_raw.as_slice())?);
        let context_id = ContextId::from(<[u8; 32]>::try_from(context_id_raw.as_slice())?);

        let evidence_hash = if evidence_hash_raw.len() == 32 {
            B256::from_slice(&evidence_hash_raw)
        } else {
            B256::ZERO
        };
        let subject_id = match subject_id_raw {
            Some(bytes) if bytes.len() == 32 => Some(trustnet_core::types::SubjectId::from(
                <[u8; 32]>::try_from(bytes.as_slice())?,
            )),
            _ => None,
        };
        let tx_hash = tx_hash_raw
            .as_ref()
            .and_then(|bytes| (bytes.len() == 32).then(|| B256::from_slice(bytes)));

        Ok(Some(EdgeRecord {
            rater,
            target,
            subject_id,
            context_id,
            level,
            updated_at_u64: updated_at_u64.max(0) as u64,
            evidence_hash,
            evidence_uri,
            observed_at_u64: observed_at_u64.max(0) as u64,
            source,
            chain_id: chain_id.map(|v| v as u64),
            block_number: block_number.map(|v| v as u64),
            tx_index: tx_index.map(|v| v as u64),
            log_index: log_index.map(|v| v as u64),
            tx_hash,
            server_seq: server_seq.map(|v| v as u64),
        }))
    }

    async fn replace_edge_latest_for_key(
        &self,
        rater_pid: &[u8],
        target_pid: &[u8],
        context_id: &[u8],
        edge: Option<&EdgeRecord>,
    ) -> Result<()> {
        if let Some(edge) = edge {
            sqlx::query(
                r#"
                INSERT INTO edges_latest (
                    rater_pid, target_pid, context_id,
                    level_i8, updated_at_u64, evidence_hash, evidence_uri, source,
                    observed_at_u64, subject_id,
                    chain_id, block_number, tx_index, log_index, tx_hash,
                    server_seq
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    server_seq = excluded.server_seq
                "#,
            )
            .bind(edge.rater.as_bytes().as_slice())
            .bind(edge.target.as_bytes().as_slice())
            .bind(edge.context_id.as_bytes().as_slice())
            .bind(edge.level.value() as i32)
            .bind(edge.updated_at_u64 as i64)
            .bind(edge.evidence_hash.as_slice())
            .bind(edge.evidence_uri.as_deref())
            .bind(edge.source.as_str())
            .bind(edge.observed_at_u64 as i64)
            .bind(edge.subject_id.as_ref().map(|id| id.as_bytes().as_slice()))
            .bind(edge.chain_id.map(|v| v as i64))
            .bind(edge.block_number.map(|v| v as i64))
            .bind(edge.tx_index.map(|v| v as i64))
            .bind(edge.log_index.map(|v| v as i64))
            .bind(edge.tx_hash.as_ref().map(|h| h.as_slice()))
            .bind(edge.server_seq.map(|v| v as i64))
            .execute(&self.pool)
            .await
            .context("Failed to replace edges_latest row after feedback revocation")?;
        } else {
            sqlx::query(
                "DELETE FROM edges_latest WHERE rater_pid = ? AND target_pid = ? AND context_id = ?",
            )
            .bind(rater_pid)
            .bind(target_pid)
            .bind(context_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete edges_latest row after feedback revocation")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordering::observed_at_for_chain;
    use crate::storage::{EdgeRecord, EdgeSource, Storage};
    use alloy::primitives::{Address, B256, U256};
    use tempfile::NamedTempFile;
    use trustnet_core::types::{ContextId, Level, PrincipalId};

    async fn setup_storage() -> (Storage, NamedTempFile) {
        let temp_db = NamedTempFile::new().unwrap();
        let storage = Storage::new_with_path(temp_db.path(), None, None)
            .await
            .unwrap();
        storage.run_migrations().await.unwrap();
        (storage, temp_db)
    }

    #[tokio::test]
    async fn test_append_feedback_raw_idempotent() {
        let (storage, _tmp) = setup_storage().await;

        let record = FeedbackRecord {
            chain_id: 1,
            erc8004_reputation: Address::repeat_byte(0x11),
            erc8004_identity: None,
            agent_id: U256::from(123u64),
            client_address: Address::repeat_byte(0x22),
            feedback_index: U256::from(1u64),
            value: 100,
            value_decimals: 0,
            tag1: "trustnet:ctx:code-exec:v1".to_string(),
            tag2: "trustnet:v1".to_string(),
            endpoint: "trustnet".to_string(),
            feedback_uri: None,
            feedback_hash: B256::repeat_byte(0x33),
            subject_id: None,
            observed_at_u64: 42,
            block_number: Some(100),
            tx_index: Some(1),
            log_index: Some(0),
            tx_hash: Some(B256::repeat_byte(0xaa)),
        };

        let id1 = storage.append_feedback_raw(&record).await.unwrap();
        let id2 = storage.append_feedback_raw(&record).await.unwrap();

        assert_eq!(id1, id2);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feedback_raw")
            .fetch_one(storage.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_append_feedback_response_raw_idempotent() {
        let (storage, _tmp) = setup_storage().await;

        let record = FeedbackResponseRecord {
            chain_id: 1,
            erc8004_reputation: Address::repeat_byte(0x11),
            agent_id: U256::from(123u64),
            client_address: Address::repeat_byte(0x22),
            feedback_index: U256::from(1u64),
            responder: Address::repeat_byte(0x44),
            response_uri: Some("ipfs://response".to_string()),
            response_hash: B256::repeat_byte(0x55),
            observed_at_u64: 43,
            block_number: Some(101),
            tx_index: Some(2),
            log_index: Some(1),
            tx_hash: Some(B256::repeat_byte(0xbb)),
        };

        let id1 = storage.append_feedback_response_raw(&record).await.unwrap();
        let id2 = storage.append_feedback_response_raw(&record).await.unwrap();

        assert_eq!(id1, id2);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feedback_responses_raw")
            .fetch_one(storage.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_append_feedback_verified_idempotent() {
        let (storage, _tmp) = setup_storage().await;

        let record = FeedbackVerifiedRecord {
            chain_id: 1,
            erc8004_reputation: Address::repeat_byte(0x11),
            agent_id: U256::from(42u64),
            client_address: Address::repeat_byte(0x22),
            feedback_index: U256::from(7u64),
            responder: Address::repeat_byte(0x33),
            response_hash: B256::repeat_byte(0x44),
            observed_at_u64: 99,
        };

        let id1 = storage.append_feedback_verified(&record).await.unwrap();
        let id2 = storage.append_feedback_verified(&record).await.unwrap();

        assert_eq!(id1, id2);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feedback_verified")
            .fetch_one(storage.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_append_feedback_revocation_raw_idempotent() {
        let (storage, _tmp) = setup_storage().await;

        let record = FeedbackRevocationRecord {
            chain_id: 1,
            erc8004_reputation: Address::repeat_byte(0x11),
            agent_id: U256::from(42u64),
            client_address: Address::repeat_byte(0x22),
            feedback_index: U256::from(7u64),
            observed_at_u64: 50,
            block_number: Some(100),
            tx_index: Some(1),
            log_index: Some(0),
            tx_hash: Some(B256::repeat_byte(0xaa)),
        };

        let id1 = storage
            .append_feedback_revocation_raw(&record)
            .await
            .unwrap();
        let id2 = storage
            .append_feedback_revocation_raw(&record)
            .await
            .unwrap();
        assert_eq!(id1, id2);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feedback_revocations_raw")
            .fetch_one(storage.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_apply_feedback_revocation_rewinds_latest_erc8004_edge() {
        let (storage, _tmp) = setup_storage().await;

        let chain_id = 1u64;
        let reputation = Address::repeat_byte(0x11);
        let agent_id = U256::from(123u64);
        let client = Address::repeat_byte(0x22);
        let context_id = ContextId::from(trustnet_core::CTX_CODE_EXEC);
        let rater = PrincipalId::from_evm_address(client);
        let target = PrincipalId::from([0x33u8; 32]);

        let fb1 = FeedbackRecord {
            chain_id,
            erc8004_reputation: reputation,
            erc8004_identity: None,
            agent_id,
            client_address: client,
            feedback_index: U256::from(1u64),
            value: 75,
            value_decimals: 0,
            tag1: "trustnet:ctx:code-exec:v1".to_string(),
            tag2: "trustnet:v1".to_string(),
            endpoint: "trustnet".to_string(),
            feedback_uri: Some("ipfs://fb1".to_string()),
            feedback_hash: B256::repeat_byte(0x44),
            subject_id: None,
            observed_at_u64: observed_at_for_chain(100, 1, 0),
            block_number: Some(100),
            tx_index: Some(1),
            log_index: Some(0),
            tx_hash: Some(B256::repeat_byte(0xa1)),
        };
        storage.append_feedback_raw(&fb1).await.unwrap();

        let edge1 = EdgeRecord {
            rater,
            target,
            subject_id: None,
            context_id,
            level: Level::positive(),
            updated_at_u64: 1000,
            evidence_hash: fb1.feedback_hash,
            evidence_uri: fb1.feedback_uri.clone(),
            observed_at_u64: fb1.observed_at_u64,
            source: EdgeSource::Erc8004,
            chain_id: Some(chain_id),
            block_number: fb1.block_number,
            tx_index: fb1.tx_index,
            log_index: fb1.log_index,
            tx_hash: fb1.tx_hash,
            server_seq: None,
        };
        storage.append_edge_raw(&edge1).await.unwrap();
        storage.upsert_edge_latest(&edge1).await.unwrap();

        let fb2 = FeedbackRecord {
            chain_id,
            erc8004_reputation: reputation,
            erc8004_identity: None,
            agent_id,
            client_address: client,
            feedback_index: U256::from(2u64),
            value: 95,
            value_decimals: 0,
            tag1: "trustnet:ctx:code-exec:v1".to_string(),
            tag2: "trustnet:v1".to_string(),
            endpoint: "trustnet".to_string(),
            feedback_uri: Some("ipfs://fb2".to_string()),
            feedback_hash: B256::repeat_byte(0x55),
            subject_id: None,
            observed_at_u64: observed_at_for_chain(101, 1, 0),
            block_number: Some(101),
            tx_index: Some(1),
            log_index: Some(0),
            tx_hash: Some(B256::repeat_byte(0xa2)),
        };
        storage.append_feedback_raw(&fb2).await.unwrap();

        let edge2 = EdgeRecord {
            rater,
            target,
            subject_id: None,
            context_id,
            level: Level::strong_positive(),
            updated_at_u64: 1010,
            evidence_hash: fb2.feedback_hash,
            evidence_uri: fb2.feedback_uri.clone(),
            observed_at_u64: fb2.observed_at_u64,
            source: EdgeSource::Erc8004,
            chain_id: Some(chain_id),
            block_number: fb2.block_number,
            tx_index: fb2.tx_index,
            log_index: fb2.log_index,
            tx_hash: fb2.tx_hash,
            server_seq: None,
        };
        storage.append_edge_raw(&edge2).await.unwrap();
        storage.upsert_edge_latest(&edge2).await.unwrap();

        let before = storage
            .get_edge_latest(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.level, Level::strong_positive());

        let revocation = FeedbackRevocationRecord {
            chain_id,
            erc8004_reputation: reputation,
            agent_id,
            client_address: client,
            feedback_index: U256::from(2u64),
            observed_at_u64: observed_at_for_chain(102, 1, 0),
            block_number: Some(102),
            tx_index: Some(1),
            log_index: Some(0),
            tx_hash: Some(B256::repeat_byte(0xf1)),
        };
        storage
            .append_feedback_revocation_raw(&revocation)
            .await
            .unwrap();

        let affected = storage
            .apply_feedback_revocation(chain_id, &agent_id, &client, &U256::from(2u64))
            .await
            .unwrap();
        assert_eq!(affected, 1);

        let after = storage
            .get_edge_latest(&rater, &target, &context_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.level, Level::positive());
        assert_eq!(after.evidence_hash, B256::repeat_byte(0x44));
    }
}
