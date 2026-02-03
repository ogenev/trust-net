//! Feedback storage operations (ERC-8004 signals).

use super::{FeedbackRecord, FeedbackResponseRecord, Storage};
use anyhow::{Context, Result};

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use alloy::primitives::{Address, B256, U256};
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
            tag1: "trustnet:ctx:payments:v1".to_string(),
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
}
