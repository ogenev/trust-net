//! Database query helpers for the TrustNet API (spec v1.1).

use sqlx::SqlitePool;
use trustnet_core::Address;

/// Latest epoch record.
#[derive(Debug, sqlx::FromRow)]
pub struct DbEpoch {
    /// Epoch number.
    pub epoch: i64,
    /// Graph root bytes (32 bytes).
    pub graph_root: Vec<u8>,
    /// Edge count included in the epoch.
    pub edge_count: i64,
    /// Canonical manifest JSON (RFC 8785 JCS), if present.
    pub manifest_json: Option<String>,
    /// Public URI for the manifest, if present.
    pub manifest_uri: Option<String>,
    /// `keccak256(canonical_manifest_json_bytes)`, if present.
    pub manifest_hash: Option<Vec<u8>>,
    /// Publisher signature bytes (typically 65 bytes), if present.
    pub publisher_sig: Option<Vec<u8>>,
    /// Unix timestamp (seconds) for when the root was built, if present.
    pub created_at_u64: Option<i64>,
}

/// Row from `edges_latest` used to reconstruct an epoch tree.
#[derive(Debug, sqlx::FromRow)]
pub struct DbEdgeLatest {
    /// Rater principal id bytes (32 bytes).
    pub rater_pid: Vec<u8>,
    /// Target principal id bytes (32 bytes).
    pub target_pid: Vec<u8>,
    /// Context id bytes (32 bytes).
    pub context_id: Vec<u8>,
    /// Trust level as i8 stored in an i32 column.
    pub level_i8: i32,
    /// Unix timestamp (seconds) for when this edge was observed/updated.
    pub updated_at_u64: i64,
    /// Evidence hash bytes (32 bytes).
    pub evidence_hash: Vec<u8>,
}

/// Detailed edge row for explainability metadata.
#[derive(Debug, sqlx::FromRow)]
pub struct DbEdgeLatestDetail {
    /// Trust level as i8 stored in an i32 column.
    pub level_i8: i32,
    /// Unix timestamp (seconds) for when this edge was observed/updated.
    pub updated_at_u64: i64,
    /// Evidence hash bytes (32 bytes).
    pub evidence_hash: Vec<u8>,
    /// Optional evidence URI.
    pub evidence_uri: Option<String>,
    /// Source string (`trust_graph` | `erc8004` | `private_log`).
    pub source: String,
    /// Chain coordinates (nullable in server mode).
    pub block_number: Option<i64>,
    /// Transaction index within the block.
    pub tx_index: Option<i64>,
    /// Log index within the transaction.
    pub log_index: Option<i64>,
    /// Transaction hash bytes (32 bytes).
    pub tx_hash: Option<Vec<u8>>,
}

/// Get the latest published epoch.
pub async fn get_latest_epoch(pool: &SqlitePool) -> anyhow::Result<Option<DbEpoch>> {
    let epoch = sqlx::query_as::<_, DbEpoch>(
        r#"
        SELECT
            epoch,
            graph_root,
            edge_count,
            manifest_json,
            manifest_uri,
            manifest_hash,
            publisher_sig,
            created_at_u64
        FROM epochs
        ORDER BY epoch DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    Ok(epoch)
}

/// Fetch all latest-wins edges for SMM reconstruction.
pub async fn get_all_edges_latest(pool: &SqlitePool) -> anyhow::Result<Vec<DbEdgeLatest>> {
    let rows = sqlx::query_as::<_, DbEdgeLatest>(
        r#"
        SELECT
            rater_pid,
            target_pid,
            context_id,
            level_i8,
            updated_at_u64,
            evidence_hash
        FROM edges_latest
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Fetch one latest-wins edge with explainability metadata.
pub async fn get_edge_latest_detail(
    pool: &SqlitePool,
    rater_pid: &[u8],
    target_pid: &[u8],
    context_id: &[u8],
) -> anyhow::Result<Option<DbEdgeLatestDetail>> {
    let row = sqlx::query_as::<_, DbEdgeLatestDetail>(
        r#"
        SELECT
            level_i8,
            updated_at_u64,
            evidence_hash,
            evidence_uri,
            source,
            block_number,
            tx_index,
            log_index,
            tx_hash
        FROM edges_latest
        WHERE rater_pid = ?
          AND target_pid = ?
          AND context_id = ?
        LIMIT 1
        "#,
    )
    .bind(rater_pid)
    .bind(target_pid)
    .bind(context_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Candidate endorsers `E` for a 2-hop decision `(D -> E -> T)` in a given context.
///
/// This query is a **hint**; the API must still verify membership proofs against the published
/// epoch root before using any candidate.
pub async fn get_candidate_endorsers(
    pool: &SqlitePool,
    decider_pid: &[u8],
    target_pid: &[u8],
    context_id: &[u8],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let rows = sqlx::query_scalar::<_, Vec<u8>>(
        r#"
        SELECT e1.target_pid AS endorser_pid
        FROM edges_latest e1
        JOIN edges_latest e2
          ON e1.target_pid = e2.rater_pid
        WHERE e1.rater_pid = ?
          AND e2.target_pid = ?
          AND e1.context_id = ?
          AND e2.context_id = ?
        ORDER BY endorser_pid ASC
        "#,
    )
    .bind(decider_pid)
    .bind(target_pid)
    .bind(context_id)
    .bind(context_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Check if an evidence hash corresponds to feedback with a verified stamp.
pub async fn has_verified_feedback_for_hash(
    pool: &SqlitePool,
    evidence_hash: &[u8],
    trusted_responders: &[Address],
) -> anyhow::Result<bool> {
    let mut query = String::from(
        r#"
        SELECT 1
        FROM feedback_raw f
        JOIN feedback_verified v
          ON v.chain_id = f.chain_id
         AND v.agent_id = f.agent_id
         AND v.client_address = f.client_address
         AND v.feedback_index = f.feedback_index
        WHERE f.feedback_hash = ?
        "#,
    );

    if !trusted_responders.is_empty() {
        query.push_str(" AND v.responder IN (");
        query.push_str(
            &std::iter::repeat_n("?", trusted_responders.len())
                .collect::<Vec<_>>()
                .join(","),
        );
        query.push(')');
    }

    query.push_str(" LIMIT 1");

    let mut stmt = sqlx::query_scalar::<_, i64>(&query).bind(evidence_hash);
    for responder in trusted_responders {
        stmt = stmt.bind(responder.as_slice());
    }

    let row = stmt.fetch_optional(pool).await?;
    Ok(row.is_some())
}
