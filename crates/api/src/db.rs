//! Database query functions for the API.

use sqlx::{Row, SqlitePool};
use trustnet_core::{types::Level, Address, B256};

/// Latest epoch record from the database.
#[derive(Debug, sqlx::FromRow)]
pub struct DbEpoch {
    /// Epoch number
    pub epoch: i64,
    /// Merkle root hash
    pub graph_root: Vec<u8>,
    /// Number of edges in this epoch
    pub edge_count: i64,
}

/// Get the latest published epoch.
pub async fn get_latest_epoch(pool: &SqlitePool) -> anyhow::Result<Option<DbEpoch>> {
    let epoch = sqlx::query_as::<_, DbEpoch>(
        "SELECT epoch, graph_root, edge_count FROM epochs ORDER BY epoch DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    Ok(epoch)
}

/// Get a direct edge rating.
pub async fn get_direct_edge(
    pool: &SqlitePool,
    rater: &Address,
    target: &Address,
    context_id: &B256,
) -> anyhow::Result<Option<Level>> {
    let result: Option<(i32,)> =
        sqlx::query_as("SELECT level FROM edges WHERE rater = ? AND target = ? AND context_id = ?")
            .bind(rater.as_slice())
            .bind(target.as_slice())
            .bind(context_id.as_slice())
            .fetch_optional(pool)
            .await?;

    Ok(result.and_then(|(level,)| Level::new(level as i8).ok()))
}

/// Edge details including metadata.
#[derive(Debug, sqlx::FromRow)]
pub struct EdgeDetails {
    /// Trust level (-2 to +2)
    pub level: i32,
    /// Block number where edge was emitted
    pub block_number: i64,
    /// Transaction hash
    pub tx_hash: Option<Vec<u8>>,
    /// Unix timestamp when ingested
    pub ingested_at: i64,
    /// Source: "trust_graph" or "erc8004"
    pub source: String,
}

/// Edge details for collection endpoint (includes target).
#[derive(Debug, sqlx::FromRow)]
pub struct EdgeDetailsWithTarget {
    /// Target address
    pub target: Vec<u8>,
    /// Trust level (-2 to +2)
    pub level: i32,
    /// Block number where edge was emitted
    pub block_number: i64,
    /// Transaction hash
    pub tx_hash: Option<Vec<u8>>,
    /// Unix timestamp when ingested
    pub ingested_at: i64,
    /// Source: "trust_graph" or "erc8004"
    pub source: String,
}

/// Get edge with full details for rating endpoint.
pub async fn get_edge_details(
    pool: &SqlitePool,
    rater: &Address,
    target: &Address,
    context_id: &B256,
) -> anyhow::Result<Option<EdgeDetails>> {
    let edge = sqlx::query_as::<_, EdgeDetails>(
        "SELECT level, block_number, tx_hash, ingested_at, source FROM edges WHERE rater = ? AND target = ? AND context_id = ?"
    )
    .bind(rater.as_slice())
    .bind(target.as_slice())
    .bind(context_id.as_slice())
    .fetch_optional(pool)
    .await?;

    Ok(edge)
}

/// Two-hop path result.
#[derive(Debug, sqlx::FromRow)]
pub struct TwoHopPath {
    /// The endorser address (intermediate node)
    pub endorser: Vec<u8>,
    /// Trust level from decider to endorser
    pub level1: i32,
    /// Trust level from endorser to target
    pub level2: i32,
}

/// Get all 2-hop paths for score computation, ordered by path quality.
///
/// Returns up to 100 paths ordered by MIN(level1, level2) DESC to ensure
/// we always get the highest-quality paths first.
pub async fn get_two_hop_paths(
    pool: &SqlitePool,
    decider: &Address,
    target: &Address,
    context_id: &B256,
) -> anyhow::Result<Vec<TwoHopPath>> {
    let paths = sqlx::query_as::<_, TwoHopPath>(
        r#"
        SELECT
            e1.target as endorser,
            e1.level as level1,
            e2.level as level2
        FROM edges e1
        JOIN edges e2 ON e1.target = e2.rater
        WHERE e1.rater = ?
          AND e2.target = ?
          AND e1.context_id = ?
          AND e2.context_id = ?
        ORDER BY MIN(e1.level, e2.level) DESC
        LIMIT 100
        "#,
    )
    .bind(decider.as_slice())
    .bind(target.as_slice())
    .bind(context_id.as_slice())
    .bind(context_id.as_slice())
    .fetch_all(pool)
    .await?;

    Ok(paths)
}

/// Get all edges for SMM building.
///
/// Returns all edges as tuples (rater, target, context_id, level) for
/// constructing the Sparse Merkle Map on startup.
pub async fn get_all_edges_for_smm(
    pool: &SqlitePool,
) -> anyhow::Result<Vec<crate::smm_cache::RawEdge>> {
    let rows = sqlx::query("SELECT rater, target, context_id, level FROM edges")
        .fetch_all(pool)
        .await?;

    let edges = rows
        .into_iter()
        .map(|row| {
            crate::smm_cache::RawEdge(
                row.get("rater"),
                row.get("target"),
                row.get("context_id"),
                row.get("level"),
            )
        })
        .collect();

    Ok(edges)
}

/// Get ratings by rater with pagination support.
pub async fn get_ratings_by_rater(
    pool: &SqlitePool,
    rater: &Address,
    context_id: &B256,
    target: Option<&Address>,
    limit: i64,
    cursor: Option<&[u8]>,
) -> anyhow::Result<Vec<EdgeDetailsWithTarget>> {
    // Build query dynamically based on filters
    let mut query = String::from(
        "SELECT target, level, block_number, tx_hash, ingested_at, source FROM edges WHERE rater = ? AND context_id = ?"
    );

    // Add target filter if provided
    if target.is_some() {
        query.push_str(" AND target = ?");
    }

    // Add cursor for pagination (target > cursor)
    if cursor.is_some() {
        query.push_str(" AND target > ?");
    }

    query.push_str(" ORDER BY target ASC LIMIT ?");

    // Start building the query
    let mut q = sqlx::query_as::<_, EdgeDetailsWithTarget>(&query)
        .bind(rater.as_slice())
        .bind(context_id.as_slice());

    // Add target binding if provided
    if let Some(t) = target {
        q = q.bind(t.as_slice());
    }

    // Add cursor binding if provided
    if let Some(c) = cursor {
        q = q.bind(c);
    }

    // Add limit
    q = q.bind(limit);

    let edges = q.fetch_all(pool).await?;
    Ok(edges)
}
