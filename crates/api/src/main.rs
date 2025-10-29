use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use serde::Serialize;
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tower_http::cors::CorsLayer;
use trustnet_core::{
    compute_edge_key, Address, ContextId, B256, CTX_CODE_EXEC, CTX_DEFI_EXEC, CTX_GLOBAL,
    CTX_PAYMENTS, CTX_WRITES,
};

mod db;
mod smm_cache;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    smm_cache: Arc<smm_cache::SmmCache>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Get database URL from environment or use default
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://trustnet.db".to_string());

    // Configure connection options with read-only mode for ALL connections in pool
    let connect_options = SqliteConnectOptions::from_str(&database_url)?
        .read_only(true)
        .create_if_missing(false); // Fail if database doesn't exist

    // Create connection pool with read-only connections
    let db = SqlitePool::connect_with(connect_options).await?;

    // Initialize SMM cache from the latest published epoch (if available)
    let cache_dir = std::env::var("SMM_CACHE_DIR").unwrap_or_else(|_| "./smm_cache".to_string());
    let smm_cache = Arc::new(smm_cache::SmmCache::new(&cache_dir));

    // Check if there's a published epoch yet
    match db::get_latest_epoch(&db).await? {
        Some(latest_epoch) => {
            // Database has epochs - build cache
            println!("🔨 Building Sparse Merkle Map from database...");
            let published_root = B256::from_slice(&latest_epoch.graph_root);

            let edges = db::get_all_edges_for_smm(&db).await?;
            let success = smm_cache
                .try_rebuild_for_epoch(edges, published_root)
                .await?;

            if success {
                println!(
                    "✅ SMM built for epoch {} with root: 0x{}",
                    latest_epoch.epoch,
                    hex::encode(published_root)
                );
            } else {
                println!(
                    "⚠️  Warning: Database edges are newer than published epoch {}. Proofs will be unavailable until next epoch is published.",
                    latest_epoch.epoch
                );
            }
        }
        None => {
            // No epochs yet - this is normal for fresh databases
            println!("ℹ️  No epochs found in database. Cache will remain empty until indexer publishes first epoch.");
            println!("   /v1/root will return 404 and /v1/proof will return 503 until then.");
        }
    }

    let state = AppState { db, smm_cache };

    // Build router with Phase 2 + Phase 3 + Phase 4 endpoints
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/root", get(get_root))
        .route("/v1/context", get(get_contexts))
        .route("/v1/rating/:rater/:target", get(get_rating))
        .route("/v1/score/:decider/:target", get(get_score))
        .route("/v1/ratings", get(get_ratings))
        .route("/v1/proof/:rater/:target", get(get_proof))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("🚀 TrustNet API server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// Health check endpoint
async fn health(State(_state): State<AppState>) -> &'static str {
    "OK"
}

// Root endpoint - returns latest Merkle root and epoch
#[derive(Serialize)]
struct RootResponse {
    epoch: u64,
    root: String,
    edge_count: u64,
}

async fn get_root(
    State(state): State<AppState>,
) -> Result<Json<RootResponse>, (StatusCode, Json<ErrorResponse>)> {
    let epoch = db::get_latest_epoch(&state.db)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found("No epochs found"))?;

    // Check if cache is stale and trigger rebuild if needed
    // This ensures the proof cache stays fresh for common access patterns
    let published_root = B256::from_slice(&epoch.graph_root);
    if state.smm_cache.is_stale(published_root).await {
        // Rebuild cache in background (don't block response)
        let cache = state.smm_cache.clone();
        let db = state.db.clone();
        tokio::spawn(async move {
            if let Ok(edges) = db::get_all_edges_for_smm(&db).await {
                // try_rebuild_for_epoch only updates cache if root matches published epoch
                // If it returns false, we're in the window between ingestion and publication
                let _ = cache.try_rebuild_for_epoch(edges, published_root).await;
            }
        });
    }

    Ok(Json(RootResponse {
        epoch: epoch.epoch as u64,
        root: format!("0x{}", hex::encode(&epoch.graph_root)),
        edge_count: epoch.edge_count as u64,
    }))
}

// Context endpoint - returns canonical contexts
#[derive(Serialize)]
struct ContextResponse {
    contexts: Vec<ContextInfo>,
}

#[derive(Serialize)]
struct ContextInfo {
    id: String,
    name: String,
    description: String,
}

async fn get_contexts() -> Json<ContextResponse> {
    Json(ContextResponse {
        contexts: vec![
            ContextInfo {
                id: format!("0x{}", hex::encode(CTX_GLOBAL)),
                name: "GLOBAL".to_string(),
                description: "Global context - applies to all capabilities".to_string(),
            },
            ContextInfo {
                id: format!("0x{}", hex::encode(CTX_PAYMENTS)),
                name: "PAYMENTS".to_string(),
                description: "Payments context - for payment-related operations".to_string(),
            },
            ContextInfo {
                id: format!("0x{}", hex::encode(CTX_CODE_EXEC)),
                name: "CODE_EXEC".to_string(),
                description: "Code execution context - for code execution capabilities".to_string(),
            },
            ContextInfo {
                id: format!("0x{}", hex::encode(CTX_WRITES)),
                name: "WRITES".to_string(),
                description: "Writes context - for write/modification operations".to_string(),
            },
            ContextInfo {
                id: format!("0x{}", hex::encode(CTX_DEFI_EXEC)),
                name: "DEFI_EXEC".to_string(),
                description: "DeFi execution context - for DeFi protocol interactions".to_string(),
            },
        ],
    })
}

// Rating endpoint - returns direct rating from rater to target
#[derive(Serialize)]
struct RatingResponse {
    level: i8,
    score: i8,
    source: String,
    block_number: u64,
    tx_hash: Option<String>,
    timestamp: u64,
    exists: bool,
}

use axum::extract::{Path, Query};
use serde::Deserialize;

#[derive(Deserialize)]
struct ContextQuery {
    #[serde(default = "default_context")]
    context_id: String,
}

fn default_context() -> String {
    format!("0x{}", hex::encode(CTX_GLOBAL))
}

async fn get_rating(
    State(state): State<AppState>,
    Path((rater_str, target_str)): Path<(String, String)>,
    Query(query): Query<ContextQuery>,
) -> Result<Json<RatingResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Parse addresses
    let rater = rater_str
        .parse::<Address>()
        .map_err(|_| bad_request(&format!("Invalid rater address: {}", rater_str)))?;
    let target = target_str
        .parse::<Address>()
        .map_err(|_| bad_request(&format!("Invalid target address: {}", target_str)))?;
    let context_id = query
        .context_id
        .parse::<B256>()
        .map_err(|_| bad_request(&format!("Invalid context_id: {}", query.context_id)))?;

    // Get edge details
    if let Some(edge) = db::get_edge_details(&state.db, &rater, &target, &context_id)
        .await
        .map_err(internal_error)?
    {
        let level = trustnet_core::Level::new(edge.level as i8)
            .map_err(|_| internal_error("Invalid level in database"))?;

        return Ok(Json(RatingResponse {
            level: level.value(),
            score: level_to_erc8004_score(level),
            source: edge.source,
            block_number: edge.block_number as u64,
            tx_hash: edge.tx_hash.map(|h| format!("0x{}", hex::encode(h))),
            timestamp: edge.ingested_at as u64,
            exists: true,
        }));
    }

    // No rating found
    Ok(Json(RatingResponse {
        level: 0,
        score: 50,
        source: "none".to_string(),
        block_number: 0,
        tx_hash: None,
        timestamp: 0,
        exists: false,
    }))
}

// Score endpoint - returns computed score with 2-hop logic
#[derive(Serialize)]
struct ScoreResponse {
    /// Computed score as ERC-8004 value (0-100)
    score: i8,
    /// Trust level (-2 to +2)
    level: i8,
    /// Method used: "direct", "2-hop", or "none"
    method: String,
    /// Endorser address for 2-hop paths
    #[serde(skip_serializing_if = "Option::is_none")]
    endorser: Option<String>,
}

async fn get_score(
    State(state): State<AppState>,
    Path((decider_str, target_str)): Path<(String, String)>,
    Query(query): Query<ContextQuery>,
) -> Result<Json<ScoreResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Parse addresses
    let decider = decider_str
        .parse::<Address>()
        .map_err(|_| bad_request(&format!("Invalid decider address: {}", decider_str)))?;
    let target = target_str
        .parse::<Address>()
        .map_err(|_| bad_request(&format!("Invalid target address: {}", target_str)))?;
    let context_id = query
        .context_id
        .parse::<B256>()
        .map_err(|_| bad_request(&format!("Invalid context_id: {}", query.context_id)))?;

    // Check for direct edge first
    if let Some(level) = db::get_direct_edge(&state.db, &decider, &target, &context_id)
        .await
        .map_err(internal_error)?
    {
        return Ok(Json(ScoreResponse {
            score: level_to_erc8004_score(level),
            level: level.value(),
            method: "direct".to_string(),
            endorser: None,
        }));
    }

    // Check 2-hop paths
    let two_hop_paths = db::get_two_hop_paths(&state.db, &decider, &target, &context_id)
        .await
        .map_err(internal_error)?;

    // Find best 2-hop path using protocol scoring formula
    if let Some((endorser, _level1, _level2, path_score)) = two_hop_paths
        .into_iter()
        .map(|path| {
            // Protocol formula: (levelOY * levelYT) / 2 with truncation toward zero
            // Since no direct edge exists (levelOT=0), score = (level1 * level2) / 2
            //
            // Special case: when both levels are negative, multiplication flips the sign
            // (e.g., -2 * -2 / 2 = 2, which incorrectly suggests trust).
            // In trust semantics, if we distrust the endorser, we can't trust their
            // judgment, so we use the strongest distrust instead.
            let path_score = if path.level1 < 0 && path.level2 < 0 {
                // Both negative: use min (strongest distrust)
                path.level1.min(path.level2)
            } else {
                // At least one positive: use multiplication formula
                (path.level1 * path.level2) / 2
            };
            // Clamp to valid Level range [-2, +2]
            let path_score = path_score.clamp(-2, 2);
            (path.endorser, path.level1, path.level2, path_score)
        })
        .max_by_key(|(_, _, _, score)| *score)
    {
        return Ok(Json(ScoreResponse {
            score: level_to_erc8004_score(
                trustnet_core::Level::new(path_score as i8)
                    .map_err(|_| internal_error("Invalid level in 2-hop path"))?,
            ),
            level: path_score as i8,
            method: "2-hop".to_string(),
            endorser: Some(format!("0x{}", hex::encode(endorser))),
        }));
    }

    // No path found - return neutral default
    Ok(Json(ScoreResponse {
        score: 50,
        level: 0,
        method: "none".to_string(),
        endorser: None,
    }))
}

// Ratings collection endpoint - returns paginated list of ratings
#[derive(Deserialize)]
struct RatingsQuery {
    /// Rater address (required)
    rater: String,
    /// Context ID (optional, defaults to CTX_GLOBAL)
    #[serde(default = "default_context", rename = "contextId")]
    context_id: String,
    /// Optional target filter
    target: Option<String>,
    /// Page size limit (default 50, max 100)
    #[serde(default = "default_limit")]
    limit: u32,
    /// Pagination cursor (last target from previous page)
    cursor: Option<String>,
}

fn default_limit() -> u32 {
    50
}

#[derive(Serialize)]
struct RatingsResponse {
    /// List of ratings
    ratings: Vec<RatingItem>,
    /// Cursor for next page (if more results exist)
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct RatingItem {
    /// Target address
    target: String,
    /// Trust level (-2 to +2)
    level: i8,
    /// ERC-8004 score (0-100)
    score: i8,
    /// Block number where edge was emitted
    block_number: u64,
    /// Transaction hash
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    /// Unix timestamp when ingested
    timestamp: u64,
    /// Source: "trust_graph" or "erc8004"
    source: String,
}

async fn get_ratings(
    State(state): State<AppState>,
    Query(query): Query<RatingsQuery>,
) -> Result<Json<RatingsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Parse rater address
    let rater = query
        .rater
        .parse::<Address>()
        .map_err(|_| bad_request(&format!("Invalid rater address: {}", query.rater)))?;

    // Parse context_id
    let context_id = query
        .context_id
        .parse::<B256>()
        .map_err(|_| bad_request(&format!("Invalid context_id: {}", query.context_id)))?;

    // Parse optional target
    let target = if let Some(ref t) = query.target {
        Some(
            t.parse::<Address>()
                .map_err(|_| bad_request(&format!("Invalid target address: {}", t)))?,
        )
    } else {
        None
    };

    // Parse cursor (hex-encoded address)
    let cursor = if let Some(ref c) = query.cursor {
        let cursor_bytes = if let Some(stripped) = c.strip_prefix("0x") {
            hex::decode(stripped)
        } else {
            hex::decode(c)
        }
        .map_err(|_| bad_request(&format!("Invalid cursor: {}", c)))?;

        Some(cursor_bytes)
    } else {
        None
    };

    // Cap limit at 100
    let limit = query.limit.min(100);

    // Fetch one extra to check if there's a next page
    let edges = db::get_ratings_by_rater(
        &state.db,
        &rater,
        &context_id,
        target.as_ref(),
        (limit + 1) as i64,
        cursor.as_deref(),
    )
    .await
    .map_err(internal_error)?;

    // Check if there are more results
    let has_next = edges.len() > limit as usize;
    let edges_to_return = if has_next {
        &edges[..limit as usize]
    } else {
        &edges[..]
    };

    // Convert to response format
    let ratings: Vec<RatingItem> = edges_to_return
        .iter()
        .map(|edge| {
            let level = trustnet_core::Level::new(edge.level as i8)
                .unwrap_or(trustnet_core::Level::neutral());
            RatingItem {
                target: format!("0x{}", hex::encode(&edge.target)),
                level: level.value(),
                score: level_to_erc8004_score(level),
                block_number: edge.block_number as u64,
                tx_hash: edge
                    .tx_hash
                    .as_ref()
                    .map(|h| format!("0x{}", hex::encode(h))),
                timestamp: edge.ingested_at as u64,
                source: edge.source.clone(),
            }
        })
        .collect();

    // Generate next cursor if there are more results
    let next_cursor = if has_next {
        edges_to_return
            .last()
            .map(|e| format!("0x{}", hex::encode(&e.target)))
    } else {
        None
    };

    Ok(Json(RatingsResponse {
        ratings,
        next_cursor,
    }))
}

// Proof endpoint - returns Merkle proof for an edge
#[derive(Serialize)]
struct ProofResponse {
    /// Root hash of the SMM
    root: String,
    /// Edge key (keccak256 of rater||target||context)
    key: String,
    /// Merkle proof siblings (256 hashes)
    siblings: Vec<String>,
    /// Whether the edge exists in the tree
    exists: bool,
    /// Value at the key (0-4, representing levels -2 to +2)
    value: u8,
}

async fn get_proof(
    State(state): State<AppState>,
    Path((rater_str, target_str)): Path<(String, String)>,
    Query(query): Query<ContextQuery>,
) -> Result<Json<ProofResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Parse addresses
    let rater = rater_str
        .parse::<Address>()
        .map_err(|_| bad_request(&format!("Invalid rater address: {}", rater_str)))?;
    let target = target_str
        .parse::<Address>()
        .map_err(|_| bad_request(&format!("Invalid target address: {}", target_str)))?;
    let context_id = query
        .context_id
        .parse::<B256>()
        .map_err(|_| bad_request(&format!("Invalid context_id: {}", query.context_id)))?;

    // Get the published epoch root - this is the canonical state
    let latest_epoch = match db::get_latest_epoch(&state.db)
        .await
        .map_err(internal_error)?
    {
        Some(epoch) => epoch,
        None => {
            // No epochs yet - indexer hasn't published any data
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "No epochs published yet. Indexer must publish at least one epoch before proofs are available.".to_string(),
                }),
            ));
        }
    };

    let published_root = B256::from_slice(&latest_epoch.graph_root);

    // Check if cache is stale and rebuild if needed
    if state.smm_cache.is_stale(published_root).await {
        // Cache is stale, attempt to rebuild for the published epoch
        let edges = db::get_all_edges_for_smm(&state.db)
            .await
            .map_err(internal_error)?;

        let success = state
            .smm_cache
            .try_rebuild_for_epoch(edges, published_root)
            .await
            .map_err(internal_error)?;

        if !success {
            // The edges table is newer than the published epoch
            // This happens during the window between edge ingestion and epoch publication
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: format!(
                        "Epoch data not yet published. Latest published epoch: {}. New edges are being processed. Please retry in a moment.",
                        latest_epoch.epoch
                    ),
                }),
            ));
        }
    }

    // Get SMM from cache - guaranteed to match published epoch after checks above
    let smm = state
        .smm_cache
        .get()
        .await
        .ok_or_else(|| internal_error("SMM not available"))?;

    // Compute edge key
    let context = ContextId::new(context_id);
    let key = compute_edge_key(&rater, &target, &context);

    // Generate proof
    let proof = smm
        .prove(key)
        .map_err(|e| internal_error(format!("Failed to generate proof: {}", e)))?;

    // Convert siblings to hex strings
    let siblings: Vec<String> = proof
        .siblings
        .iter()
        .map(|sibling| format!("0x{}", hex::encode(sibling)))
        .collect();

    Ok(Json(ProofResponse {
        root: format!("0x{}", hex::encode(smm.root())),
        key: format!("0x{}", hex::encode(key)),
        siblings,
        exists: proof.is_membership, // Use membership flag, not value comparison
        value: proof.value,
    }))
}

// Helper: Convert Level to ERC-8004 score (0-100)
fn level_to_erc8004_score(level: trustnet_core::Level) -> i8 {
    match level.value() {
        -2 => 0,
        -1 => 25,
        0 => 50,
        1 => 75,
        2 => 100,
        _ => 50, // Default to neutral
    }
}

// Error helpers
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: format!("Internal error: {}", err),
        }),
    )
}

fn not_found(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

fn bad_request(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use trustnet_core::types::Level;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = Router::new()
            .route("/health", get(health))
            .with_state(create_test_app_state().await);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn test_get_contexts() {
        let response = get_contexts().await;
        let contexts = response.0.contexts;

        assert_eq!(contexts.len(), 5);
        assert_eq!(contexts[0].name, "GLOBAL");
        assert_eq!(contexts[1].name, "PAYMENTS");
        assert_eq!(contexts[2].name, "CODE_EXEC");
        assert_eq!(contexts[3].name, "WRITES");
        assert_eq!(contexts[4].name, "DEFI_EXEC");
    }

    #[tokio::test]
    async fn test_invalid_address_format() {
        let app = Router::new()
            .route("/v1/rating/:rater/:target", get(get_rating))
            .with_state(create_test_app_state().await);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/rating/invalid/0x0000000000000000000000000000000000000001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_2hop_scoring_both_positive() {
        // (2, 2) -> 2*2/2 = 2
        let score = compute_2hop_score(2, 2);
        assert_eq!(score, 2);

        // (2, 1) -> 2*1/2 = 1
        let score = compute_2hop_score(2, 1);
        assert_eq!(score, 1);

        // (1, 1) -> 1*1/2 = 0
        let score = compute_2hop_score(1, 1);
        assert_eq!(score, 0);
    }

    #[tokio::test]
    async fn test_2hop_scoring_mixed_signs() {
        // (2, -1) -> 2*-1/2 = -1
        let score = compute_2hop_score(2, -1);
        assert_eq!(score, -1);

        // (-1, 2) -> -1*2/2 = -1
        let score = compute_2hop_score(-1, 2);
        assert_eq!(score, -1);

        // (1, -2) -> 1*-2/2 = -1
        let score = compute_2hop_score(1, -2);
        assert_eq!(score, -1);
    }

    #[tokio::test]
    async fn test_2hop_scoring_both_negative() {
        // (-2, -2) -> min(-2, -2) = -2 (not +2!)
        let score = compute_2hop_score(-2, -2);
        assert_eq!(score, -2);

        // (-1, -1) -> min(-1, -1) = -1 (not 0!)
        let score = compute_2hop_score(-1, -1);
        assert_eq!(score, -1);

        // (-2, -1) -> min(-2, -1) = -2 (not +1!)
        let score = compute_2hop_score(-2, -1);
        assert_eq!(score, -2);
    }

    #[test]
    fn test_level_to_erc8004_score_conversion() {
        assert_eq!(level_to_erc8004_score(Level::new(2).unwrap()), 100);
        assert_eq!(level_to_erc8004_score(Level::new(1).unwrap()), 75);
        assert_eq!(level_to_erc8004_score(Level::new(0).unwrap()), 50);
        assert_eq!(level_to_erc8004_score(Level::new(-1).unwrap()), 25);
        assert_eq!(level_to_erc8004_score(Level::new(-2).unwrap()), 0);
    }

    // Helper function to compute 2-hop score (extracted logic from get_score)
    fn compute_2hop_score(level1: i32, level2: i32) -> i32 {
        let path_score = if level1 < 0 && level2 < 0 {
            level1.min(level2)
        } else {
            (level1 * level2) / 2
        };
        path_score.clamp(-2, 2)
    }

    // Helper to create test AppState with in-memory database
    async fn create_test_app_state() -> AppState {
        let db = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");

        // Create tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS epochs (
                epoch INTEGER PRIMARY KEY,
                graph_root BLOB NOT NULL,
                edge_count INTEGER NOT NULL
            )
            "#,
        )
        .execute(&db)
        .await
        .expect("Failed to create epochs table");

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS edges (
                rater BLOB NOT NULL,
                target BLOB NOT NULL,
                context_id BLOB NOT NULL,
                level INTEGER NOT NULL,
                block_number INTEGER NOT NULL,
                tx_hash BLOB,
                ingested_at INTEGER NOT NULL,
                source TEXT NOT NULL,
                PRIMARY KEY (rater, target, context_id)
            )
            "#,
        )
        .execute(&db)
        .await
        .expect("Failed to create edges table");

        let cache_dir = std::env::temp_dir().join("trustnet_test_cache");
        let smm_cache = Arc::new(smm_cache::SmmCache::new(cache_dir));

        AppState { db, smm_cache }
    }
}
