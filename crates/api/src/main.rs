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
/// Full 2-hop path proof as specified in whitepaper Section 4.2
#[derive(Serialize)]
struct TrustPathProof {
    /// Decider address (D)
    #[serde(rename = "D")]
    decider: String,
    /// Endorser address (E)
    #[serde(rename = "E")]
    endorser: String,
    /// Target address (T)
    #[serde(rename = "T")]
    target: String,

    /// D→E edge level (Decider to Endorser)
    #[serde(rename = "lDE")]
    level_de: i8,
    /// D→E Merkle proof siblings
    #[serde(rename = "merkleDE")]
    merkle_de: Vec<String>,

    /// E→T edge level (Endorser to Target)
    #[serde(rename = "lET")]
    level_et: i8,
    /// E→T Merkle proof siblings
    #[serde(rename = "merkleET")]
    merkle_et: Vec<String>,

    /// D→T direct edge level (Decider to Target, 0 if absent)
    #[serde(rename = "lDT")]
    level_dt: i8,
    /// D→T Merkle proof siblings
    #[serde(rename = "merkleDT")]
    merkle_dt: Vec<String>,
    /// Whether D→T edge is absent (non-membership proof)
    #[serde(rename = "dtIsAbsent")]
    dt_is_absent: bool,
}

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

    /// Epoch number
    epoch: i64,
    /// Merkle root hash of the graph
    #[serde(rename = "graphRoot")]
    graph_root: String,
    /// Context ID for this score
    #[serde(rename = "contextId")]
    context_id: String,

    /// Full 2-hop path proof (only present for 2-hop method)
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<TrustPathProof>,
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

    // Get the published epoch root for proof generation
    let latest_epoch = db::get_latest_epoch(&state.db)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "No epochs published yet".to_string(),
                }),
            )
        })?;

    let published_root = B256::from_slice(&latest_epoch.graph_root);

    // Ensure SMM cache is synchronized with published epoch
    if state.smm_cache.is_stale(published_root).await {
        let edges = db::get_all_edges_for_smm(&state.db)
            .await
            .map_err(internal_error)?;
        let success = state
            .smm_cache
            .try_rebuild_for_epoch(edges, published_root)
            .await
            .map_err(internal_error)?;

        if !success {
            // Rebuild failed (edges ahead of published epoch)
            // Check if we have an existing cache we can continue using
            if state.smm_cache.get().await.is_none() {
                // No cache at all - truly unavailable (cold start, no snapshot)
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: format!(
                            "No snapshot available for published epoch {}. Edges are ahead of published epoch. Waiting for indexer to publish or for snapshot to be created.",
                            latest_epoch.epoch
                        ),
                    }),
                ));
            }
            // else: we have a cache (possibly for older epoch), continue using it
            // The is_membership guards will catch any attempts to use unpublished edges
        }
    }

    let smm = state
        .smm_cache
        .get()
        .await
        .ok_or_else(|| internal_error("SMM not available"))?;

    // Verify cached SMM root matches published epoch root
    // This ensures we never return proofs from a stale epoch
    let cached_root = smm.root();
    if cached_root != published_root {
        // Cache is from a different epoch - cannot serve with correct root
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: format!(
                    "Cache root mismatch. Published epoch {} has root 0x{}, but cached root is 0x{}. Waiting for cache rebuild.",
                    latest_epoch.epoch,
                    hex::encode(published_root),
                    hex::encode(cached_root)
                ),
            }),
        ));
    }

    let epoch = latest_epoch.epoch;
    let graph_root = format!("0x{}", hex::encode(published_root));
    let context_id_hex = format!("0x{}", hex::encode(context_id));

    // Check for direct edge in published epoch (not database)
    // This ensures the score and published root are synchronized
    let context = ContextId::new(context_id);
    let key_dt = compute_edge_key(&decider, &target, &context);
    let proof_dt = smm
        .prove(key_dt)
        .map_err(|e| internal_error(format!("Failed to generate D→T proof: {}", e)))?;

    if proof_dt.is_membership {
        // Direct edge exists in published epoch
        let published_level_dt = (proof_dt.value as i8) - 2; // SMM value 0-4 → level -2 to +2
        return Ok(Json(ScoreResponse {
            score: level_to_erc8004_score(
                trustnet_core::Level::new(published_level_dt)
                    .map_err(|_| internal_error("Invalid level in direct edge"))?,
            ),
            level: published_level_dt,
            method: "direct".to_string(),
            endorser: None,
            epoch,
            graph_root,
            context_id: context_id_hex,
            proof: None,
        }));
    }

    // Check 2-hop paths
    let two_hop_paths = db::get_two_hop_paths(&state.db, &decider, &target, &context_id)
        .await
        .map_err(internal_error)?;

    // Evaluate all 2-hop paths to find the best published path
    // Note: SQL ordering by MIN(level1, level2) DESC no longer matches actual scores
    // because the whitepaper formula treats double-negatives as positive (multiplication)
    // Example: (-2, -2) has min=-2 but score=+2, better than (+2, -1) with min=-1 and score=-1
    let context = ContextId::new(context_id);
    let mut best_path: Option<(i8, TrustPathProof, Address)> = None;

    for path in two_hop_paths {
        let endorser_addr = Address::from_slice(&path.endorser);

        // Generate proofs for this candidate path
        let key_de = compute_edge_key(&decider, &endorser_addr, &context);
        let proof_de = smm
            .prove(key_de)
            .map_err(|e| internal_error(format!("Failed to generate D→E proof: {}", e)))?;

        // Skip this path if D→E not in published epoch (try next candidate)
        if !proof_de.is_membership {
            continue;
        }

        let key_et = compute_edge_key(&endorser_addr, &target, &context);
        let proof_et = smm
            .prove(key_et)
            .map_err(|e| internal_error(format!("Failed to generate E→T proof: {}", e)))?;

        // Skip this path if E→T not in published epoch (try next candidate)
        if !proof_et.is_membership {
            continue;
        }

        // Both edges exist in published epoch - this path is valid!
        // Generate D→T proof (may be non-membership)
        let key_dt = compute_edge_key(&decider, &target, &context);
        let proof_dt = smm
            .prove(key_dt)
            .map_err(|e| internal_error(format!("Failed to generate D→T proof: {}", e)))?;

        // Extract levels from published epoch (proof values), not database
        // This ensures the score and proof are synchronized with the published root
        let published_level_de = (proof_de.value as i8) - 2; // SMM value 0-4 → level -2 to +2
        let published_level_et = (proof_et.value as i8) - 2;
        let published_level_dt = if proof_dt.is_membership {
            (proof_dt.value as i8) - 2
        } else {
            0 // Non-membership defaults to 0
        };

        // Recompute score using published levels (not database levels)
        // This matches the protocol formula in the whitepaper (§5):
        // sumProducts = lDE * lET
        // scoreNumerator = 2*lDT + sumProducts
        // score = clamp(scoreNumerator / 2, -2, +2)
        let sum_products = published_level_de as i32 * published_level_et as i32;
        let score_numerator = 2 * (published_level_dt as i32) + sum_products;
        let published_path_score = (score_numerator / 2).clamp(-2, 2) as i8;

        // Check if this is the best path so far
        let is_better = match &best_path {
            None => true,
            Some((best_score, _, _)) => published_path_score > *best_score,
        };

        if is_better {
            let trust_path_proof = TrustPathProof {
                decider: format!("0x{}", hex::encode(decider)),
                endorser: format!("0x{}", hex::encode(endorser_addr)),
                target: format!("0x{}", hex::encode(target)),
                level_de: published_level_de,
                merkle_de: proof_de
                    .siblings
                    .iter()
                    .map(|s| format!("0x{}", hex::encode(s)))
                    .collect(),
                level_et: published_level_et,
                merkle_et: proof_et
                    .siblings
                    .iter()
                    .map(|s| format!("0x{}", hex::encode(s)))
                    .collect(),
                level_dt: published_level_dt,
                merkle_dt: proof_dt
                    .siblings
                    .iter()
                    .map(|s| format!("0x{}", hex::encode(s)))
                    .collect(),
                dt_is_absent: !proof_dt.is_membership,
            };

            best_path = Some((published_path_score, trust_path_proof, endorser_addr));
        }
    }

    // Return best path if found
    if let Some((best_score, best_proof, best_endorser)) = best_path {
        return Ok(Json(ScoreResponse {
            score: level_to_erc8004_score(
                trustnet_core::Level::new(best_score)
                    .map_err(|_| internal_error("Invalid level in 2-hop path"))?,
            ),
            level: best_score,
            method: "2-hop".to_string(),
            endorser: Some(format!("0x{}", hex::encode(best_endorser))),
            epoch,
            graph_root,
            context_id: context_id_hex,
            proof: Some(best_proof),
        }));
    }

    // No path found - return neutral default
    Ok(Json(ScoreResponse {
        score: 50,
        level: 0,
        method: "none".to_string(),
        endorser: None,
        epoch,
        graph_root,
        context_id: context_id_hex,
        proof: None,
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
            // Rebuild failed (edges ahead of published epoch)
            // Check if we have an existing cache we can continue using
            if state.smm_cache.get().await.is_none() {
                // No cache at all - truly unavailable (cold start, no snapshot)
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: format!(
                            "No snapshot available for published epoch {}. Edges are ahead of published epoch. Waiting for indexer to publish or for snapshot to be created.",
                            latest_epoch.epoch
                        ),
                    }),
                ));
            }
            // else: we have a cache (possibly for older epoch), continue using it
        }
    }

    // Get SMM from cache
    let smm = state
        .smm_cache
        .get()
        .await
        .ok_or_else(|| internal_error("SMM not available"))?;

    // Verify cached SMM root matches published epoch root
    // This ensures we never return proofs from a stale epoch
    let cached_root = smm.root();
    if cached_root != published_root {
        // Cache is from a different epoch - cannot serve with correct root
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: format!(
                    "Cache root mismatch. Published epoch {} has root 0x{}, but cached root is 0x{}. Waiting for cache rebuild.",
                    latest_epoch.epoch,
                    hex::encode(published_root),
                    hex::encode(cached_root)
                ),
            }),
        ));
    }

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
        // Per whitepaper §5: sumProducts = lDE * lET (pure multiplication)
        // Two negatives multiply to positive (protocol-defined behavior)

        // (-2, -2) -> (-2)*(-2)/2 = 4/2 = +2
        let score = compute_2hop_score(-2, -2);
        assert_eq!(score, 2);

        // (-1, -1) -> (-1)*(-1)/2 = 1/2 = 0 (integer division)
        let score = compute_2hop_score(-1, -1);
        assert_eq!(score, 0);

        // (-2, -1) -> (-2)*(-1)/2 = 2/2 = +1
        let score = compute_2hop_score(-2, -1);
        assert_eq!(score, 1);
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
    // Implements the whitepaper formula (§5): score = clamp((lDE * lET) / 2, -2, +2)
    fn compute_2hop_score(level1: i32, level2: i32) -> i32 {
        let path_score = (level1 * level2) / 2;
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
