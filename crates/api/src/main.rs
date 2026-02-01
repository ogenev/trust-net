use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tower_http::cors::CorsLayer;
use trustnet_core::{hashing::compute_edge_key, ContextId, LeafValueV1, Level, PrincipalId, B256};
use trustnet_engine::{decide, Candidate, Decision, Thresholds};
use trustnet_smm::Smm;

mod db;
mod smm_cache;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    smm_cache: Arc<smm_cache::SmmCache>,
    thresholds: Thresholds,
    write_enabled: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://trustnet.db".to_string());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    let write_enabled = std::env::var("TRUSTNET_API_WRITE_ENABLED")
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let connect_options = SqliteConnectOptions::from_str(&database_url)?
        .read_only(!write_enabled)
        .create_if_missing(write_enabled);
    let db = SqlitePool::connect_with(connect_options).await?;

    let cache_dir = std::env::var("SMM_CACHE_DIR").unwrap_or_else(|_| "./smm_cache".to_string());
    let smm_cache = Arc::new(smm_cache::SmmCache::new(&cache_dir));

    let thresholds = Thresholds::new(2, 1).expect("static thresholds");

    let state = AppState {
        db,
        smm_cache,
        thresholds,
        write_enabled,
    };

    // Best-effort warmup.
    if let Ok(Some(epoch)) = db::get_latest_epoch(&state.db).await {
        let _ = ensure_smm_for_epoch(&state, &epoch).await;
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/root", get(get_root))
        .route("/v1/contexts", get(get_contexts))
        .route("/v1/decision", get(get_decision))
        .route("/v1/proof", get(get_proof))
        .route("/v1/ratings", post(post_rating))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("TrustNet API server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(_state): State<AppState>) -> &'static str {
    "OK"
}

fn is_allowlisted_context_id(context_id: &ContextId) -> bool {
    matches!(
        *context_id.inner(),
        trustnet_core::CTX_GLOBAL
            | trustnet_core::CTX_PAYMENTS
            | trustnet_core::CTX_CODE_EXEC
            | trustnet_core::CTX_WRITES
            | trustnet_core::CTX_DEFI_EXEC
    )
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg.into() }),
    )
}

fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse { error: msg.into() }),
    )
}

fn not_found(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse { error: msg.into() }),
    )
}

fn service_unavailable(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse { error: msg.into() }),
    )
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: format!("Internal error: {}", err),
        }),
    )
}

fn ttl_seconds_for_context_id(context_id: &ContextId) -> u64 {
    let id = context_id.inner();
    if *id == trustnet_core::CTX_PAYMENTS {
        return 30 * 24 * 60 * 60;
    }
    if *id == trustnet_core::CTX_CODE_EXEC {
        return 7 * 24 * 60 * 60;
    }
    if *id == trustnet_core::CTX_WRITES {
        return 7 * 24 * 60 * 60;
    }
    if *id == trustnet_core::CTX_DEFI_EXEC {
        return 7 * 24 * 60 * 60;
    }
    0
}

fn edge_is_expired(updated_at_u64: u64, context_id: &ContextId, as_of_u64: u64) -> bool {
    let ttl_seconds = ttl_seconds_for_context_id(context_id);
    if ttl_seconds == 0 {
        return false;
    }
    if updated_at_u64 == 0 {
        return true;
    }
    updated_at_u64.saturating_add(ttl_seconds) < as_of_u64
}

fn hex_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_b256(v: &B256) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}

fn parse_b256(bytes: &[u8]) -> anyhow::Result<B256> {
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    Ok(B256::from_slice(bytes))
}

fn parse_principal_id(bytes: &[u8]) -> anyhow::Result<PrincipalId> {
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    Ok(PrincipalId::from(<[u8; 32]>::try_from(bytes)?))
}

fn parse_context_id(bytes: &[u8]) -> anyhow::Result<ContextId> {
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    Ok(ContextId::from(<[u8; 32]>::try_from(bytes)?))
}

fn build_epoch_leaves(
    edges: Vec<db::DbEdgeLatest>,
    as_of_u64: u64,
) -> anyhow::Result<Vec<smm_cache::SnapshotLeaf>> {
    let mut leaves = Vec::with_capacity(edges.len());
    for edge in edges {
        if edge.level_i8 == 0 {
            continue;
        }

        let rater = parse_principal_id(&edge.rater_pid)?;
        let target = parse_principal_id(&edge.target_pid)?;
        let context_id = parse_context_id(&edge.context_id)?;

        let updated_at_u64 = edge.updated_at_u64.max(0) as u64;
        if edge_is_expired(updated_at_u64, &context_id, as_of_u64) {
            continue;
        }

        let level = Level::new(edge.level_i8 as i8)?;
        if level.value() == 0 {
            continue;
        }

        let evidence_hash = if edge.evidence_hash.len() == 32 {
            B256::from_slice(&edge.evidence_hash)
        } else {
            B256::ZERO
        };

        let key = compute_edge_key(&rater, &target, &context_id);
        let leaf_value = LeafValueV1 {
            level,
            updated_at_u64,
            evidence_hash,
        }
        .encode()
        .to_vec();

        leaves.push(smm_cache::SnapshotLeaf { key, leaf_value });
    }

    leaves.sort_by_key(|l| l.key);
    Ok(leaves)
}

async fn ensure_smm_for_epoch(
    state: &AppState,
    epoch: &db::DbEpoch,
) -> Result<Arc<Smm>, (StatusCode, Json<ErrorResponse>)> {
    let published_root = parse_b256(&epoch.graph_root).map_err(internal_error)?;

    let as_of_u64 = epoch
        .created_at_u64
        .ok_or_else(|| service_unavailable("Epoch missing created_at_u64 (v0.4 required)"))?
        .max(0) as u64;

    if state.smm_cache.is_stale(published_root).await {
        let edges = db::get_all_edges_latest(&state.db)
            .await
            .map_err(internal_error)?;
        let leaves = build_epoch_leaves(edges, as_of_u64).map_err(internal_error)?;

        let success = state
            .smm_cache
            .try_rebuild_for_epoch(leaves, published_root)
            .await
            .map_err(internal_error)?;

        if !success && state.smm_cache.get().await.is_none() {
            return Err(service_unavailable(
                "Proofs unavailable: edges_latest does not match published root",
            ));
        }
    }

    let smm = state
        .smm_cache
        .get()
        .await
        .ok_or_else(|| service_unavailable("SMM not available"))?;

    if smm.root() != published_root {
        return Err(service_unavailable(
            "SMM cache root mismatch; waiting for rebuild",
        ));
    }

    Ok(smm)
}

#[derive(Serialize)]
struct RootResponseV1 {
    epoch: u64,
    #[serde(rename = "graphRoot")]
    graph_root: String,
    #[serde(rename = "edgeCount")]
    edge_count: u64,
    #[serde(rename = "manifestUri", skip_serializing_if = "Option::is_none")]
    manifest_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<serde_json::Value>,
    #[serde(rename = "manifestHash", skip_serializing_if = "Option::is_none")]
    manifest_hash: Option<String>,
    #[serde(rename = "publisherSig", skip_serializing_if = "Option::is_none")]
    publisher_sig: Option<String>,
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    created_at_u64: Option<u64>,
}

async fn get_root(
    State(state): State<AppState>,
) -> Result<Json<RootResponseV1>, (StatusCode, Json<ErrorResponse>)> {
    let epoch = db::get_latest_epoch(&state.db)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found("No epochs published"))?;

    let graph_root = parse_b256(&epoch.graph_root).map_err(internal_error)?;
    let manifest_hash = epoch
        .manifest_hash
        .as_deref()
        .and_then(|b| (b.len() == 32).then(|| hex_bytes(b)));
    let publisher_sig = epoch.publisher_sig.as_deref().map(hex_bytes);

    let manifest = match epoch.manifest_json.as_deref() {
        Some(json) => serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .or_else(|| Some(serde_json::Value::String(json.to_string()))),
        None => None,
    };

    Ok(Json(RootResponseV1 {
        epoch: epoch.epoch as u64,
        graph_root: hex_b256(&graph_root),
        edge_count: epoch.edge_count.max(0) as u64,
        manifest_uri: manifest.as_ref().map(|_| "inline".to_string()),
        manifest,
        manifest_hash,
        publisher_sig,
        created_at_u64: epoch.created_at_u64.map(|v| v.max(0) as u64),
    }))
}

#[derive(Serialize)]
struct ContextInfo {
    name: String,
    #[serde(rename = "contextId")]
    context_id: String,
    description: String,
}

#[derive(Serialize)]
struct ContextsResponse {
    contexts: Vec<ContextInfo>,
}

async fn get_contexts() -> Json<ContextsResponse> {
    Json(ContextsResponse {
        contexts: vec![
            ContextInfo {
                name: "trustnet:ctx:global:v1".to_string(),
                context_id: hex_b256(&trustnet_core::CTX_GLOBAL),
                description: "Global context (capability-agnostic)".to_string(),
            },
            ContextInfo {
                name: "trustnet:ctx:payments:v1".to_string(),
                context_id: hex_b256(&trustnet_core::CTX_PAYMENTS),
                description: "Payments context".to_string(),
            },
            ContextInfo {
                name: "trustnet:ctx:code-exec:v1".to_string(),
                context_id: hex_b256(&trustnet_core::CTX_CODE_EXEC),
                description: "Code execution context".to_string(),
            },
            ContextInfo {
                name: "trustnet:ctx:writes:v1".to_string(),
                context_id: hex_b256(&trustnet_core::CTX_WRITES),
                description: "Writes/modification context".to_string(),
            },
            ContextInfo {
                name: "trustnet:ctx:defi-exec:v1".to_string(),
                context_id: hex_b256(&trustnet_core::CTX_DEFI_EXEC),
                description: "DeFi execution context".to_string(),
            },
        ],
    })
}

#[derive(Debug, Deserialize)]
struct DecisionQuery {
    decider: String,
    target: String,
    #[serde(rename = "contextId")]
    context_id: String,
}

#[derive(Serialize)]
struct ThresholdsJson {
    allow: i8,
    ask: i8,
}

#[derive(Serialize)]
struct LeafValueJson {
    level: i8,
    #[serde(rename = "updatedAt")]
    updated_at: u64,
    #[serde(rename = "evidenceHash")]
    evidence_hash: String,
}

#[derive(Serialize)]
struct WhyJson {
    #[serde(rename = "edgeDE")]
    edge_de: LeafValueJson,
    #[serde(rename = "edgeET")]
    edge_et: LeafValueJson,
    #[serde(rename = "edgeDT")]
    edge_dt: LeafValueJson,
}

#[derive(Serialize)]
struct ConstraintsJson {
    #[serde(rename = "ttlSeconds")]
    ttl_seconds: u64,
}

#[derive(Serialize)]
struct SmmProofV1Json {
    #[serde(rename = "type")]
    ty: &'static str,
    #[serde(rename = "edgeKey")]
    edge_key: String,
    #[serde(rename = "contextId", skip_serializing_if = "Option::is_none")]
    context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rater: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(rename = "isMembership")]
    is_membership: bool,
    #[serde(rename = "leafValue", skip_serializing_if = "Option::is_none")]
    leaf_value: Option<LeafValueJson>,
    siblings: Vec<String>,
    format: &'static str,
}

fn leaf_value_json_from_v1(v: &LeafValueV1) -> LeafValueJson {
    LeafValueJson {
        level: v.level.value(),
        updated_at: v.updated_at_u64,
        evidence_hash: hex_b256(&v.evidence_hash),
    }
}

fn smm_proof_v1_json(
    proof: &trustnet_smm::SmmProof,
    rater: Option<&PrincipalId>,
    target: Option<&PrincipalId>,
    context_id: Option<&ContextId>,
) -> Result<SmmProofV1Json, (StatusCode, Json<ErrorResponse>)> {
    let leaf_value = if proof.is_membership {
        let decoded =
            LeafValueV1::decode(&proof.leaf_value).map_err(|e| bad_request(e.to_string()))?;
        Some(leaf_value_json_from_v1(&decoded))
    } else {
        None
    };

    Ok(SmmProofV1Json {
        ty: "trustnet.smmProof.v1",
        edge_key: hex_b256(&proof.key),
        context_id: context_id.map(|c| hex_b256(c.inner())),
        rater: rater.map(|p| hex_bytes(p.as_bytes())),
        target: target.map(|p| hex_bytes(p.as_bytes())),
        is_membership: proof.is_membership,
        leaf_value,
        siblings: proof.siblings.iter().map(hex_b256).collect(),
        format: "uncompressed",
    })
}

#[derive(Serialize)]
struct ProofsJson {
    #[serde(rename = "DE")]
    de: Option<SmmProofV1Json>,
    #[serde(rename = "ET")]
    et: Option<SmmProofV1Json>,
    #[serde(rename = "DT")]
    dt: SmmProofV1Json,
}

#[derive(Serialize)]
struct DecisionBundleV1Json {
    #[serde(rename = "type")]
    ty: &'static str,
    epoch: u64,
    #[serde(rename = "graphRoot")]
    graph_root: String,
    #[serde(rename = "manifestHash")]
    manifest_hash: String,
    decider: String,
    target: String,
    #[serde(rename = "contextId")]
    context_id: String,
    decision: String,
    score: i8,
    thresholds: ThresholdsJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    endorser: Option<String>,
    why: WhyJson,
    constraints: ConstraintsJson,
    proofs: ProofsJson,
}

struct CandidateMaterial {
    endorser: PrincipalId,
    proof_de: trustnet_smm::SmmProof,
    proof_et: trustnet_smm::SmmProof,
    leaf_de: LeafValueV1,
    leaf_et: LeafValueV1,
}

async fn get_decision(
    State(state): State<AppState>,
    Query(query): Query<DecisionQuery>,
) -> Result<Json<DecisionBundleV1Json>, (StatusCode, Json<ErrorResponse>)> {
    let decider = query.decider.parse::<PrincipalId>().map_err(|_| {
        bad_request("Invalid decider (expected 0x-address, 0x-bytes32, or agentRef:...)")
    })?;
    let target = query.target.parse::<PrincipalId>().map_err(|_| {
        bad_request("Invalid target (expected 0x-address, 0x-bytes32, or agentRef:...)")
    })?;
    let context_id = query
        .context_id
        .parse::<ContextId>()
        .map_err(|_| bad_request("Invalid contextId (expected 0x-bytes32)"))?;

    if !is_allowlisted_context_id(&context_id) {
        return Err(bad_request("Unknown contextId"));
    }

    let epoch = db::get_latest_epoch(&state.db)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found("No epochs published"))?;

    let published_root = parse_b256(&epoch.graph_root).map_err(internal_error)?;
    let manifest_hash = epoch
        .manifest_hash
        .as_deref()
        .ok_or_else(|| service_unavailable("Epoch missing manifestHash (v0.4 required)"))?;
    let manifest_hash = parse_b256(manifest_hash).map_err(internal_error)?;

    let smm = ensure_smm_for_epoch(&state, &epoch).await?;

    // DT proof (direct edge).
    let dt_key = compute_edge_key(&decider, &target, &context_id);
    let dt_proof = smm.prove(dt_key).map_err(internal_error)?;
    let dt_leaf = if dt_proof.is_membership {
        LeafValueV1::decode(&dt_proof.leaf_value).map_err(internal_error)?
    } else {
        LeafValueV1::default_neutral()
    };

    // Candidate endorsers from DB (hint only).
    let candidate_endorsers = db::get_candidate_endorsers(
        &state.db,
        decider.as_bytes(),
        target.as_bytes(),
        context_id.as_bytes(),
    )
    .await
    .map_err(internal_error)?;

    let mut candidates = Vec::new();
    for endorser_bytes in candidate_endorsers {
        let endorser = parse_principal_id(&endorser_bytes).map_err(internal_error)?;

        let de_key = compute_edge_key(&decider, &endorser, &context_id);
        let et_key = compute_edge_key(&endorser, &target, &context_id);

        let proof_de = smm.prove(de_key).map_err(internal_error)?;
        let proof_et = smm.prove(et_key).map_err(internal_error)?;
        if !proof_de.is_membership || !proof_et.is_membership {
            continue;
        }

        let leaf_de = LeafValueV1::decode(&proof_de.leaf_value).map_err(internal_error)?;
        let leaf_et = LeafValueV1::decode(&proof_et.leaf_value).map_err(internal_error)?;

        candidates.push(CandidateMaterial {
            endorser,
            proof_de,
            proof_et,
            leaf_de,
            leaf_et,
        });
    }

    let engine_candidates: Vec<Candidate> = candidates
        .iter()
        .map(|c| Candidate {
            endorser: c.endorser,
            level_de: c.leaf_de.level,
            level_et: c.leaf_et.level,
        })
        .collect();

    let result = decide(state.thresholds, dt_leaf.level, &engine_candidates);

    let (chosen_proof_de, chosen_proof_et, leaf_de, leaf_et) =
        if let Some(endorser) = result.endorser {
            let chosen = candidates
                .into_iter()
                .find(|c| c.endorser == endorser)
                .ok_or_else(|| internal_error("Selected endorser missing material"))?;
            (
                Some(smm_proof_v1_json(
                    &chosen.proof_de,
                    Some(&decider),
                    Some(&endorser),
                    Some(&context_id),
                )?),
                Some(smm_proof_v1_json(
                    &chosen.proof_et,
                    Some(&endorser),
                    Some(&target),
                    Some(&context_id),
                )?),
                chosen.leaf_de,
                chosen.leaf_et,
            )
        } else {
            (
                None,
                None,
                LeafValueV1::default_neutral(),
                LeafValueV1::default_neutral(),
            )
        };

    let dt = smm_proof_v1_json(&dt_proof, Some(&decider), Some(&target), Some(&context_id))?;

    let decision_str = match result.decision {
        Decision::Allow | Decision::Ask | Decision::Deny => result.decision.as_str().to_string(),
    };

    Ok(Json(DecisionBundleV1Json {
        ty: "trustnet.decisionBundle.v1",
        epoch: epoch.epoch as u64,
        graph_root: hex_b256(&published_root),
        manifest_hash: hex_b256(&manifest_hash),
        decider: hex_bytes(decider.as_bytes()),
        target: hex_bytes(target.as_bytes()),
        context_id: hex_b256(context_id.inner()),
        decision: decision_str,
        score: result.score,
        thresholds: ThresholdsJson {
            allow: state.thresholds.allow,
            ask: state.thresholds.ask,
        },
        endorser: result.endorser.map(|p| hex_bytes(p.as_bytes())),
        why: WhyJson {
            edge_de: leaf_value_json_from_v1(&leaf_de),
            edge_et: leaf_value_json_from_v1(&leaf_et),
            edge_dt: leaf_value_json_from_v1(&dt_leaf),
        },
        constraints: ConstraintsJson { ttl_seconds: 300 },
        proofs: ProofsJson {
            de: chosen_proof_de,
            et: chosen_proof_et,
            dt,
        },
    }))
}

#[derive(Debug, Deserialize)]
struct ProofQuery {
    key: String,
}

async fn get_proof(
    State(state): State<AppState>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<SmmProofV1Json>, (StatusCode, Json<ErrorResponse>)> {
    let key = query
        .key
        .parse::<B256>()
        .map_err(|_| bad_request("Invalid key (expected 0x-bytes32)"))?;

    let epoch = db::get_latest_epoch(&state.db)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found("No epochs published"))?;

    let smm = ensure_smm_for_epoch(&state, &epoch).await?;

    let proof = smm.prove(key).map_err(internal_error)?;
    Ok(Json(smm_proof_v1_json(&proof, None, None, None)?))
}

#[derive(Debug, Deserialize, Serialize)]
struct RatingEventV1 {
    #[serde(rename = "type")]
    ty: String,
    rater: String,
    #[serde(rename = "raterPubKey", default)]
    rater_pub_key: Option<String>,
    target: String,
    #[serde(rename = "contextId")]
    context_id: String,
    level: i8,
    #[serde(rename = "evidenceURI", default)]
    evidence_uri: Option<String>,
    #[serde(rename = "evidenceHash", default)]
    evidence_hash: Option<String>,
    #[serde(rename = "createdAt", default)]
    created_at: Option<String>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct RatingEventUnsignedV1 {
    #[serde(rename = "type")]
    ty: String,
    rater: String,
    #[serde(rename = "raterPubKey", skip_serializing_if = "Option::is_none")]
    rater_pub_key: Option<String>,
    target: String,
    #[serde(rename = "contextId")]
    context_id: String,
    level: i8,
    #[serde(rename = "evidenceURI", skip_serializing_if = "Option::is_none")]
    evidence_uri: Option<String>,
    #[serde(rename = "evidenceHash", skip_serializing_if = "Option::is_none")]
    evidence_hash: Option<String>,
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

#[derive(Serialize)]
struct RatingIngestResponse {
    ok: bool,
    #[serde(rename = "serverSeq")]
    server_seq: i64,
}

fn decode_binary_field(field: &str, value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("base64:").unwrap_or(value);
    if let Some(hex_str) = value.strip_prefix("0x") {
        return hex::decode(hex_str).map_err(|e| format!("Invalid hex {}: {}", field, e));
    }
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("Invalid base64 {}: {}", field, e))
}

fn parse_rfc3339_seconds(s: &str) -> Result<u64, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|e| format!("Invalid createdAt: {}", e))
        .map(|dt| dt.timestamp().max(0) as u64)
}

async fn post_rating(
    State(state): State<AppState>,
    Json(event): Json<RatingEventV1>,
) -> Result<Json<RatingIngestResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.write_enabled {
        return Err(forbidden(
            "Write disabled (set TRUSTNET_API_WRITE_ENABLED=1)",
        ));
    }

    if event.ty != "trustnet.rating.v1" {
        return Err(bad_request("Invalid type (expected trustnet.rating.v1)"));
    }

    let rater = event
        .rater
        .parse::<PrincipalId>()
        .map_err(|_| bad_request("Invalid rater"))?;
    let target = event
        .target
        .parse::<PrincipalId>()
        .map_err(|_| bad_request("Invalid target"))?;
    let context_id = event
        .context_id
        .parse::<ContextId>()
        .map_err(|_| bad_request("Invalid contextId"))?;

    if !is_allowlisted_context_id(&context_id) {
        return Err(bad_request("Unknown contextId"));
    }

    let level = Level::new(event.level).map_err(|e| bad_request(e.to_string()))?;

    let created_at_u64 = match event.created_at.as_deref() {
        Some(s) => parse_rfc3339_seconds(s).map_err(bad_request)?,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(internal_error)?
            .as_secs(),
    };

    let evidence_hash = match event.evidence_hash.as_deref() {
        Some(s) => s
            .parse::<B256>()
            .map_err(|_| bad_request("Invalid evidenceHash (expected 0x-bytes32)"))?,
        None => B256::ZERO,
    };

    let unsigned = RatingEventUnsignedV1 {
        ty: event.ty.clone(),
        rater: event.rater.clone(),
        rater_pub_key: event.rater_pub_key.clone(),
        target: event.target.clone(),
        context_id: event.context_id.clone(),
        level: level.value(),
        evidence_uri: event.evidence_uri.clone(),
        evidence_hash: event.evidence_hash.clone(),
        created_at: event.created_at.clone(),
    };

    let unsigned_canonical = serde_jcs::to_vec(&unsigned).map_err(internal_error)?;
    let sig_bytes = decode_binary_field("signature", &event.signature).map_err(bad_request)?;

    if let Some(expected) = rater.to_evm_address_opt() {
        let signature =
            alloy_primitives::PrimitiveSignature::from_raw(&sig_bytes).map_err(|e| {
                bad_request(format!(
                    "Invalid signature bytes (expected 65 bytes): {}",
                    e
                ))
            })?;

        let recovered = signature
            .recover_address_from_msg(&unsigned_canonical)
            .map_err(|e| bad_request(format!("Invalid signature: {}", e)))?;

        if recovered != expected {
            return Err(bad_request("Signature does not match rater"));
        }
    } else {
        // Non-EVM PrincipalId: treat as agentRef (self-certifying local identity).
        //
        // v0.4 rule: agentRef == sha256(agentPublicKey). See spec §6.1.
        let pubkey_str = event
            .rater_pub_key
            .as_deref()
            .ok_or_else(|| bad_request("raterPubKey is required for agentRef raters"))?;
        let pubkey_bytes = decode_binary_field("raterPubKey", pubkey_str).map_err(bad_request)?;
        let pubkey_bytes: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| bad_request("Invalid raterPubKey (expected 32 bytes)"))?;

        let agent_ref: [u8; 32] = Sha256::digest(pubkey_bytes).into();
        if agent_ref != *rater.as_bytes() {
            return Err(bad_request("raterPubKey does not match agentRef"));
        }

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| bad_request(format!("Invalid raterPubKey: {}", e)))?;
        let signature = Ed25519Signature::from_slice(&sig_bytes)
            .map_err(|e| bad_request(format!("Invalid ed25519 signature: {}", e)))?;

        verifying_key
            .verify_strict(&unsigned_canonical, &signature)
            .map_err(|_| bad_request("Invalid signature"))?;
    }

    let event_json = String::from_utf8(serde_jcs::to_vec(&event).map_err(internal_error)?)
        .map_err(internal_error)?;

    let mut tx = state.db.begin().await.map_err(internal_error)?;

    // Append immutable raw event (auditable).
    let result = sqlx::query(
        r#"
        INSERT INTO edges_raw (
            rater_pid, target_pid, context_id,
            level_i8, updated_at_u64, evidence_hash,
            source,
            chain_id, block_number, tx_index, log_index, tx_hash,
            server_seq,
            event_json, signature
        )
        VALUES (?, ?, ?, ?, ?, ?, 'private_log', NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)
        "#,
    )
    .bind(rater.as_bytes().as_slice())
    .bind(target.as_bytes().as_slice())
    .bind(context_id.as_bytes().as_slice())
    .bind(level.value() as i32)
    .bind(created_at_u64 as i64)
    .bind(evidence_hash.as_slice())
    .bind(&event_json)
    .bind(&sig_bytes)
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;

    let server_seq = result.last_insert_rowid();

    // Store the server seq on the raw row for easy reproduction via seq windows.
    sqlx::query("UPDATE edges_raw SET server_seq = ? WHERE id = ?")
        .bind(server_seq)
        .bind(server_seq)
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

    // Latest-wins reduction (server ordering).
    sqlx::query(
        r#"
        INSERT INTO edges_latest (
            rater_pid, target_pid, context_id,
            level_i8, updated_at_u64, evidence_hash, source,
            chain_id, block_number, tx_index, log_index, tx_hash,
            server_seq
        )
        VALUES (?, ?, ?, ?, ?, ?, 'private_log', NULL, NULL, NULL, NULL, NULL, ?)
        ON CONFLICT(rater_pid, target_pid, context_id)
        DO UPDATE SET
            level_i8 = excluded.level_i8,
            updated_at_u64 = excluded.updated_at_u64,
            evidence_hash = excluded.evidence_hash,
            source = excluded.source,
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
    .bind(rater.as_bytes().as_slice())
    .bind(target.as_bytes().as_slice())
    .bind(context_id.as_bytes().as_slice())
    .bind(level.value() as i32)
    .bind(created_at_u64 as i64)
    .bind(evidence_hash.as_slice())
    .bind(server_seq)
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;

    tx.commit().await.map_err(internal_error)?;

    Ok(Json(RatingIngestResponse {
        ok: true,
        server_seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt;

    async fn setup_state() -> (
        AppState,
        TempDir,
        PrincipalId,
        PrincipalId,
        PrincipalId,
        ContextId,
    ) {
        let db = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory db");

        // Minimal schema for v0.4 endpoints.
        sqlx::query(
            r#"
            CREATE TABLE epochs (
                epoch INTEGER PRIMARY KEY,
                graph_root BLOB NOT NULL,
                edge_count INTEGER NOT NULL,
                manifest_json TEXT,
                manifest_hash BLOB,
                publisher_sig BLOB,
                created_at_u64 INTEGER
            );
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE edges_raw (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rater_pid BLOB NOT NULL,
                target_pid BLOB NOT NULL,
                context_id BLOB NOT NULL,
                level_i8 INTEGER NOT NULL,
                updated_at_u64 INTEGER NOT NULL,
                evidence_hash BLOB NOT NULL,
                source TEXT NOT NULL,
                chain_id INTEGER,
                block_number INTEGER,
                tx_index INTEGER,
                log_index INTEGER,
                tx_hash BLOB,
                server_seq INTEGER,
                event_json TEXT,
                signature BLOB
            );

            CREATE TABLE edges_latest (
                rater_pid BLOB NOT NULL,
                target_pid BLOB NOT NULL,
                context_id BLOB NOT NULL,
                level_i8 INTEGER NOT NULL,
                updated_at_u64 INTEGER NOT NULL,
                evidence_hash BLOB NOT NULL,
                source TEXT NOT NULL,
                chain_id INTEGER,
                block_number INTEGER,
                tx_index INTEGER,
                log_index INTEGER,
                tx_hash BLOB,
                server_seq INTEGER,
                PRIMARY KEY (rater_pid, target_pid, context_id)
            );
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        let decider = PrincipalId::from([0x10u8; 32]);
        let endorser = PrincipalId::from([0x20u8; 32]);
        let target = PrincipalId::from([0x30u8; 32]);
        let context_id = ContextId::from(trustnet_core::CTX_CODE_EXEC);

        let created_at_u64 = 1000u64;
        let updated_at_u64 = 1000u64;

        // Insert edges (D->E=+2, E->T=+1).
        let evidence_hash = [0u8; 32];
        sqlx::query(
            r#"
            INSERT INTO edges_latest (rater_pid, target_pid, context_id, level_i8, updated_at_u64, evidence_hash, source)
            VALUES (?, ?, ?, ?, ?, ?, 'trust_graph')
            "#,
        )
        .bind(decider.as_bytes().as_slice())
        .bind(endorser.as_bytes().as_slice())
        .bind(context_id.as_bytes().as_slice())
        .bind(2i32)
        .bind(updated_at_u64 as i64)
        .bind(evidence_hash.as_slice())
        .execute(&db)
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO edges_latest (rater_pid, target_pid, context_id, level_i8, updated_at_u64, evidence_hash, source)
            VALUES (?, ?, ?, ?, ?, ?, 'trust_graph')
            "#,
        )
        .bind(endorser.as_bytes().as_slice())
        .bind(target.as_bytes().as_slice())
        .bind(context_id.as_bytes().as_slice())
        .bind(1i32)
        .bind(updated_at_u64 as i64)
        .bind(evidence_hash.as_slice())
        .execute(&db)
        .await
        .unwrap();

        // Build expected root (same logic as API).
        let leaves =
            build_epoch_leaves(db::get_all_edges_latest(&db).await.unwrap(), created_at_u64)
                .unwrap();
        let smm = {
            let mut builder = trustnet_smm::SmmBuilder::new();
            for leaf in &leaves {
                builder.insert(leaf.key, leaf.leaf_value.clone()).unwrap();
            }
            builder.build()
        };

        let graph_root = smm.root();

        // Insert epoch.
        sqlx::query(
            r#"
            INSERT INTO epochs (epoch, graph_root, edge_count, manifest_json, manifest_hash, publisher_sig, created_at_u64)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(1i64)
        .bind(graph_root.as_slice())
        .bind(2i64)
        .bind(r#"{"specVersion":"trustnet-spec-0.4"}"#)
        .bind([0xaau8; 32].as_slice())
        .bind([0x11u8; 65].as_slice())
        .bind(created_at_u64 as i64)
        .execute(&db)
        .await
        .unwrap();

        let tmp = TempDir::new().unwrap();
        let state = AppState {
            db,
            smm_cache: Arc::new(smm_cache::SmmCache::new(tmp.path())),
            thresholds: Thresholds::new(2, 1).unwrap(),
            write_enabled: true,
        };

        (state, tmp, decider, endorser, target, context_id)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (state, _tmp, _, _, _, _) = setup_state().await;
        let app = Router::new()
            .route("/health", get(health))
            .with_state(state);

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
        assert_eq!(response.0.contexts.len(), 5);
        assert_eq!(response.0.contexts[0].name, "trustnet:ctx:global:v1");
    }

    #[tokio::test]
    async fn test_decision_bundle_is_verifiable() {
        let (state, _tmp, decider, endorser, target, context_id) = setup_state().await;
        let app = Router::new()
            .route("/v1/decision", get(get_decision))
            .with_state(state);

        let uri = format!(
            "/v1/decision?decider={}&target={}&contextId={}",
            hex_bytes(decider.as_bytes()),
            hex_bytes(target.as_bytes()),
            hex_b256(context_id.inner())
        );

        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["decision"], "ask");
        assert_eq!(json["endorser"], hex_bytes(endorser.as_bytes()));

        // Verify proofs against the graphRoot in the response.
        let graph_root = json["graphRoot"].as_str().unwrap().parse::<B256>().unwrap();

        fn parse_leaf_value(v: &serde_json::Value) -> Vec<u8> {
            let level = v["level"].as_i64().unwrap() as i8;
            let updated_at = v["updatedAt"].as_u64().unwrap();
            let evidence_hash = v["evidenceHash"].as_str().unwrap().parse::<B256>().unwrap();
            LeafValueV1 {
                level: Level::new(level).unwrap(),
                updated_at_u64: updated_at,
                evidence_hash,
            }
            .encode()
            .to_vec()
        }

        fn parse_proof(p: &serde_json::Value) -> trustnet_smm::SmmProof {
            let key = p["edgeKey"].as_str().unwrap().parse::<B256>().unwrap();
            let is_membership = p["isMembership"].as_bool().unwrap();
            let leaf_value = if is_membership {
                parse_leaf_value(&p["leafValue"])
            } else {
                Vec::new()
            };
            let siblings: Vec<B256> = p["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().parse::<B256>().unwrap())
                .collect();
            trustnet_smm::SmmProof {
                key,
                leaf_value,
                siblings,
                is_membership,
            }
        }

        let proof_dt = parse_proof(&json["proofs"]["DT"]);
        assert!(proof_dt.verify(graph_root));

        let proof_de = parse_proof(&json["proofs"]["DE"]);
        let proof_et = parse_proof(&json["proofs"]["ET"]);
        assert!(proof_de.verify(graph_root));
        assert!(proof_et.verify(graph_root));

        // Verify decision score rule locally (gateway behavior).
        let l_dt = json["why"]["edgeDT"]["level"].as_i64().unwrap() as i8;
        let l_de = json["why"]["edgeDE"]["level"].as_i64().unwrap() as i8;
        let l_et = json["why"]["edgeET"]["level"].as_i64().unwrap() as i8;

        // v0.4 scoring: veto dominates; else base = min(lDE,lET) if both > 0; direct positive overrides.
        let score = if l_dt == -2 {
            -2
        } else {
            let base = if l_de > 0 && l_et > 0 {
                l_de.min(l_et)
            } else {
                0
            };
            if l_dt > 0 {
                base.max(l_dt)
            } else {
                base
            }
        };
        assert_eq!(json["score"].as_i64().unwrap() as i8, score);
    }

    #[tokio::test]
    async fn test_get_decision_rejects_unknown_context_id() {
        let (state, _tmp, decider, _endorser, target, _context_id) = setup_state().await;
        let app = Router::new()
            .route("/v1/decision", get(get_decision))
            .with_state(state);

        let unknown_context_id = ContextId::from(B256::repeat_byte(0x99));
        let uri = format!(
            "/v1/decision?decider={}&target={}&contextId={}",
            hex_bytes(decider.as_bytes()),
            hex_bytes(target.as_bytes()),
            hex_b256(unknown_context_id.inner())
        );

        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_post_rating_appends_private_log_edge() {
        let (state, _tmp, _decider, _endorser, target, context_id) = setup_state().await;
        let app = Router::new()
            .route("/v1/ratings", post(post_rating))
            .with_state(state.clone());

        // Create a signer and corresponding rater address.
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let rater_addr = trustnet_core::Address::from_private_key(&signing_key);

        let created_at = "1970-01-01T00:16:40Z".to_string(); // 1000s

        let mut event = RatingEventV1 {
            ty: "trustnet.rating.v1".to_string(),
            rater: format!("0x{}", hex::encode(rater_addr.as_slice())),
            rater_pub_key: None,
            target: hex_bytes(target.as_bytes()),
            context_id: hex_b256(context_id.inner()),
            level: 2,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at.clone()),
            signature: String::new(),
        };

        // Sign canonical JCS of the unsigned event with EIP-191 message prefix.
        let unsigned = RatingEventUnsignedV1 {
            ty: event.ty.clone(),
            rater: event.rater.clone(),
            rater_pub_key: None,
            target: event.target.clone(),
            context_id: event.context_id.clone(),
            level: event.level,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at),
        };

        let unsigned_canonical = serde_jcs::to_vec(&unsigned).unwrap();
        let prehash = alloy_primitives::eip191_hash_message(&unsigned_canonical);
        let (sig, recid) = signing_key
            .sign_prehash_recoverable(prehash.as_slice())
            .unwrap();
        let primitive_sig = alloy_primitives::PrimitiveSignature::from((sig, recid));
        let sig_bytes: [u8; 65] = primitive_sig.into();
        event.signature = base64::engine::general_purpose::STANDARD.encode(sig_bytes);

        let body = serde_json::to_vec(&event).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ratings")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Ensure rows were appended.
        let raw_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges_raw")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(raw_count, 1);

        let latest_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM edges_latest WHERE source = 'private_log'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(latest_count, 1);
    }

    #[tokio::test]
    async fn test_post_rating_accepts_agentref_ed25519() {
        let (state, _tmp, _decider, _endorser, target, context_id) = setup_state().await;
        let app = Router::new()
            .route("/v1/ratings", post(post_rating))
            .with_state(state.clone());

        // Create an ed25519 signer and derive agentRef = sha256(pubkey).
        let signing_key = SigningKey::from_bytes(&[0x22u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();

        let agent_ref: [u8; 32] = Sha256::digest(pubkey_bytes).into();
        let rater = format!("agentRef:0x{}", hex::encode(agent_ref));

        let created_at = "1970-01-01T00:16:40Z".to_string(); // 1000s

        let mut event = RatingEventV1 {
            ty: "trustnet.rating.v1".to_string(),
            rater: rater.clone(),
            rater_pub_key: Some(base64::engine::general_purpose::STANDARD.encode(pubkey_bytes)),
            target: hex_bytes(target.as_bytes()),
            context_id: hex_b256(context_id.inner()),
            level: 2,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at.clone()),
            signature: String::new(),
        };

        let unsigned = RatingEventUnsignedV1 {
            ty: event.ty.clone(),
            rater: event.rater.clone(),
            rater_pub_key: event.rater_pub_key.clone(),
            target: event.target.clone(),
            context_id: event.context_id.clone(),
            level: event.level,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at),
        };

        let unsigned_canonical = serde_jcs::to_vec(&unsigned).unwrap();
        let sig = signing_key.sign(&unsigned_canonical);
        event.signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let body = serde_json::to_vec(&event).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ratings")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Ensure rows were appended.
        let raw_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges_raw")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(raw_count, 1);

        let latest_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM edges_latest WHERE source = 'private_log'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(latest_count, 1);
    }

    #[tokio::test]
    async fn test_post_rating_rejects_unknown_context_id() {
        let (state, _tmp, _decider, _endorser, target, _context_id) = setup_state().await;
        let app = Router::new()
            .route("/v1/ratings", post(post_rating))
            .with_state(state.clone());

        // Create a signer and corresponding rater address.
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let rater_addr = trustnet_core::Address::from_private_key(&signing_key);

        let created_at = "1970-01-01T00:16:40Z".to_string(); // 1000s
        let unknown_context_id = ContextId::from(B256::repeat_byte(0x99));

        let mut event = RatingEventV1 {
            ty: "trustnet.rating.v1".to_string(),
            rater: format!("0x{}", hex::encode(rater_addr.as_slice())),
            rater_pub_key: None,
            target: hex_bytes(target.as_bytes()),
            context_id: hex_b256(unknown_context_id.inner()),
            level: 2,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at.clone()),
            signature: String::new(),
        };

        let unsigned = RatingEventUnsignedV1 {
            ty: event.ty.clone(),
            rater: event.rater.clone(),
            rater_pub_key: None,
            target: event.target.clone(),
            context_id: event.context_id.clone(),
            level: event.level,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at),
        };

        let unsigned_canonical = serde_jcs::to_vec(&unsigned).unwrap();
        let prehash = alloy_primitives::eip191_hash_message(&unsigned_canonical);
        let (sig, recid) = signing_key
            .sign_prehash_recoverable(prehash.as_slice())
            .unwrap();
        let primitive_sig = alloy_primitives::PrimitiveSignature::from((sig, recid));
        let sig_bytes: [u8; 65] = primitive_sig.into();
        event.signature = base64::engine::general_purpose::STANDARD.encode(sig_bytes);

        let body = serde_json::to_vec(&event).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ratings")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let raw_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges_raw")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(raw_count, 0);
    }
}
