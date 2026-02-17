use anyhow::Context;
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
use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc};
use tower_http::cors::CorsLayer;
use trustnet_core::{
    hashing::compute_edge_key, Address, ContextId, LeafValueV1, Level, PrincipalId, B256,
};
use trustnet_engine::{
    decide_with_evidence, CandidateEvidence, Decision, EvidencePolicy, Thresholds,
};
use trustnet_smm::Smm;

use crate::{db, smm_cache};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecisionPolicyResolved {
    thresholds: Thresholds,
    ttl_seconds: u64,
    require_evidence_et: bool,
    require_evidence_dt: bool,
}

#[derive(Debug, Clone)]
struct DecisionPolicy {
    default: DecisionPolicyResolved,
    by_context: HashMap<ContextId, DecisionPolicyResolved>,
}

impl DecisionPolicy {
    fn for_context(&self, context_id: &ContextId) -> DecisionPolicyResolved {
        self.by_context
            .get(context_id)
            .copied()
            .unwrap_or(self.default)
    }
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    smm_cache: Arc<smm_cache::SmmCache>,
    decision_policy: DecisionPolicy,
    trusted_responders: Vec<Address>,
    write_enabled: bool,
}

/// Runtime configuration for the TrustNet API server.
#[derive(Debug, Clone)]
pub struct ApiRuntimeConfig {
    database_url: String,
    port: u16,
    write_enabled: bool,
    cache_dir: String,
    decision_policy: DecisionPolicy,
    trusted_responders: Vec<Address>,
}

impl ApiRuntimeConfig {
    /// Build runtime configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
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

        let cache_dir =
            std::env::var("SMM_CACHE_DIR").unwrap_or_else(|_| "./smm_cache".to_string());

        Ok(Self {
            database_url,
            port,
            write_enabled,
            cache_dir,
            decision_policy: load_decision_policy_from_env()?,
            trusted_responders: load_trusted_responders_from_env()?,
        })
    }

    /// Build deterministic test configuration with default decision policy.
    pub fn for_test(database_url: impl Into<String>, cache_dir: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
            port: 0,
            write_enabled: true,
            cache_dir: cache_dir.into(),
            decision_policy: DecisionPolicy {
                default: DecisionPolicyResolved {
                    thresholds: Thresholds::new(2, 1).expect("valid default thresholds"),
                    ttl_seconds: 300,
                    require_evidence_et: false,
                    require_evidence_dt: false,
                },
                by_context: HashMap::new(),
            },
            trusted_responders: Vec::new(),
        }
    }
}

fn parse_env_i8(name: &str) -> anyhow::Result<Option<i8>> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(None);
    };
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "{} is set but empty", name);
    let v: i8 = raw
        .parse()
        .with_context(|| format!("Invalid {} (expected i8)", name))?;
    Ok(Some(v))
}

fn parse_env_u64(name: &str) -> anyhow::Result<Option<u64>> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(None);
    };
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "{} is set but empty", name);
    let v: u64 = raw
        .parse()
        .with_context(|| format!("Invalid {} (expected u64)", name))?;
    Ok(Some(v))
}

fn parse_env_bool(name: &str) -> anyhow::Result<Option<bool>> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(None);
    };
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "{} is set but empty", name);
    let normalized = raw.to_ascii_lowercase();
    let value = match normalized.as_str() {
        "1" | "true" | "yes" | "y" | "on" => true,
        "0" | "false" | "no" | "n" | "off" => false,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid {} (expected boolean-like value)",
                name
            ))
        }
    };
    Ok(Some(value))
}

fn load_trusted_responders_from_env() -> anyhow::Result<Vec<Address>> {
    let Ok(raw) = std::env::var("TRUSTNET_VERIFIED_RESPONDERS") else {
        return Ok(Vec::new());
    };

    let mut responders = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let addr = Address::from_str(trimmed)
            .with_context(|| format!("Invalid TRUSTNET_VERIFIED_RESPONDERS entry: {}", trimmed))?;
        responders.push(addr);
    }

    Ok(responders)
}

fn load_decision_policy_from_env() -> anyhow::Result<DecisionPolicy> {
    let allow = parse_env_i8("TRUSTNET_ALLOW_THRESHOLD")?.unwrap_or(2);
    let ask = parse_env_i8("TRUSTNET_ASK_THRESHOLD")?.unwrap_or(1);
    let default_thresholds = Thresholds::new(allow, ask)
        .map_err(|e| anyhow::anyhow!(e))
        .context("Invalid TRUSTNET_{ALLOW,ASK}_THRESHOLD")?;

    let default_ttl_seconds = parse_env_u64("TRUSTNET_DECISION_TTL_SECONDS")?.unwrap_or(300);
    let default_require_evidence_et =
        parse_env_bool("TRUSTNET_REQUIRE_EVIDENCE_ET")?.unwrap_or(false);
    let default_require_evidence_dt =
        parse_env_bool("TRUSTNET_REQUIRE_EVIDENCE_DT")?.unwrap_or(false);

    let default = DecisionPolicyResolved {
        thresholds: default_thresholds,
        ttl_seconds: default_ttl_seconds,
        require_evidence_et: default_require_evidence_et,
        require_evidence_dt: default_require_evidence_dt,
    };

    // Optional per-context overrides (MVP-friendly):
    // - TRUSTNET_ALLOW_THRESHOLD_<CONTEXT>
    // - TRUSTNET_ASK_THRESHOLD_<CONTEXT>
    // - TRUSTNET_DECISION_TTL_SECONDS_<CONTEXT>
    //
    // Context suffixes: GLOBAL, PAYMENTS, CODE_EXEC, WRITES, MESSAGING.
    let known_contexts = [
        ("GLOBAL", ContextId::from(trustnet_core::CTX_GLOBAL)),
        ("PAYMENTS", ContextId::from(trustnet_core::CTX_PAYMENTS)),
        ("CODE_EXEC", ContextId::from(trustnet_core::CTX_CODE_EXEC)),
        ("WRITES", ContextId::from(trustnet_core::CTX_WRITES)),
        ("MESSAGING", ContextId::from(trustnet_core::CTX_MESSAGING)),
    ];

    let mut by_context = HashMap::new();
    for (suffix, context_id) in known_contexts {
        let allow = parse_env_i8(&format!("TRUSTNET_ALLOW_THRESHOLD_{}", suffix))?
            .unwrap_or(default.thresholds.allow);
        let ask = parse_env_i8(&format!("TRUSTNET_ASK_THRESHOLD_{}", suffix))?
            .unwrap_or(default.thresholds.ask);
        let thresholds = Thresholds::new(allow, ask)
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| format!("Invalid thresholds for {}", suffix))?;

        let ttl_seconds = parse_env_u64(&format!("TRUSTNET_DECISION_TTL_SECONDS_{}", suffix))?
            .unwrap_or(default.ttl_seconds);

        let require_evidence_et =
            parse_env_bool(&format!("TRUSTNET_REQUIRE_EVIDENCE_ET_{}", suffix))?
                .unwrap_or(default.require_evidence_et);
        let require_evidence_dt =
            parse_env_bool(&format!("TRUSTNET_REQUIRE_EVIDENCE_DT_{}", suffix))?
                .unwrap_or(default.require_evidence_dt);

        let resolved = DecisionPolicyResolved {
            thresholds,
            ttl_seconds,
            require_evidence_et,
            require_evidence_dt,
        };

        if resolved != default {
            by_context.insert(context_id, resolved);
        }
    }

    Ok(DecisionPolicy {
        default,
        by_context,
    })
}

async fn build_state(config: &ApiRuntimeConfig) -> anyhow::Result<AppState> {
    let connect_options = SqliteConnectOptions::from_str(&config.database_url)?
        .read_only(!config.write_enabled)
        .create_if_missing(config.write_enabled);
    let db = SqlitePool::connect_with(connect_options).await?;

    Ok(AppState {
        db,
        smm_cache: Arc::new(smm_cache::SmmCache::new(&config.cache_dir)),
        decision_policy: config.decision_policy.clone(),
        trusted_responders: config.trusted_responders.clone(),
        write_enabled: config.write_enabled,
    })
}

async fn build_state_with_warmup(config: &ApiRuntimeConfig) -> anyhow::Result<AppState> {
    let state = build_state(config).await?;
    if let Ok(Some(epoch)) = db::get_latest_epoch(&state.db).await {
        let _ = ensure_smm_for_epoch(&state, &epoch).await;
    }
    Ok(state)
}

fn router_for_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/root", get(get_root))
        .route("/v1/contexts", get(get_contexts))
        .route("/v1/decision", get(get_decision))
        .route("/v1/proof", get(get_proof))
        .route("/v1/ratings", post(post_rating))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Build an in-process API router from explicit runtime config.
pub async fn build_app(config: &ApiRuntimeConfig) -> anyhow::Result<Router> {
    let state = build_state_with_warmup(config).await?;
    Ok(router_for_state(state))
}

/// Run the API server with explicit runtime configuration.
pub async fn run_with_config(config: ApiRuntimeConfig) -> anyhow::Result<()> {
    let state = build_state_with_warmup(&config).await?;
    let db_for_shutdown = state.db.clone();
    let app = router_for_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    println!("TrustNet API server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    db_for_shutdown.close().await;
    println!("TrustNet API server shutdown complete");
    Ok(())
}

/// Run the API server using environment-driven configuration.
pub async fn run_from_env() -> anyhow::Result<()> {
    run_with_config(ApiRuntimeConfig::from_env()?).await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            eprintln!("Failed to install Ctrl+C handler: {}", err);
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                eprintln!("Failed to install SIGTERM handler: {}", err);
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("Shutdown signal received");
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
            | trustnet_core::CTX_MESSAGING
    )
}

const ERROR_CODE_INVALID_REQUEST: &str = "invalid_request";
const ERROR_CODE_UNKNOWN_CONTEXT: &str = "unknown_context";
const ERROR_CODE_ROOT_UNAVAILABLE: &str = "root_unavailable";
const ERROR_CODE_PROOF_UNAVAILABLE: &str = "proof_unavailable";
const ERROR_CODE_INVALID_SIGNATURE: &str = "invalid_signature";
const ERROR_CODE_INTERNAL_ERROR: &str = "internal_error";

#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorInfo,
}

#[derive(Serialize)]
struct ErrorInfo {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: ErrorInfo {
                code,
                message: message.into(),
                details: None,
            },
        }),
    )
}

fn api_error_details(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    details: serde_json::Value,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: ErrorInfo {
                code,
                message: message.into(),
                details: Some(details),
            },
        }),
    )
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(StatusCode::BAD_REQUEST, ERROR_CODE_INVALID_REQUEST, msg)
}

fn unknown_context(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error_details(
        StatusCode::BAD_REQUEST,
        ERROR_CODE_UNKNOWN_CONTEXT,
        msg,
        serde_json::json!({ "field": "contextId" }),
    )
}

fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(StatusCode::FORBIDDEN, ERROR_CODE_INVALID_REQUEST, msg)
}

fn not_found(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(StatusCode::NOT_FOUND, ERROR_CODE_ROOT_UNAVAILABLE, msg)
}

fn conflict(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(StatusCode::CONFLICT, ERROR_CODE_INVALID_REQUEST, msg)
}

fn root_unavailable(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        ERROR_CODE_ROOT_UNAVAILABLE,
        msg,
    )
}

fn proof_unavailable(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        ERROR_CODE_PROOF_UNAVAILABLE,
        msg,
    )
}

fn invalid_signature(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(StatusCode::BAD_REQUEST, ERROR_CODE_INVALID_SIGNATURE, msg)
}

fn service_unavailable(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        ERROR_CODE_INTERNAL_ERROR,
        msg,
    )
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, Json<ErrorResponse>) {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        ERROR_CODE_INTERNAL_ERROR,
        format!("Internal error: {}", err),
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
    if *id == trustnet_core::CTX_MESSAGING {
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

async fn has_verified_evidence(
    state: &AppState,
    evidence_hash: &B256,
) -> Result<bool, (StatusCode, Json<ErrorResponse>)> {
    if *evidence_hash == B256::ZERO {
        return Ok(false);
    }

    db::has_verified_feedback_for_hash(
        &state.db,
        evidence_hash.as_slice(),
        &state.trusted_responders,
    )
    .await
    .map_err(internal_error)
}

fn hex_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_b256(v: &B256) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}

fn bitmap_compress_siblings(
    siblings: &[B256],
    default_hashes: &[B256; 257],
) -> anyhow::Result<(String, Vec<String>)> {
    anyhow::ensure!(
        siblings.len() == 256,
        "proof siblings must have 256 entries (got {})",
        siblings.len()
    );

    let mut bitmap = [0u8; 32];
    let mut packed = Vec::new();

    for (i, sibling) in siblings.iter().enumerate() {
        let default_sibling = default_hashes[255 - i];
        if *sibling != default_sibling {
            bitmap[i / 8] |= 1 << (7 - (i % 8));
            packed.push(hex_b256(sibling));
        }
    }

    Ok((hex_bytes(&bitmap), packed))
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
        .ok_or_else(|| root_unavailable("Epoch missing created_at_u64 (v0.4 required)"))?
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
            return Err(proof_unavailable(
                "Proofs unavailable: edges_latest does not match published root",
            ));
        }
    }

    let smm = state
        .smm_cache
        .get()
        .await
        .ok_or_else(|| proof_unavailable("SMM not available"))?;

    if smm.root() != published_root {
        return Err(proof_unavailable(
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
    #[serde(rename = "manifestHash")]
    manifest_hash: String,
    #[serde(rename = "publisherSig")]
    publisher_sig: String,
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
    let manifest_hash_bytes = epoch
        .manifest_hash
        .as_deref()
        .ok_or_else(|| root_unavailable("Epoch missing manifestHash (v0.4 required)"))?;
    if manifest_hash_bytes.len() != 32 {
        return Err(root_unavailable(format!(
            "Epoch has invalid manifestHash length (expected 32, got {})",
            manifest_hash_bytes.len()
        )));
    }
    let manifest_hash = hex_bytes(manifest_hash_bytes);

    let publisher_sig_bytes = epoch
        .publisher_sig
        .as_deref()
        .ok_or_else(|| root_unavailable("Epoch missing publisherSig (v0.4 required)"))?;
    if publisher_sig_bytes.len() != 65 {
        return Err(root_unavailable(format!(
            "Epoch has invalid publisherSig length (expected 65, got {})",
            publisher_sig_bytes.len()
        )));
    }
    let publisher_sig = hex_bytes(publisher_sig_bytes);

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
        manifest_uri: epoch.manifest_uri,
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
                name: "trustnet:ctx:messaging:v1".to_string(),
                context_id: hex_b256(&trustnet_core::CTX_MESSAGING),
                description: "Messaging context".to_string(),
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
    #[serde(rename = "evidenceVerified", skip_serializing_if = "Option::is_none")]
    evidence_verified: Option<bool>,
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
    #[serde(rename = "requireEvidenceForPositiveET")]
    require_evidence_for_positive_et: bool,
    #[serde(rename = "requireEvidenceForPositiveDT")]
    require_evidence_for_positive_dt: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    bitmap: Option<String>,
    siblings: Vec<String>,
    format: &'static str,
}

fn leaf_value_json_from_v1(v: &LeafValueV1, evidence_verified: Option<bool>) -> LeafValueJson {
    LeafValueJson {
        level: v.level.value(),
        updated_at: v.updated_at_u64,
        evidence_hash: hex_b256(&v.evidence_hash),
        evidence_verified,
    }
}

fn smm_proof_v1_json(
    proof: &trustnet_smm::SmmProof,
    rater: Option<&PrincipalId>,
    target: Option<&PrincipalId>,
    context_id: Option<&ContextId>,
    default_hashes: &[B256; 257],
) -> Result<SmmProofV1Json, (StatusCode, Json<ErrorResponse>)> {
    let leaf_value = if proof.is_membership {
        let decoded =
            LeafValueV1::decode(&proof.leaf_value).map_err(|e| bad_request(e.to_string()))?;
        Some(leaf_value_json_from_v1(&decoded, None))
    } else {
        None
    };
    let (bitmap, siblings) = bitmap_compress_siblings(&proof.siblings, default_hashes)
        .map_err(|e| internal_error(e.to_string()))?;

    Ok(SmmProofV1Json {
        ty: "trustnet.smmProof.v1",
        edge_key: hex_b256(&proof.key),
        context_id: context_id.map(|c| hex_b256(c.inner())),
        rater: rater.map(|p| hex_bytes(p.as_bytes())),
        target: target.map(|p| hex_bytes(p.as_bytes())),
        is_membership: proof.is_membership,
        leaf_value,
        bitmap: Some(bitmap),
        siblings,
        format: "bitmap",
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
    et_evidence_verified: Option<bool>,
    et_has_evidence: bool,
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
        return Err(unknown_context("Unknown contextId"));
    }

    let epoch = db::get_latest_epoch(&state.db)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found("No epochs published"))?;

    let published_root = parse_b256(&epoch.graph_root).map_err(internal_error)?;
    let manifest_hash = epoch
        .manifest_hash
        .as_deref()
        .ok_or_else(|| root_unavailable("Epoch missing manifestHash (v0.4 required)"))?;
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

    let policy = state.decision_policy.for_context(&context_id);

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

        let et_evidence_verified = if policy.require_evidence_et
            && leaf_et.level.value() > 0
            && leaf_et.evidence_hash != B256::ZERO
        {
            Some(has_verified_evidence(&state, &leaf_et.evidence_hash).await?)
        } else if policy.require_evidence_et {
            Some(false)
        } else {
            None
        };

        let et_has_evidence = et_evidence_verified.unwrap_or(leaf_et.evidence_hash != B256::ZERO);

        candidates.push(CandidateMaterial {
            endorser,
            proof_de,
            proof_et,
            leaf_de,
            leaf_et,
            et_evidence_verified,
            et_has_evidence,
        });
    }
    let engine_candidates: Vec<CandidateEvidence> = candidates
        .iter()
        .map(|c| CandidateEvidence {
            endorser: c.endorser,
            level_de: c.leaf_de.level,
            level_et: c.leaf_et.level,
            et_has_evidence: c.et_has_evidence,
        })
        .collect();

    let evidence_policy = EvidencePolicy {
        require_positive_et_evidence: policy.require_evidence_et,
        require_positive_dt_evidence: policy.require_evidence_dt,
    };
    let dt_evidence_verified = if policy.require_evidence_dt
        && dt_leaf.level.value() > 0
        && dt_leaf.evidence_hash != B256::ZERO
    {
        Some(has_verified_evidence(&state, &dt_leaf.evidence_hash).await?)
    } else if policy.require_evidence_dt {
        Some(false)
    } else {
        None
    };
    let dt_has_evidence = dt_evidence_verified.unwrap_or(dt_leaf.evidence_hash != B256::ZERO);
    let result = decide_with_evidence(
        policy.thresholds,
        evidence_policy,
        dt_leaf.level,
        dt_has_evidence,
        &engine_candidates,
    );

    let (chosen_proof_de, chosen_proof_et, leaf_de, leaf_et, et_evidence_verified) =
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
                    smm.default_hashes(),
                )?),
                Some(smm_proof_v1_json(
                    &chosen.proof_et,
                    Some(&endorser),
                    Some(&target),
                    Some(&context_id),
                    smm.default_hashes(),
                )?),
                chosen.leaf_de,
                chosen.leaf_et,
                chosen.et_evidence_verified,
            )
        } else {
            (
                None,
                None,
                LeafValueV1::default_neutral(),
                LeafValueV1::default_neutral(),
                if policy.require_evidence_et {
                    Some(false)
                } else {
                    None
                },
            )
        };

    let dt = smm_proof_v1_json(
        &dt_proof,
        Some(&decider),
        Some(&target),
        Some(&context_id),
        smm.default_hashes(),
    )?;

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
            allow: policy.thresholds.allow,
            ask: policy.thresholds.ask,
        },
        endorser: result.endorser.map(|p| hex_bytes(p.as_bytes())),
        why: WhyJson {
            edge_de: leaf_value_json_from_v1(&leaf_de, None),
            edge_et: leaf_value_json_from_v1(&leaf_et, et_evidence_verified),
            edge_dt: leaf_value_json_from_v1(&dt_leaf, dt_evidence_verified),
        },
        constraints: ConstraintsJson {
            ttl_seconds: policy.ttl_seconds,
            require_evidence_for_positive_et: policy.require_evidence_et,
            require_evidence_for_positive_dt: policy.require_evidence_dt,
        },
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
    Ok(Json(smm_proof_v1_json(
        &proof,
        None,
        None,
        None,
        smm.default_hashes(),
    )?))
}

#[derive(Debug, Deserialize, Serialize)]
struct RatingEventV1 {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
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
    #[serde(
        rename = "observedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    observed_at: Option<u64>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct RatingEventUnsignedV1 {
    #[serde(rename = "type")]
    ty: String,
    #[serde(rename = "source", skip_serializing_if = "Option::is_none")]
    source: Option<String>,
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

    if let Some(source) = &event.source {
        if source.to_lowercase() != "private_log" {
            return Err(bad_request("Invalid source (expected private_log)"));
        }
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
        return Err(unknown_context("Unknown contextId"));
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
        source: event.source.clone(),
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
    let sig_bytes =
        decode_binary_field("signature", &event.signature).map_err(invalid_signature)?;

    if let Some(expected) = rater.to_evm_address_opt() {
        let signature =
            alloy_primitives::PrimitiveSignature::from_raw(&sig_bytes).map_err(|e| {
                invalid_signature(format!(
                    "Invalid signature bytes (expected 65 bytes): {}",
                    e
                ))
            })?;

        let recovered = signature
            .recover_address_from_msg(&unsigned_canonical)
            .map_err(|e| invalid_signature(format!("Invalid signature: {}", e)))?;

        if recovered != expected {
            return Err(invalid_signature("Signature does not match rater"));
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
            return Err(invalid_signature("raterPubKey does not match agentRef"));
        }

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| bad_request(format!("Invalid raterPubKey: {}", e)))?;
        let signature = Ed25519Signature::from_slice(&sig_bytes)
            .map_err(|e| invalid_signature(format!("Invalid ed25519 signature: {}", e)))?;

        verifying_key
            .verify_strict(&unsigned_canonical, &signature)
            .map_err(|_| invalid_signature("Invalid signature"))?;
    }

    let event_json = String::from_utf8(serde_jcs::to_vec(&event).map_err(internal_error)?)
        .map_err(internal_error)?;

    let mut tx = state.db.begin().await.map_err(internal_error)?;

    // Hard guardrail (spec §9.3 MVP simplification): do not mix chain + private-log ingestion in one DB.
    //
    // First successful writer claims the DB's mode; subsequent mismatched writers are rejected.
    sqlx::query(
        r#"
        INSERT INTO deployment_mode (id, mode)
        VALUES (1, 'server')
        ON CONFLICT(id) DO NOTHING
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        service_unavailable(format!(
            "Failed to claim deployment_mode (run migrations?): {}",
            e
        ))
    })?;

    let current_mode: Option<String> =
        sqlx::query_scalar("SELECT mode FROM deployment_mode WHERE id = 1")
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal_error)?;

    let Some(current_mode) = current_mode else {
        return Err(internal_error("deployment_mode missing row (id=1)"));
    };

    if current_mode != "server" {
        return Err(conflict(
            "DB is configured for chain mode; use a separate DB for server ingestion",
        ));
    }

    // Append immutable raw event (auditable).
    let result = sqlx::query(
        r#"
        INSERT INTO edges_raw (
            rater_pid, target_pid, context_id,
            level_i8, updated_at_u64, evidence_hash, evidence_uri,
            source,
            observed_at_u64,
            subject_id,
            chain_id, block_number, tx_index, log_index, tx_hash,
            server_seq,
            event_json, signature
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'private_log', ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)
        "#,
    )
    .bind(rater.as_bytes().as_slice())
    .bind(target.as_bytes().as_slice())
    .bind(context_id.as_bytes().as_slice())
    .bind(level.value() as i32)
    .bind(created_at_u64 as i64)
    .bind(evidence_hash.as_slice())
    .bind(event.evidence_uri.as_deref())
    .bind(0i64)
    .bind(&event_json)
    .bind(&sig_bytes)
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;

    let server_seq = result.last_insert_rowid();

    // Store the server seq on the raw row for easy reproduction via seq windows.
    sqlx::query("UPDATE edges_raw SET server_seq = ?, observed_at_u64 = ? WHERE id = ?")
        .bind(server_seq)
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
            level_i8, updated_at_u64, evidence_hash, evidence_uri, source,
            observed_at_u64,
            subject_id,
            chain_id, block_number, tx_index, log_index, tx_hash,
            server_seq
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'private_log', ?, NULL, NULL, NULL, NULL, NULL, NULL, ?)
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
    .bind(rater.as_bytes().as_slice())
    .bind(target.as_bytes().as_slice())
    .bind(context_id.as_bytes().as_slice())
    .bind(level.value() as i32)
    .bind(created_at_u64 as i64)
    .bind(evidence_hash.as_slice())
    .bind(event.evidence_uri.as_deref())
    .bind(server_seq)
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
    use trustnet_engine::{CandidateEvidence, EvidencePolicy};
    use trustnet_verifier::{DecisionBundleV1Json, RootResponseV1};

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
                manifest_uri TEXT,
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
            CREATE TABLE deployment_mode (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                mode TEXT NOT NULL CHECK (mode IN ('server', 'chain')),
                set_at INTEGER NOT NULL DEFAULT (unixepoch())
            ) STRICT;

            CREATE TABLE edges_raw (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rater_pid BLOB NOT NULL,
                target_pid BLOB NOT NULL,
                context_id BLOB NOT NULL,
                level_i8 INTEGER NOT NULL,
                updated_at_u64 INTEGER NOT NULL,
                evidence_hash BLOB NOT NULL,
                evidence_uri TEXT,
                source TEXT NOT NULL,
                observed_at_u64 INTEGER NOT NULL DEFAULT 0,
                subject_id BLOB,
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
                evidence_uri TEXT,
                source TEXT NOT NULL,
                observed_at_u64 INTEGER NOT NULL DEFAULT 0,
                subject_id BLOB,
                chain_id INTEGER,
                block_number INTEGER,
                tx_index INTEGER,
                log_index INTEGER,
                tx_hash BLOB,
                server_seq INTEGER,
                PRIMARY KEY (rater_pid, target_pid, context_id)
            );

            CREATE TABLE feedback_raw (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL,
                erc8004_reputation BLOB NOT NULL,
                erc8004_identity BLOB,
                agent_id BLOB NOT NULL,
                client_address BLOB NOT NULL,
                feedback_index BLOB NOT NULL,
                value_u256 BLOB NOT NULL,
                value_decimals INTEGER NOT NULL,
                tag1 TEXT NOT NULL,
                tag2 TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                feedback_uri TEXT,
                feedback_hash BLOB NOT NULL,
                subject_id BLOB,
                observed_at_u64 INTEGER NOT NULL,
                block_number INTEGER,
                tx_index INTEGER,
                log_index INTEGER,
                tx_hash BLOB
            );

            CREATE TABLE feedback_responses_raw (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL,
                erc8004_reputation BLOB NOT NULL,
                agent_id BLOB NOT NULL,
                client_address BLOB NOT NULL,
                feedback_index BLOB NOT NULL,
                responder BLOB NOT NULL,
                response_uri TEXT,
                response_hash BLOB NOT NULL,
                observed_at_u64 INTEGER NOT NULL,
                block_number INTEGER,
                tx_index INTEGER,
                log_index INTEGER,
                tx_hash BLOB
            );

            CREATE TABLE feedback_verified (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL,
                erc8004_reputation BLOB NOT NULL,
                agent_id BLOB NOT NULL,
                client_address BLOB NOT NULL,
                feedback_index BLOB NOT NULL,
                responder BLOB NOT NULL,
                response_hash BLOB NOT NULL,
                observed_at_u64 INTEGER NOT NULL
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
        let evidence_hash_de = [0u8; 32];
        let evidence_hash_et = [0x11u8; 32];
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
        .bind(evidence_hash_de.as_slice())
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
        .bind(evidence_hash_et.as_slice())
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
            INSERT INTO epochs (epoch, graph_root, edge_count, manifest_json, manifest_uri, manifest_hash, publisher_sig, created_at_u64)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(1i64)
        .bind(graph_root.as_slice())
        .bind(2i64)
        .bind(r#"{"specVersion":"trustnet-spec-0.6"}"#)
        .bind("https://cdn.example.com/trustnet/manifests/epoch-1.json")
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
            decision_policy: DecisionPolicy {
                default: DecisionPolicyResolved {
                    thresholds: Thresholds::new(2, 1).unwrap(),
                    ttl_seconds: 300,
                    require_evidence_et: false,
                    require_evidence_dt: false,
                },
                by_context: HashMap::new(),
            },
            trusted_responders: Vec::new(),
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
    async fn test_get_root_includes_manifest_hash_and_publisher_sig() {
        let (state, _tmp, _decider, _endorser, _target, _context_id) = setup_state().await;
        let app = Router::new()
            .route("/v1/root", get(get_root))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["manifestUri"],
            "https://cdn.example.com/trustnet/manifests/epoch-1.json"
        );
        assert_eq!(json["manifestHash"], format!("0x{}", "aa".repeat(32)));
        assert_eq!(json["publisherSig"], format!("0x{}", "11".repeat(65)));
    }

    #[tokio::test]
    async fn test_get_root_rejects_missing_manifest_hash() {
        let (state, _tmp, _decider, _endorser, _target, _context_id) = setup_state().await;
        sqlx::query("UPDATE epochs SET manifest_hash = NULL")
            .execute(&state.db)
            .await
            .unwrap();

        let app = Router::new()
            .route("/v1/root", get(get_root))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_get_root_rejects_missing_publisher_sig() {
        let (state, _tmp, _decider, _endorser, _target, _context_id) = setup_state().await;
        sqlx::query("UPDATE epochs SET publisher_sig = NULL")
            .execute(&state.db)
            .await
            .unwrap();

        let app = Router::new()
            .route("/v1/root", get(get_root))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
            let format = p["format"].as_str().unwrap();
            let siblings = match format {
                "uncompressed" => p["siblings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap().parse::<B256>().unwrap())
                    .collect(),
                "bitmap" => {
                    let bitmap_hex = p["bitmap"].as_str().expect("bitmap proof missing bitmap");
                    let bitmap_raw =
                        hex::decode(bitmap_hex.trim_start_matches("0x")).expect("invalid bitmap");
                    assert_eq!(bitmap_raw.len(), 32);
                    let mut bitmap = [0u8; 32];
                    bitmap.copy_from_slice(&bitmap_raw);

                    let packed: Vec<B256> = p["siblings"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s.as_str().unwrap().parse::<B256>().unwrap())
                        .collect();

                    let empty_smm = trustnet_smm::SmmBuilder::new().build();
                    let default_hashes = empty_smm.default_hashes();
                    let mut packed_idx = 0usize;
                    let mut expanded = Vec::with_capacity(256);

                    for i in 0..256 {
                        let bit_set = (bitmap[i / 8] & (1 << (7 - (i % 8)))) != 0;
                        if bit_set {
                            expanded.push(
                                *packed
                                    .get(packed_idx)
                                    .expect("bitmap set bit without packed sibling"),
                            );
                            packed_idx += 1;
                        } else {
                            expanded.push(default_hashes[255 - i]);
                        }
                    }

                    assert_eq!(
                        packed_idx,
                        packed.len(),
                        "unused packed siblings left after bitmap expansion"
                    );
                    expanded
                }
                other => panic!("unsupported proof format in test: {}", other),
            };
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

        assert_eq!(json["proofs"]["DT"]["type"], "trustnet.smmProof.v1");
        assert_eq!(json["proofs"]["DT"]["format"], "bitmap");
        assert!(json["proofs"]["DT"]["bitmap"].is_string());

        let ttl_seconds = json["constraints"]["ttlSeconds"].as_u64().unwrap();
        let require_et = json["constraints"]["requireEvidenceForPositiveET"]
            .as_bool()
            .unwrap();
        let require_dt = json["constraints"]["requireEvidenceForPositiveDT"]
            .as_bool()
            .unwrap();
        assert_eq!(ttl_seconds, 300);
        assert!(!require_et);
        assert!(!require_dt);

        // Verify decision score rule locally (gateway behavior).
        let l_dt = json["why"]["edgeDT"]["level"].as_i64().unwrap() as i8;
        let l_de = json["why"]["edgeDE"]["level"].as_i64().unwrap() as i8;
        let l_et = json["why"]["edgeET"]["level"].as_i64().unwrap() as i8;

        let thresholds = Thresholds::new(
            json["thresholds"]["allow"].as_i64().unwrap() as i8,
            json["thresholds"]["ask"].as_i64().unwrap() as i8,
        )
        .unwrap();

        let dt_evidence = json["why"]["edgeDT"]["evidenceHash"]
            .as_str()
            .unwrap()
            .parse::<B256>()
            .unwrap();
        let et_evidence = json["why"]["edgeET"]["evidenceHash"]
            .as_str()
            .unwrap()
            .parse::<B256>()
            .unwrap();
        let dt_evidence_verified = json["why"]["edgeDT"]["evidenceVerified"].as_bool();
        let et_evidence_verified = json["why"]["edgeET"]["evidenceVerified"].as_bool();

        let dt_has_evidence = dt_evidence_verified.unwrap_or(dt_evidence != B256::ZERO);
        let et_has_evidence = et_evidence_verified.unwrap_or(et_evidence != B256::ZERO);

        let mut candidates = Vec::new();
        if json["endorser"].is_string() {
            candidates.push(CandidateEvidence {
                endorser,
                level_de: Level::new(l_de).unwrap(),
                level_et: Level::new(l_et).unwrap(),
                et_has_evidence,
            });
        }

        let evidence_policy = EvidencePolicy {
            require_positive_et_evidence: require_et,
            require_positive_dt_evidence: require_dt,
        };
        let result = trustnet_engine::decide_with_evidence(
            thresholds,
            evidence_policy,
            Level::new(l_dt).unwrap(),
            dt_has_evidence,
            &candidates,
        );

        assert_eq!(json["score"].as_i64().unwrap() as i8, result.score);
        assert_eq!(json["decision"].as_str().unwrap(), result.decision.as_str());
    }

    #[tokio::test]
    async fn test_decision_bundle_applies_evidence_gating() {
        let (mut state, _tmp, decider, _endorser, target, context_id) = setup_state().await;
        state.decision_policy.default.require_evidence_et = true;

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

        assert_eq!(json["decision"], "deny");
        assert!(json["endorser"].is_null());
        assert!(json["proofs"]["DE"].is_null());
        assert!(json["proofs"]["ET"].is_null());
        assert_eq!(json["score"].as_i64().unwrap() as i8, 0);
        assert_eq!(json["why"]["edgeDE"]["level"].as_i64().unwrap(), 0);
        assert_eq!(json["why"]["edgeET"]["level"].as_i64().unwrap(), 0);
        assert_eq!(
            json["why"]["edgeET"]["evidenceVerified"].as_bool(),
            Some(false)
        );

        assert_eq!(json["constraints"]["requireEvidenceForPositiveET"], true);
        assert_eq!(json["constraints"]["requireEvidenceForPositiveDT"], false);
    }

    #[tokio::test]
    async fn test_decision_bundle_accepts_verified_evidence_stamp() {
        let (mut state, _tmp, decider, endorser, target, context_id) = setup_state().await;
        state.decision_policy.default.require_evidence_et = true;

        let evidence_hash: Vec<u8> = sqlx::query_scalar(
            r#"
            SELECT evidence_hash
            FROM edges_latest
            WHERE rater_pid = ? AND target_pid = ? AND context_id = ?
            "#,
        )
        .bind(endorser.as_bytes().as_slice())
        .bind(target.as_bytes().as_slice())
        .bind(context_id.as_bytes().as_slice())
        .fetch_one(&state.db)
        .await
        .unwrap();

        let agent_id = [0x01u8; 32];
        let client_address = [0x02u8; 20];
        let feedback_index = [0x03u8; 32];
        let reputation = [0x04u8; 20];

        sqlx::query(
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
            "#,
        )
        .bind(1i64)
        .bind(reputation.as_slice())
        .bind(None::<&[u8]>)
        .bind(agent_id.as_slice())
        .bind(client_address.as_slice())
        .bind(feedback_index.as_slice())
        .bind([0u8; 32].as_slice())
        .bind(0i64)
        .bind("trustnet:ctx:payments:v1")
        .bind("trustnet:v1")
        .bind("trustnet")
        .bind(None::<&str>)
        .bind(evidence_hash.as_slice())
        .bind(None::<&[u8]>)
        .bind(42i64)
        .bind(None::<i64>)
        .bind(None::<i64>)
        .bind(None::<i64>)
        .bind(None::<&[u8]>)
        .execute(&state.db)
        .await
        .unwrap();

        let responder = [0x05u8; 20];
        let response_hash = [0x06u8; 32];
        sqlx::query(
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
            "#,
        )
        .bind(1i64)
        .bind(reputation.as_slice())
        .bind(agent_id.as_slice())
        .bind(client_address.as_slice())
        .bind(feedback_index.as_slice())
        .bind(responder.as_slice())
        .bind(response_hash.as_slice())
        .bind(43i64)
        .execute(&state.db)
        .await
        .unwrap();

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
        assert_eq!(
            json["why"]["edgeET"]["evidenceVerified"].as_bool(),
            Some(true)
        );
    }

    #[tokio::test]
    async fn test_decision_bundle_verifies_with_verifier() {
        let (state, _tmp, decider, _endorser, target, context_id) = setup_state().await;

        let graph_root_bytes: Vec<u8> =
            sqlx::query_scalar("SELECT graph_root FROM epochs WHERE epoch = 1")
                .fetch_one(&state.db)
                .await
                .unwrap();
        let graph_root = B256::from_slice(&graph_root_bytes);

        let manifest_value = serde_json::json!({ "specVersion": "trustnet-spec-0.6" });
        let canonical = serde_jcs::to_vec(&manifest_value).unwrap();
        let manifest_hash = trustnet_core::hashing::keccak256(&canonical);

        let publisher_key = [0x42u8; 32];
        let signing_key = k256::ecdsa::SigningKey::from_bytes((&publisher_key).into()).unwrap();
        let publisher_addr = trustnet_core::Address::from_private_key(&signing_key);

        let digest =
            trustnet_core::hashing::compute_root_signature_hash(1, &graph_root, &manifest_hash);
        let (sig, recid) = signing_key
            .sign_prehash_recoverable(digest.as_slice())
            .unwrap();
        let sig = alloy_primitives::PrimitiveSignature::from((sig, recid));
        let sig_bytes: [u8; 65] = sig.into();

        let manifest_json = String::from_utf8(canonical).unwrap();
        sqlx::query(
            "UPDATE epochs SET manifest_json = ?, manifest_hash = ?, publisher_sig = ? WHERE epoch = 1",
        )
        .bind(manifest_json)
        .bind(manifest_hash.as_slice())
        .bind(sig_bytes.as_slice())
        .execute(&state.db)
        .await
        .unwrap();

        let app_root = Router::new()
            .route("/v1/root", get(get_root))
            .with_state(state.clone());
        let app_decision = Router::new()
            .route("/v1/decision", get(get_decision))
            .with_state(state);

        let root_response = app_root
            .oneshot(
                Request::builder()
                    .uri("/v1/root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(root_response.status(), StatusCode::OK);
        let root_body = root_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let root_json: serde_json::Value = serde_json::from_slice(&root_body).unwrap();
        let root: RootResponseV1 = serde_json::from_value(root_json).unwrap();

        let uri = format!(
            "/v1/decision?decider={}&target={}&contextId={}",
            hex_bytes(decider.as_bytes()),
            hex_bytes(target.as_bytes()),
            hex_b256(context_id.inner())
        );
        let decision_response = app_decision
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(decision_response.status(), StatusCode::OK);
        let decision_body = decision_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let decision_json: serde_json::Value = serde_json::from_slice(&decision_body).unwrap();
        let bundle: DecisionBundleV1Json = serde_json::from_value(decision_json).unwrap();

        trustnet_verifier::verify_decision_bundle(&root, &bundle, Some(publisher_addr)).unwrap();
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
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "unknown_context");
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
            source: None,
            rater: format!("0x{}", hex::encode(rater_addr.as_slice())),
            rater_pub_key: None,
            target: hex_bytes(target.as_bytes()),
            context_id: hex_b256(context_id.inner()),
            level: 2,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at.clone()),
            observed_at: None,
            signature: String::new(),
        };

        // Sign canonical JCS of the unsigned event with EIP-191 message prefix.
        let unsigned = RatingEventUnsignedV1 {
            ty: event.ty.clone(),
            source: None,
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
            source: None,
            rater: rater.clone(),
            rater_pub_key: Some(base64::engine::general_purpose::STANDARD.encode(pubkey_bytes)),
            target: hex_bytes(target.as_bytes()),
            context_id: hex_b256(context_id.inner()),
            level: 2,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at.clone()),
            observed_at: None,
            signature: String::new(),
        };

        let unsigned = RatingEventUnsignedV1 {
            ty: event.ty.clone(),
            source: None,
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
            source: None,
            rater: format!("0x{}", hex::encode(rater_addr.as_slice())),
            rater_pub_key: None,
            target: hex_bytes(target.as_bytes()),
            context_id: hex_b256(unknown_context_id.inner()),
            level: 2,
            evidence_uri: None,
            evidence_hash: None,
            created_at: Some(created_at.clone()),
            observed_at: None,
            signature: String::new(),
        };

        let unsigned = RatingEventUnsignedV1 {
            ty: event.ty.clone(),
            source: None,
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
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "unknown_context");

        let raw_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges_raw")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(raw_count, 0);
    }
}
