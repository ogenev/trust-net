use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use http_body_util::BodyExt;
use serde::Serialize;
use tempfile::TempDir;
use tower::ServiceExt;
use trustnet_api::server::{build_app, ApiRuntimeConfig};
use trustnet_core::{hashing::keccak256, Address, Level, PrincipalId, B256};
use trustnet_indexer::{
    server_root::{build_server_root, BuildServerRootInput},
    storage::{DeploymentMode, Storage},
};
use trustnet_verifier::{DecisionBundleV1Json, RootResponseV1};

#[derive(Debug, Serialize)]
struct RatingEventV1 {
    #[serde(rename = "type")]
    ty: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(rename = "observedAt", skip_serializing_if = "Option::is_none")]
    observed_at: Option<u64>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct RatingEventUnsignedV1 {
    #[serde(rename = "type")]
    ty: &'static str,
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

fn context_id_from_input(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.starts_with("0x") && trimmed.len() == 66 {
        let parsed = trimmed.parse::<B256>().expect("valid context bytes32");
        return format!("0x{}", hex::encode(parsed.as_slice()));
    }

    let hash = keccak256(trimmed.as_bytes());
    format!("0x{}", hex::encode(hash.as_slice()))
}

fn build_signed_rating_event(
    private_key: [u8; 32],
    target: &str,
    context: &str,
    level: i8,
) -> serde_json::Value {
    let _target_pid = target
        .parse::<PrincipalId>()
        .expect("target principal id should be valid");
    let _level = Level::new(level).expect("level should be valid");

    let signing_key = k256::ecdsa::SigningKey::from_slice(&private_key).expect("valid key");
    let rater_addr = Address::from_private_key(&signing_key);
    let rater = format!("0x{}", hex::encode(rater_addr.as_slice()));
    let context_id = context_id_from_input(context);
    let created_at = chrono::Utc::now().to_rfc3339();

    let unsigned = RatingEventUnsignedV1 {
        ty: "trustnet.rating.v1",
        source: None,
        rater: rater.clone(),
        rater_pub_key: None,
        target: target.to_string(),
        context_id: context_id.clone(),
        level,
        evidence_uri: None,
        evidence_hash: None,
        created_at: Some(created_at.clone()),
    };

    let unsigned_canonical = serde_jcs::to_vec(&unsigned).expect("canonicalize unsigned rating");
    let prehash = alloy_primitives::eip191_hash_message(&unsigned_canonical);
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(prehash.as_slice())
        .expect("sign rating");
    let primitive_sig = alloy_primitives::PrimitiveSignature::from((sig, recid));
    let sig_bytes: [u8; 65] = primitive_sig.into();

    let event = RatingEventV1 {
        ty: "trustnet.rating.v1",
        source: None,
        rater,
        rater_pub_key: None,
        target: target.to_string(),
        context_id,
        level,
        evidence_uri: None,
        evidence_hash: None,
        created_at: Some(created_at),
        observed_at: None,
        signature: base64::engine::general_purpose::STANDARD.encode(sig_bytes),
    };

    serde_json::to_value(event).expect("serialize rating")
}

async fn post_rating(app: &axum::Router, payload: &serde_json::Value) -> serde_json::Value {
    let body = serde_json::to_vec(payload).expect("serialize post payload");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ratings")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("POST /v1/ratings should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("decode post response")
}

#[tokio::test]
async fn server_mode_true_two_hop_smoke_flow_is_verifiable() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("trustnet-smoke.db");
    let db_url = format!("sqlite://{}", db_path.display());
    let cache_dir = temp.path().join("smm_cache");

    let storage = Storage::new(&db_url, None, None)
        .await
        .expect("storage connect");
    storage.run_migrations().await.expect("migrations");
    storage
        .enforce_deployment_mode(DeploymentMode::Server)
        .await
        .expect("set server deployment mode");

    let config = ApiRuntimeConfig::for_test(db_url.clone(), cache_dir.display().to_string());
    let app = build_app(&config).await.expect("build in-process app");

    let pk_decider = [0x11u8; 32];
    let pk_endorser = [0x22u8; 32];
    let target = "0x3333333333333333333333333333333333333333";
    let context = "trustnet:ctx:agent-collab:code-exec:v1";

    let payload_et = build_signed_rating_event(pk_endorser, target, context, 2);
    let endorser = payload_et["rater"]
        .as_str()
        .expect("endorser rater")
        .to_string();
    let context_id = payload_et["contextId"]
        .as_str()
        .expect("context id")
        .to_string();

    let payload_de = build_signed_rating_event(pk_decider, &endorser, context, 2);
    let decider = payload_de["rater"]
        .as_str()
        .expect("decider rater")
        .to_string();

    let first = post_rating(&app, &payload_de).await;
    assert_eq!(first["ok"], true);
    assert_eq!(first["serverSeq"], 1);

    let second = post_rating(&app, &payload_et).await;
    assert_eq!(second["ok"], true);
    assert_eq!(second["serverSeq"], 2);

    let root_result = build_server_root(&BuildServerRootInput {
        database_url: db_url,
        publisher_key: format!("0x{}", hex::encode(pk_decider)),
        stream_id: "server".to_string(),
        stream_hash: None,
        epoch: None,
        dry_run: false,
    })
    .await
    .expect("build and insert root");
    assert_eq!(root_result.epoch, 1);
    assert!(root_result.inserted);

    let root_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/root")
                .body(Body::empty())
                .expect("root request"),
        )
        .await
        .expect("GET /v1/root should succeed");
    assert_eq!(root_response.status(), StatusCode::OK);
    let root_body = root_response
        .into_body()
        .collect()
        .await
        .expect("root body")
        .to_bytes();
    let root: RootResponseV1 = serde_json::from_slice(&root_body).expect("parse root response");

    let decision_uri = format!(
        "/v1/decision?decider={}&target={}&contextId={}",
        decider, target, context_id
    );
    let decision_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(decision_uri)
                .body(Body::empty())
                .expect("decision request"),
        )
        .await
        .expect("GET /v1/decision should succeed");
    assert_eq!(decision_response.status(), StatusCode::OK);
    let decision_body = decision_response
        .into_body()
        .collect()
        .await
        .expect("decision body")
        .to_bytes();
    let decision_json: serde_json::Value =
        serde_json::from_slice(&decision_body).expect("parse decision response");

    assert_eq!(decision_json["decision"], "allow");
    let selected_endorser = decision_json["endorser"]
        .as_str()
        .expect("selected endorser");
    let selected_endorser_pid = selected_endorser
        .parse::<PrincipalId>()
        .expect("selected endorser pid");
    let expected_endorser_pid = endorser
        .parse::<PrincipalId>()
        .expect("expected endorser pid");
    assert_eq!(selected_endorser_pid, expected_endorser_pid);
    assert!(decision_json["proofs"]["DE"].is_object());
    assert!(decision_json["proofs"]["ET"].is_object());

    let bundle: DecisionBundleV1Json =
        serde_json::from_value(decision_json).expect("decision bundle parse");
    let publisher = decider.parse::<Address>().expect("publisher parse");
    trustnet_verifier::verify_decision_bundle(&root, &bundle, Some(publisher))
        .expect("verify decision bundle");
}
