//! Minimal helper to sign a trustnet.rating.v1 for server-mode ingestion.

use alloy_primitives::{eip191_hash_message, B256};
use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use k256::ecdsa::SigningKey;
use serde::Serialize;
use std::str::FromStr;
use trustnet_core::hashing::keccak256;
use trustnet_core::types::{Level, PrincipalId};

#[derive(Debug, Parser)]
#[command(name = "trustnet-rate", about = "Sign a trustnet.rating.v1 payload")]
struct Args {
    /// Private key (32-byte hex, with or without 0x)
    #[arg(long)]
    private_key: String,

    /// Target principal id (0x-address, 0x-bytes32, or agentRef:...)
    #[arg(long)]
    target: String,

    /// Context id or canonical context string.
    /// If not 0x-bytes32, keccak256(context) is used.
    #[arg(long)]
    context: String,

    /// Trust level (-2..+2)
    #[arg(long)]
    level: i8,

    /// RFC3339 createdAt timestamp (defaults to now)
    #[arg(long)]
    created_at: Option<String>,

    /// Optional evidence URI
    #[arg(long)]
    evidence_uri: Option<String>,

    /// Optional evidence hash (0x-bytes32)
    #[arg(long)]
    evidence_hash: Option<String>,

    /// Optional source field (must be private_log if set)
    #[arg(long)]
    source: Option<String>,

    /// Emit compact JSON (default: pretty)
    #[arg(long)]
    compact: bool,
}

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

fn parse_hex_bytes32(input: &str) -> Result<B256> {
    let value = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(value).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32-byte hex");
    Ok(B256::from_slice(&bytes))
}

fn context_id_from_input(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.starts_with("0x") && trimmed.len() == 66 {
        parse_hex_bytes32(trimmed).context("invalid contextId")?;
        return Ok(trimmed.to_string());
    }

    let hash = keccak256(trimmed.as_bytes());
    Ok(format!("0x{}", hex::encode(hash.as_slice())))
}

fn parse_private_key(input: &str) -> Result<[u8; 32]> {
    let value = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(value).context("invalid private key hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32-byte private key");
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid private key length"))
}

fn ensure_rfc3339(value: &str) -> Result<()> {
    chrono::DateTime::parse_from_rfc3339(value).context("invalid createdAt (RFC3339)")?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(source) = args.source.as_deref() {
        anyhow::ensure!(
            source == "private_log",
            "source must be \"private_log\" if set"
        );
    }

    let level = Level::new(args.level).context("level out of range (-2..+2)")?;

    PrincipalId::from_str(&args.target).context("invalid target")?;

    let context_id = context_id_from_input(&args.context)?;

    let created_at = match args.created_at.as_deref() {
        Some(value) => {
            ensure_rfc3339(value)?;
            Some(value.to_string())
        }
        None => Some(chrono::Utc::now().to_rfc3339()),
    };

    let evidence_hash = match args.evidence_hash.as_deref() {
        Some(value) => {
            parse_hex_bytes32(value).context("invalid evidenceHash")?;
            Some(value.to_string())
        }
        None => None,
    };

    let key_bytes = parse_private_key(&args.private_key)?;
    let signing_key = SigningKey::from_slice(&key_bytes).context("invalid private key")?;

    let rater_addr = trustnet_core::Address::from_private_key(&signing_key);
    let rater = format!("0x{}", hex::encode(rater_addr.as_slice()));

    let unsigned = RatingEventUnsignedV1 {
        ty: "trustnet.rating.v1",
        source: args.source.clone(),
        rater: rater.clone(),
        rater_pub_key: None,
        target: args.target.clone(),
        context_id: context_id.clone(),
        level: level.value(),
        evidence_uri: args.evidence_uri.clone(),
        evidence_hash: evidence_hash.clone(),
        created_at: created_at.clone(),
    };

    let unsigned_canonical = serde_jcs::to_vec(&unsigned).context("failed to canonicalize")?;
    let prehash = eip191_hash_message(&unsigned_canonical);
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(prehash.as_slice())
        .context("failed to sign")?;
    let primitive_sig = alloy_primitives::PrimitiveSignature::from((sig, recid));
    let sig_bytes: [u8; 65] = primitive_sig.into();
    let signature = base64::engine::general_purpose::STANDARD.encode(sig_bytes);

    let event = RatingEventV1 {
        ty: "trustnet.rating.v1",
        source: args.source,
        rater,
        rater_pub_key: None,
        target: args.target,
        context_id,
        level: level.value(),
        evidence_uri: args.evidence_uri,
        evidence_hash,
        created_at,
        observed_at: None,
        signature,
    };

    if args.compact {
        println!(
            "{}",
            serde_json::to_string(&event).context("failed to serialize")?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&event).context("failed to serialize")?
        );
    }

    Ok(())
}
