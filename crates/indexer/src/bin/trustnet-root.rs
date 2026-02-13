//! Build and publish a server-mode root to the local database.

use alloy::signers::Signer;
use anyhow::{Context, Result};
use clap::Parser;
use trustnet_core::hashing::{compute_edge_key, compute_root_signature_hash, keccak256};
use trustnet_core::LeafValueV1;
use trustnet_indexer::root_manifest::{build_server_root_manifest_v1, canonicalize_manifest};
use trustnet_indexer::storage::{DeploymentMode, EdgeRecord, EpochRecord, Storage};
use trustnet_smm::SmmBuilder;

#[derive(Debug, Parser)]
#[command(name = "trustnet-root", about = "Build server-mode root from DB")]
struct Args {
    /// Database URL (e.g. sqlite://trustnet.db)
    #[arg(long, default_value = "sqlite://trustnet.db")]
    database_url: String,

    /// Publisher private key (32-byte hex, with or without 0x)
    #[arg(long)]
    publisher_key: String,

    /// Stream identifier for server mode
    #[arg(long, default_value = "server")]
    stream_id: String,

    /// Optional stream hash (0x-bytes32). Defaults to zero.
    #[arg(long)]
    stream_hash: Option<String>,

    /// Override epoch number (must be > latest). Defaults to latest + 1.
    #[arg(long)]
    epoch: Option<u64>,

    /// Do not insert epoch; just print root + manifest summary.
    #[arg(long)]
    dry_run: bool,
}

fn edge_is_expired(edge: &EdgeRecord, as_of_u64: u64) -> bool {
    let ttl_seconds = trustnet_indexer::root_manifest::ttl_seconds_for_context_id(&edge.context_id);
    if ttl_seconds == 0 {
        return false;
    }

    if edge.updated_at_u64 == 0 {
        return true;
    }

    edge.updated_at_u64.saturating_add(ttl_seconds) < as_of_u64
}

async fn server_seq_range(storage: &Storage) -> Result<(u64, u64)> {
    let row: (Option<i64>, Option<i64>) = sqlx::query_as(
        r#"
        SELECT MIN(server_seq), MAX(server_seq)
        FROM edges_raw
        WHERE source = 'private_log'
        "#,
    )
    .fetch_one(storage.pool())
    .await
    .context("Failed to query server_seq range")?;

    let min = row.0.unwrap_or(0).max(0) as u64;
    let max = row.1.unwrap_or(0).max(0) as u64;
    Ok((min, max))
}

fn parse_b256(input: &str) -> Result<alloy::primitives::B256> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32-byte hex");
    Ok(alloy::primitives::B256::from_slice(&bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let storage = Storage::new(&args.database_url, None, None)
        .await
        .context("Failed to connect to database")?;
    storage
        .run_migrations()
        .await
        .context("Failed to run migrations")?;
    storage
        .enforce_deployment_mode(DeploymentMode::Server)
        .await
        .context("Database is not configured for server deployment mode")?;

    let now_u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let mut edges = storage
        .get_all_edges_latest()
        .await
        .context("Failed to fetch edges_latest")?;

    edges.retain(|edge| edge.level.value() != 0);
    edges.retain(|edge| !edge_is_expired(edge, now_u64));
    edges.sort_by_key(|edge| compute_edge_key(&edge.rater, &edge.target, &edge.context_id));

    let mut builder = SmmBuilder::new();
    for edge in &edges {
        let key = compute_edge_key(&edge.rater, &edge.target, &edge.context_id);
        let leaf_value = LeafValueV1 {
            level: edge.level,
            updated_at_u64: edge.updated_at_u64,
            evidence_hash: edge.evidence_hash,
        }
        .encode()
        .to_vec();
        builder
            .insert(key, leaf_value)
            .context("Failed to insert edge into SMM builder")?;
    }

    let smm = builder.build();
    let root = smm.root();
    let edge_count = edges.len() as u64;

    let latest_epoch = storage.get_latest_epoch().await?;
    let next_epoch = latest_epoch.as_ref().map(|e| e.epoch + 1).unwrap_or(1);
    let epoch = args.epoch.unwrap_or(next_epoch);
    if epoch <= latest_epoch.as_ref().map(|e| e.epoch).unwrap_or(0) {
        anyhow::bail!("epoch {} must be greater than latest", epoch);
    }

    let (from_seq, to_seq) = server_seq_range(&storage).await?;
    let stream_hash = match args.stream_hash.as_deref() {
        Some(value) => Some(parse_b256(value)?),
        None => None,
    };

    let created_at = chrono::Utc::now().to_rfc3339();
    let manifest = build_server_root_manifest_v1(
        epoch,
        &root,
        args.stream_id.clone(),
        from_seq,
        to_seq,
        stream_hash,
        created_at,
    );

    let canonical = canonicalize_manifest(&manifest);
    let manifest_hash = keccak256(&canonical);

    let signer = args
        .publisher_key
        .trim_start_matches("0x")
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .context("Failed to parse publisher key")?;

    let digest = compute_root_signature_hash(epoch, &root, &manifest_hash);
    let signature = signer
        .sign_hash(&digest)
        .await
        .context("Failed to sign root digest")?;

    let epoch_record = EpochRecord {
        epoch,
        graph_root: root,
        published_at_block: 0,
        published_at: now_u64 as i64,
        tx_hash: None,
        edge_count,
        manifest_json: Some(String::from_utf8(canonical).context("Manifest must be valid UTF-8")?),
        manifest_hash: Some(manifest_hash),
        publisher_sig: Some(signature.as_bytes().to_vec()),
        created_at_u64: Some(now_u64),
    };

    if args.dry_run {
        println!("epoch: {}", epoch_record.epoch);
        println!("graphRoot: 0x{}", hex::encode(epoch_record.graph_root));
        println!("edgeCount: {}", epoch_record.edge_count);
        println!(
            "manifestHash: 0x{}",
            hex::encode(epoch_record.manifest_hash.unwrap_or_default())
        );
        println!(
            "publisherSig: 0x{}",
            hex::encode(epoch_record.publisher_sig.unwrap_or_default())
        );
        println!("fromSeq: {}", from_seq);
        println!("toSeq: {}", to_seq);
        return Ok(());
    }

    storage
        .insert_epoch(&epoch_record)
        .await
        .context("Failed to insert epoch")?;

    println!(
        "Inserted epoch {} (root=0x{})",
        epoch,
        hex::encode(epoch_record.graph_root)
    );

    Ok(())
}
