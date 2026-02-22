use alloy::primitives::{Address as AlloyAddress, B256, U256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use anyhow::Context;
use clap::Args;
use std::path::PathBuf;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract RootRegistry {
        function currentEpoch() external view returns (uint256);
        function getRootAt(uint256 epoch) external view returns (bytes32);
        function getManifestHashAt(uint256 epoch) external view returns (bytes32);
    }
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Path to /v1/root JSON
    #[arg(long)]
    root: PathBuf,
    /// Path to /v1/score JSON
    #[arg(long)]
    bundle: PathBuf,
    /// Expected publisher EVM address (0x...)
    #[arg(long)]
    publisher: Option<String>,
    /// RPC URL for on-chain RootRegistry cross-check.
    #[arg(long, requires = "root_registry")]
    rpc_url: Option<String>,
    /// RootRegistry contract address for on-chain cross-check.
    #[arg(long, requires = "rpc_url")]
    root_registry: Option<String>,
    /// Epoch to check on-chain (defaults to root.epoch).
    #[arg(long, requires_all = ["rpc_url", "root_registry"])]
    epoch: Option<u64>,
}

#[derive(Debug, Args)]
pub struct ReceiptArgs {
    /// Path to /v1/root JSON
    #[arg(long)]
    root: PathBuf,
    /// Path to /v1/score JSON
    #[arg(long)]
    bundle: PathBuf,
    /// Expected publisher EVM address (0x...)
    #[arg(long)]
    publisher: Option<String>,
    /// Tool name (e.g. "payments.send")
    #[arg(long)]
    tool: String,
    /// Path to tool args JSON (hashed into argsHash)
    #[arg(long)]
    args: PathBuf,
    /// Path to tool result JSON (hashed into resultHash)
    #[arg(long)]
    result: Option<PathBuf>,
    /// Error string (alternative to --result)
    #[arg(long)]
    error: Option<String>,
    /// Optional policy manifest hash (bytes32 hex)
    #[arg(long)]
    policy_manifest_hash: Option<String>,
    /// Receipt signer private key (32-byte hex). Also supports env TRUSTNET_RECEIPT_SIGNER_KEY.
    #[arg(long)]
    signer_key: Option<String>,
    /// Output file path (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VerifyReceiptArgs {
    /// Path to ActionReceipt JSON
    #[arg(long)]
    receipt: PathBuf,
    /// Expected root publisher EVM address (0x...)
    #[arg(long)]
    publisher: Option<String>,
    /// Expected receipt signer EVM address (0x...)
    #[arg(long)]
    signer: Option<String>,
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(path: &PathBuf) -> anyhow::Result<T> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn parse_hex_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    Ok(<[u8; 32]>::try_from(bytes.as_slice())?)
}

fn keccak256_jcs_file(path: &PathBuf) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let canonical = serde_jcs::to_vec(&value)?;
    let hash = trustnet_core::hashing::keccak256(&canonical);
    Ok(format!("0x{}", hex::encode(hash.as_slice())))
}

fn keccak256_jcs_value(value: &serde_json::Value) -> anyhow::Result<String> {
    let canonical = serde_jcs::to_vec(value)?;
    let hash = trustnet_core::hashing::keccak256(&canonical);
    Ok(format!("0x{}", hex::encode(hash.as_slice())))
}

fn resolve_chain_anchor_epoch(
    root_epoch: u64,
    bundle_epoch: u64,
    epoch_override: Option<u64>,
) -> anyhow::Result<u64> {
    anyhow::ensure!(
        root_epoch == bundle_epoch,
        "root/bundle epoch mismatch before chain anchor check (root={}, bundle={})",
        root_epoch,
        bundle_epoch
    );

    if let Some(epoch) = epoch_override {
        anyhow::ensure!(
            epoch == root_epoch,
            "--epoch ({}) must match root/bundle epoch ({})",
            epoch,
            root_epoch
        );
        Ok(epoch)
    } else {
        Ok(root_epoch)
    }
}

async fn verify_root_anchor_onchain(
    root: &trustnet_verifier::RootResponseV1,
    bundle: &trustnet_verifier::ScoreBundleV1Json,
    rpc_url: &str,
    root_registry: &str,
    epoch_override: Option<u64>,
) -> anyhow::Result<()> {
    let epoch = resolve_chain_anchor_epoch(root.epoch, bundle.epoch, epoch_override)?;
    let graph_root = root.graph_root.parse::<B256>()?;
    let manifest_hash = root
        .manifest_hash
        .as_deref()
        .context("root.manifestHash missing (required for on-chain root check)")?
        .parse::<B256>()?;
    let registry_addr = root_registry
        .parse::<AlloyAddress>()
        .with_context(|| format!("invalid --root-registry address: {}", root_registry))?;

    let provider = ProviderBuilder::new().on_http(
        rpc_url
            .parse()
            .with_context(|| format!("invalid --rpc-url: {}", rpc_url))?,
    );
    let registry = RootRegistry::new(registry_addr, provider);

    let current_epoch_u256 = registry
        .currentEpoch()
        .call()
        .await
        .context("failed to query RootRegistry.currentEpoch()")?
        ._0;
    let current_epoch: u64 = current_epoch_u256.try_into().map_err(|_| {
        anyhow::anyhow!(
            "RootRegistry.currentEpoch too large: {}",
            current_epoch_u256
        )
    })?;

    anyhow::ensure!(
        current_epoch >= epoch,
        "RootRegistry currentEpoch ({}) is behind requested epoch ({})",
        current_epoch,
        epoch
    );

    let onchain_root = registry
        .getRootAt(U256::from(epoch))
        .call()
        .await
        .context("failed to query RootRegistry.getRootAt()")?
        ._0;
    anyhow::ensure!(
        onchain_root != B256::ZERO,
        "RootRegistry has no root for epoch {}",
        epoch
    );

    let onchain_manifest_hash = registry
        .getManifestHashAt(U256::from(epoch))
        .call()
        .await
        .context("failed to query RootRegistry.getManifestHashAt()")?
        ._0;
    anyhow::ensure!(
        onchain_manifest_hash != B256::ZERO,
        "RootRegistry has no manifest hash for epoch {}",
        epoch
    );

    anyhow::ensure!(
        onchain_root == graph_root,
        "graphRoot mismatch against RootRegistry at epoch {}",
        epoch
    );
    anyhow::ensure!(
        onchain_manifest_hash == manifest_hash,
        "manifestHash mismatch against RootRegistry at epoch {}",
        epoch
    );

    Ok(())
}

pub async fn run_verify(args: VerifyArgs) -> anyhow::Result<()> {
    let root: trustnet_verifier::RootResponseV1 = read_json(&args.root)?;
    let bundle: trustnet_verifier::ScoreBundleV1Json = read_json(&args.bundle)?;

    let publisher_addr = match args.publisher {
        Some(s) => Some(s.parse::<trustnet_core::Address>()?),
        None => None,
    };

    if let (Some(rpc_url), Some(root_registry)) = (&args.rpc_url, &args.root_registry) {
        verify_root_anchor_onchain(&root, &bundle, rpc_url, root_registry, args.epoch).await?;
    }

    trustnet_verifier::verify_score_bundle(&root, &bundle, publisher_addr)?;
    println!("OK");
    Ok(())
}

pub fn run_receipt(args: ReceiptArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.result.is_some() ^ args.error.is_some(),
        "provide exactly one of --result or --error"
    );

    let root_value: serde_json::Value = read_json(&args.root)?;
    let bundle_value: serde_json::Value = read_json(&args.bundle)?;

    let root_parsed: trustnet_verifier::RootResponseV1 =
        serde_json::from_value(root_value.clone())?;
    let bundle_parsed: trustnet_verifier::ScoreBundleV1Json =
        serde_json::from_value(bundle_value.clone())?;

    let publisher_addr = match args.publisher {
        Some(s) => Some(s.parse::<trustnet_core::Address>()?),
        None => None,
    };
    trustnet_verifier::verify_score_bundle(&root_parsed, &bundle_parsed, publisher_addr)?;

    let args_hash = keccak256_jcs_file(&args.args)?;
    let result_hash = match (args.result, args.error) {
        (Some(path), None) => keccak256_jcs_file(&path)?,
        (None, Some(msg)) => {
            let v = serde_json::json!({ "error": msg });
            keccak256_jcs_value(&v)?
        }
        _ => unreachable!(),
    };

    let created_at = chrono::Utc::now().to_rfc3339();
    let unsigned = trustnet_verifier::ActionReceiptUnsignedV1 {
        ty: "trustnet.actionReceipt.v1".to_string(),
        created_at,
        tool: args.tool,
        args_hash,
        result_hash,
        root: root_value,
        score_bundle: bundle_value,
        policy_manifest_hash: args.policy_manifest_hash,
    };

    let signer_key = args
        .signer_key
        .or_else(|| std::env::var("TRUSTNET_RECEIPT_SIGNER_KEY").ok())
        .context("missing --signer-key and env TRUSTNET_RECEIPT_SIGNER_KEY")?;
    let key_bytes = parse_hex_32(&signer_key)?;

    let receipt = trustnet_verifier::sign_action_receipt_v1(unsigned, &key_bytes)?;

    // Best-effort self-check.
    let expected_signer = Some(receipt.signer.parse::<trustnet_core::Address>()?);
    trustnet_verifier::verify_action_receipt_v1(&receipt, publisher_addr, expected_signer)?;

    let json = serde_json::to_string_pretty(&receipt)?;
    if let Some(path) = args.out {
        std::fs::write(path, json)?;
    } else {
        println!("{}", json);
    }

    Ok(())
}

pub fn run_verify_receipt(args: VerifyReceiptArgs) -> anyhow::Result<()> {
    let receipt: trustnet_verifier::ActionReceiptV1 = read_json(&args.receipt)?;
    let publisher_addr = match args.publisher {
        Some(s) => Some(s.parse::<trustnet_core::Address>()?),
        None => None,
    };
    let signer_addr = match args.signer {
        Some(s) => Some(s.parse::<trustnet_core::Address>()?),
        None => None,
    };
    trustnet_verifier::verify_action_receipt_v1(&receipt, publisher_addr, signer_addr)?;
    println!("OK");
    Ok(())
}

pub fn run_vectors() -> anyhow::Result<()> {
    let vectors = trustnet_verifier::generate_vectors_v1_1();
    println!("{}", serde_json::to_string_pretty(&vectors)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_chain_anchor_epoch;

    #[test]
    fn resolve_chain_anchor_epoch_defaults_to_root_epoch() {
        let epoch = resolve_chain_anchor_epoch(7, 7, None).expect("resolve epoch");
        assert_eq!(epoch, 7);
    }

    #[test]
    fn resolve_chain_anchor_epoch_accepts_matching_override() {
        let epoch = resolve_chain_anchor_epoch(3, 3, Some(3)).expect("resolve epoch");
        assert_eq!(epoch, 3);
    }

    #[test]
    fn resolve_chain_anchor_epoch_rejects_mismatch_override() {
        let err = resolve_chain_anchor_epoch(4, 4, Some(5)).expect_err("expected mismatch");
        assert!(err.to_string().contains("--epoch"));
    }

    #[test]
    fn resolve_chain_anchor_epoch_rejects_root_bundle_mismatch() {
        let err = resolve_chain_anchor_epoch(2, 3, None).expect_err("expected mismatch");
        assert!(err.to_string().contains("root/bundle epoch mismatch"));
    }
}
