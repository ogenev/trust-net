use anyhow::Context;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Path to /v1/root JSON
    #[arg(long)]
    root: PathBuf,
    /// Path to /v1/decision JSON
    #[arg(long)]
    bundle: PathBuf,
    /// Expected publisher EVM address (0x...)
    #[arg(long)]
    publisher: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReceiptArgs {
    /// Path to /v1/root JSON
    #[arg(long)]
    root: PathBuf,
    /// Path to /v1/decision JSON
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

pub fn run_verify(args: VerifyArgs) -> anyhow::Result<()> {
    let root: trustnet_verifier::RootResponseV1 = read_json(&args.root)?;
    let bundle: trustnet_verifier::DecisionBundleV1Json = read_json(&args.bundle)?;

    let publisher_addr = match args.publisher {
        Some(s) => Some(s.parse::<trustnet_core::Address>()?),
        None => None,
    };

    trustnet_verifier::verify_decision_bundle(&root, &bundle, publisher_addr)?;
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
    let bundle_parsed: trustnet_verifier::DecisionBundleV1Json =
        serde_json::from_value(bundle_value.clone())?;

    let publisher_addr = match args.publisher {
        Some(s) => Some(s.parse::<trustnet_core::Address>()?),
        None => None,
    };
    trustnet_verifier::verify_decision_bundle(&root_parsed, &bundle_parsed, publisher_addr)?;

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
        decision_bundle: bundle_value,
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
    let vectors = trustnet_verifier::generate_vectors_v0_6();
    println!("{}", serde_json::to_string_pretty(&vectors)?);
    Ok(())
}
