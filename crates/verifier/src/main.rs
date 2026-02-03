use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "trustnet-verify")]
#[command(about = "Offline verification utilities for TrustNet v0.6", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a DecisionBundle against a Root bundle (server mode signature).
    Verify {
        /// Path to /v1/root JSON
        #[arg(long)]
        root: PathBuf,
        /// Path to /v1/decision JSON
        #[arg(long)]
        bundle: PathBuf,
        /// Expected publisher EVM address (0x...)
        #[arg(long)]
        publisher: Option<String>,
    },

    /// Create a signed ActionReceipt bundle (gateway audit artifact).
    Receipt {
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
    },

    /// Verify a signed ActionReceipt (includes verifying embedded decision bundle).
    VerifyReceipt {
        /// Path to ActionReceipt JSON
        #[arg(long)]
        receipt: PathBuf,
        /// Expected root publisher EVM address (0x...)
        #[arg(long)]
        publisher: Option<String>,
        /// Expected receipt signer EVM address (0x...)
        #[arg(long)]
        signer: Option<String>,
    },

    /// Print deterministic v0.6 hashing vectors as JSON.
    Vectors,
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Verify {
            root,
            bundle,
            publisher,
        } => {
            let root: trustnet_verifier::RootResponseV1 = read_json(&root)?;
            let bundle: trustnet_verifier::DecisionBundleV1Json = read_json(&bundle)?;

            let publisher_addr = match publisher {
                Some(s) => Some(s.parse::<trustnet_core::Address>()?),
                None => None,
            };

            trustnet_verifier::verify_decision_bundle(&root, &bundle, publisher_addr)?;
            println!("OK");
        }

        Command::Receipt {
            root,
            bundle,
            publisher,
            tool,
            args,
            result,
            error,
            policy_manifest_hash,
            signer_key,
            out,
        } => {
            anyhow::ensure!(
                result.is_some() ^ error.is_some(),
                "provide exactly one of --result or --error"
            );

            let root_value: serde_json::Value = read_json(&root)?;
            let bundle_value: serde_json::Value = read_json(&bundle)?;

            let root_parsed: trustnet_verifier::RootResponseV1 =
                serde_json::from_value(root_value.clone())?;
            let bundle_parsed: trustnet_verifier::DecisionBundleV1Json =
                serde_json::from_value(bundle_value.clone())?;

            let publisher_addr = match publisher {
                Some(s) => Some(s.parse::<trustnet_core::Address>()?),
                None => None,
            };
            trustnet_verifier::verify_decision_bundle(
                &root_parsed,
                &bundle_parsed,
                publisher_addr,
            )?;

            let args_hash = keccak256_jcs_file(&args)?;
            let result_hash = match (result, error) {
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
                tool,
                args_hash,
                result_hash,
                root: root_value,
                decision_bundle: bundle_value,
                policy_manifest_hash,
            };

            let signer_key = signer_key
                .or_else(|| std::env::var("TRUSTNET_RECEIPT_SIGNER_KEY").ok())
                .context("missing --signer-key and env TRUSTNET_RECEIPT_SIGNER_KEY")?;
            let key_bytes = parse_hex_32(&signer_key)?;

            let receipt = trustnet_verifier::sign_action_receipt_v1(unsigned, &key_bytes)?;

            // Best-effort self-check.
            let expected_signer = Some(receipt.signer.parse::<trustnet_core::Address>()?);
            trustnet_verifier::verify_action_receipt_v1(&receipt, publisher_addr, expected_signer)?;

            let json = serde_json::to_string_pretty(&receipt)?;
            if let Some(path) = out {
                std::fs::write(path, json)?;
            } else {
                println!("{}", json);
            }
        }

        Command::VerifyReceipt {
            receipt,
            publisher,
            signer,
        } => {
            let receipt: trustnet_verifier::ActionReceiptV1 = read_json(&receipt)?;
            let publisher_addr = match publisher {
                Some(s) => Some(s.parse::<trustnet_core::Address>()?),
                None => None,
            };
            let signer_addr = match signer {
                Some(s) => Some(s.parse::<trustnet_core::Address>()?),
                None => None,
            };
            trustnet_verifier::verify_action_receipt_v1(&receipt, publisher_addr, signer_addr)?;
            println!("OK");
        }

        Command::Vectors => {
            let vectors = trustnet_verifier::generate_vectors_v0_6();
            println!("{}", serde_json::to_string_pretty(&vectors)?);
        }
    }

    Ok(())
}
