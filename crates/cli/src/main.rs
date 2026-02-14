use anyhow::Result;
use clap::{Parser, Subcommand};

mod cmd;

#[derive(Debug, Parser)]
#[command(name = "trustnet")]
#[command(about = "Unified TrustNet operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build server-mode root from DB and optionally insert it.
    Root(cmd::root::RootArgs),
    /// Sign a trustnet.rating.v1 payload.
    Rate(cmd::rate::RateArgs),
    /// Verify a DecisionBundle against a Root bundle.
    Verify(cmd::verify::VerifyArgs),
    /// Create and sign an ActionReceipt bundle.
    Receipt(cmd::verify::ReceiptArgs),
    /// Verify a signed ActionReceipt bundle.
    VerifyReceipt(cmd::verify::VerifyReceiptArgs),
    /// Print deterministic v0.6 hashing vectors as JSON.
    Vectors,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Root(args) => cmd::root::run(args).await?,
        Command::Rate(args) => cmd::rate::run(args)?,
        Command::Verify(args) => cmd::verify::run_verify(args)?,
        Command::Receipt(args) => cmd::verify::run_receipt(args)?,
        Command::VerifyReceipt(args) => cmd::verify::run_verify_receipt(args)?,
        Command::Vectors => cmd::verify::run_vectors()?,
    }

    Ok(())
}
