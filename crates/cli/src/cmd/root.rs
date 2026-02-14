use anyhow::Result;
use clap::Args;
use trustnet_indexer::server_root::{build_server_root, BuildServerRootInput};

#[derive(Debug, Args)]
pub struct RootArgs {
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

pub async fn run(args: RootArgs) -> Result<()> {
    let output = build_server_root(&BuildServerRootInput {
        database_url: args.database_url,
        publisher_key: args.publisher_key,
        stream_id: args.stream_id,
        stream_hash: args.stream_hash,
        epoch: args.epoch,
        dry_run: args.dry_run,
    })
    .await?;

    if output.inserted {
        println!(
            "Inserted epoch {} (root=0x{})",
            output.epoch,
            hex::encode(output.graph_root)
        );
    } else {
        println!("epoch: {}", output.epoch);
        println!("graphRoot: 0x{}", hex::encode(output.graph_root));
        println!("edgeCount: {}", output.edge_count);
        println!("manifestHash: 0x{}", hex::encode(output.manifest_hash));
        println!("publisherSig: 0x{}", hex::encode(output.publisher_sig));
        println!("fromSeq: {}", output.from_seq);
        println!("toSeq: {}", output.to_seq);
    }

    Ok(())
}
