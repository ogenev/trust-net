#[tokio::main]
async fn main() -> anyhow::Result<()> {
    trustnet_api::server::run_from_env().await
}
