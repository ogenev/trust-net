//! RPC provider wrapper for Ethereum communication.

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use alloy::transports::http::{Client, Http};
use anyhow::{Context, Result};

use super::events::{NewFeedback, NewFeedbackEvent};

/// HTTP RPC provider for querying Ethereum.
#[derive(Clone)]
pub struct RpcProvider {
    provider: RootProvider<Http<Client>>,
    erc8004_address: Address,
}

impl RpcProvider {
    /// Create a new RPC provider.
    pub async fn new(rpc_url: &str, erc8004_address: Address) -> Result<Self> {
        let url = rpc_url
            .parse()
            .with_context(|| format!("Invalid RPC URL: {}", rpc_url))?;

        let provider = ProviderBuilder::new().on_http(url);

        Ok(Self {
            provider,
            erc8004_address,
        })
    }

    /// Get the latest block number.
    pub async fn get_block_number(&self) -> Result<u64> {
        self.provider
            .get_block_number()
            .await
            .context("Failed to get block number")
    }

    /// Get NewFeedback event logs for a block range.
    pub async fn get_logs(&self, from_block: u64, to_block: u64) -> Result<Vec<NewFeedbackEvent>> {
        // Create filter for NewFeedback events
        let filter = Filter::new()
            .address(self.erc8004_address)
            .event_signature(NewFeedback::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        // Fetch logs
        let logs: Vec<Log> = self
            .provider
            .get_logs(&filter)
            .await
            .context("Failed to fetch logs from RPC")?;

        // Parse logs into events
        let mut events = Vec::new();
        for log in &logs {
            match NewFeedbackEvent::from_log(log) {
                Ok(event) => events.push(event),
                Err(e) => {
                    // Log parsing error but continue processing other events
                    tracing::warn!("Failed to parse NewFeedback event: {}", e);
                }
            }
        }

        Ok(events)
    }
}
