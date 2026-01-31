//! RPC provider wrapper for Ethereum communication.

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use alloy::transports::http::{Client, Http};
use anyhow::{Context, Result};

use super::events::{EdgeRated, EdgeRatedEvent, NewFeedback, NewFeedbackEvent};

/// HTTP RPC provider for querying Ethereum.
#[derive(Clone)]
pub struct RpcProvider {
    provider: RootProvider<Http<Client>>,
    trust_graph_address: Address,
    erc8004_address: Address,
}

/// A supported chain event emitted by on-chain sources.
#[derive(Debug, Clone)]
pub enum ChainEvent {
    /// TrustGraph EdgeRated event.
    TrustGraph(EdgeRatedEvent),
    /// ERC-8004 Reputation NewFeedback event.
    Erc8004(NewFeedbackEvent),
}

impl RpcProvider {
    /// Create a new RPC provider.
    pub async fn new(
        rpc_url: &str,
        trust_graph_address: Address,
        erc8004_address: Address,
    ) -> Result<Self> {
        let url = rpc_url
            .parse()
            .with_context(|| format!("Invalid RPC URL: {}", rpc_url))?;

        let provider = ProviderBuilder::new().on_http(url);

        Ok(Self {
            provider,
            trust_graph_address,
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

    /// Get TrustGraph + ERC-8004 event logs for a block range.
    pub async fn get_logs(&self, from_block: u64, to_block: u64) -> Result<Vec<ChainEvent>> {
        let filter_trust_graph = Filter::new()
            .address(self.trust_graph_address)
            .event_signature(EdgeRated::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let filter_erc8004 = Filter::new()
            .address(self.erc8004_address)
            .event_signature(NewFeedback::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let (logs_trust_graph, logs_erc8004): (Vec<Log>, Vec<Log>) = tokio::try_join!(
            self.provider.get_logs(&filter_trust_graph),
            self.provider.get_logs(&filter_erc8004)
        )
        .context("Failed to fetch logs from RPC")?;

        let mut events = Vec::new();

        for log in &logs_trust_graph {
            match EdgeRatedEvent::from_log(log) {
                Ok(event) => events.push(ChainEvent::TrustGraph(event)),
                Err(e) => tracing::warn!("Failed to parse EdgeRated event: {}", e),
            }
        }

        for log in &logs_erc8004 {
            match NewFeedbackEvent::from_log(log) {
                Ok(event) => events.push(ChainEvent::Erc8004(event)),
                Err(e) => tracing::warn!("Failed to parse NewFeedback event: {}", e),
            }
        }

        // Sort by block coordinates for stable processing.
        events.sort_by_key(|e| match e {
            ChainEvent::TrustGraph(ev) => (ev.block_number, ev.tx_index, ev.log_index),
            ChainEvent::Erc8004(ev) => (ev.block_number, ev.tx_index, ev.log_index),
        });

        Ok(events)
    }

    /// Get block timestamp (unix seconds) for a block number.
    pub async fn get_block_timestamp(&self, block_number: u64) -> Result<u64> {
        use alloy::rpc::types::{BlockNumberOrTag, BlockTransactionsKind};

        let block = self
            .provider
            .get_block_by_number(
                BlockNumberOrTag::Number(block_number),
                BlockTransactionsKind::Hashes,
            )
            .await
            .context("Failed to fetch block")?
            .ok_or_else(|| anyhow::anyhow!("Block not found: {}", block_number))?;

        Ok(block.header.timestamp)
    }
}
