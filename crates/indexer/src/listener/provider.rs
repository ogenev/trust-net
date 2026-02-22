//! RPC provider wrapper for Ethereum communication.

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{BlockId, BlockNumberOrTag, Filter, Log};
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::transports::http::{Client, Http};
use anyhow::{Context, Result};

use super::events::{
    EdgeRated, EdgeRatedEvent, FeedbackRevoked, FeedbackRevokedEvent, NewFeedback,
    NewFeedbackEvent, ResponseAppended, ResponseAppendedEvent,
};

sol! {
    /// ERC-8004 Identity Registry (agentId -> agentWallet).
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Erc8004IdentityRegistry {
        function getAgentWallet(uint256 agentId) external view returns (address agentWallet);
    }
}

/// HTTP RPC provider for querying Ethereum.
#[derive(Clone)]
pub struct RpcProvider {
    provider: RootProvider<Http<Client>>,
    trust_graph_address: Address,
    erc8004_address: Address,
    erc8004_identity: Option<Address>,
}

/// A supported chain event emitted by on-chain sources.
#[derive(Debug, Clone)]
pub enum ChainEvent {
    /// TrustGraph EdgeRated event.
    TrustGraph(EdgeRatedEvent),
    /// ERC-8004 Reputation NewFeedback event.
    Erc8004(NewFeedbackEvent),
    /// ERC-8004 ResponseAppended event.
    Erc8004Response(ResponseAppendedEvent),
    /// ERC-8004 FeedbackRevoked event.
    Erc8004Revoked(FeedbackRevokedEvent),
}

impl RpcProvider {
    /// Create a new RPC provider.
    pub async fn new(
        rpc_url: &str,
        trust_graph_address: Address,
        erc8004_address: Address,
        erc8004_identity: Option<Address>,
    ) -> Result<Self> {
        let url = rpc_url
            .parse()
            .with_context(|| format!("Invalid RPC URL: {}", rpc_url))?;

        let provider = ProviderBuilder::new().on_http(url);

        Ok(Self {
            provider,
            trust_graph_address,
            erc8004_address,
            erc8004_identity,
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

        let filter_erc8004_responses = Filter::new()
            .address(self.erc8004_address)
            .event_signature(ResponseAppended::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let filter_erc8004_revocations = Filter::new()
            .address(self.erc8004_address)
            .event_signature(FeedbackRevoked::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let (logs_trust_graph, logs_erc8004, logs_erc8004_responses, logs_erc8004_revocations): (
            Vec<Log>,
            Vec<Log>,
            Vec<Log>,
            Vec<Log>,
        ) = tokio::try_join!(
            self.provider.get_logs(&filter_trust_graph),
            self.provider.get_logs(&filter_erc8004),
            self.provider.get_logs(&filter_erc8004_responses),
            self.provider.get_logs(&filter_erc8004_revocations)
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

        for log in &logs_erc8004_responses {
            match ResponseAppendedEvent::from_log(log) {
                Ok(event) => events.push(ChainEvent::Erc8004Response(event)),
                Err(e) => tracing::warn!("Failed to parse ResponseAppended event: {}", e),
            }
        }

        for log in &logs_erc8004_revocations {
            match FeedbackRevokedEvent::from_log(log) {
                Ok(event) => events.push(ChainEvent::Erc8004Revoked(event)),
                Err(e) => tracing::warn!("Failed to parse FeedbackRevoked event: {}", e),
            }
        }

        // Sort by block coordinates for stable processing.
        events.sort_by_key(|e| match e {
            ChainEvent::TrustGraph(ev) => (ev.block_number, ev.tx_index, ev.log_index),
            ChainEvent::Erc8004(ev) => (ev.block_number, ev.tx_index, ev.log_index),
            ChainEvent::Erc8004Response(ev) => (ev.block_number, ev.tx_index, ev.log_index),
            ChainEvent::Erc8004Revoked(ev) => (ev.block_number, ev.tx_index, ev.log_index),
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

    /// Get block hash for a block number.
    pub async fn get_block_hash(&self, block_number: u64) -> Result<B256> {
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

        Ok(block.header.hash)
    }

    /// Resolve an ERC-8004 agentId to its agentWallet at a specific block.
    pub async fn resolve_agent_wallet(
        &self,
        agent_id: U256,
        block_number: u64,
    ) -> Result<Option<Address>> {
        let Some(identity_registry) = self.erc8004_identity else {
            return Ok(None);
        };

        let registry = Erc8004IdentityRegistry::new(identity_registry, &self.provider);
        let block_id = BlockId::Number(BlockNumberOrTag::Number(block_number));
        let result = registry
            .getAgentWallet(agent_id)
            .block(block_id)
            .call()
            .await
            .context("Failed to resolve agentWallet from identity registry")?;

        let agent_wallet = result.agentWallet;
        if agent_wallet == Address::ZERO {
            return Ok(None);
        }

        Ok(Some(agent_wallet))
    }
}
