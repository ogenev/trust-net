//! Configuration management for the TrustNet indexer.
//!
//! This module handles loading configuration from:
//! - TOML files
//! - Environment variables (overrides TOML)
//! - Default values (fallbacks)

use alloy::primitives::Address;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration for the indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network configuration
    pub network: NetworkConfig,

    /// Contract addresses
    pub contracts: ContractsConfig,

    /// Database configuration
    pub database: DatabaseConfig,

    /// Sync configuration
    pub sync: SyncConfig,

    /// SMM builder configuration
    #[serde(default)]
    pub builder: BuilderConfig,

    /// Publisher configuration
    pub publisher: PublisherConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Ethereum RPC URL
    pub rpc_url: String,

    /// Chain ID (e.g., 11155111 for Sepolia)
    pub chain_id: u64,
}

/// Contract addresses configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractsConfig {
    /// TrustGraph contract address (EdgeRated events)
    pub trust_graph: Address,

    /// RootRegistry contract address (for publishing roots)
    pub root_registry: Address,

    /// ERC-8004 Reputation contract address (NewFeedback events)
    pub erc8004_reputation: Address,

    /// ERC-8004 Identity contract address (optional, for agentWallet lookup)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erc8004_identity: Option<Address>,

    /// ERC-8004 Validation contract address (optional, not required for MVP ingestion)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erc8004_validation: Option<Address>,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL (e.g., "sqlite://trustnet.db")
    pub url: String,

    /// Maximum number of connections in the pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum number of connections in the pool
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
}

/// Sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Block number to start syncing from (0 = from genesis)
    #[serde(default)]
    pub start_block: u64,

    /// Polling interval in seconds for new blocks
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Batch size for historical sync (number of blocks per batch)
    #[serde(default = "default_batch_size")]
    pub batch_size: u64,

    /// Number of confirmations to wait before processing blocks
    #[serde(default = "default_confirmations")]
    pub confirmations: u64,
}

/// SMM builder configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderConfig {
    /// Rebuild interval in seconds (300 = 5 minutes).
    ///
    /// **Must be > 0** - Zero will cause a panic in tokio::time::interval.
    #[serde(default = "default_rebuild_interval_secs")]
    pub rebuild_interval_secs: u64,
}

impl Default for BuilderConfig {
    fn default() -> Self {
        Self {
            rebuild_interval_secs: default_rebuild_interval_secs(),
        }
    }
}

/// Publisher configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherConfig {
    /// Enable automatic root publishing
    #[serde(default = "default_auto_publish")]
    pub auto_publish: bool,

    /// Publish interval in seconds (3600 = 1 hour)
    #[serde(default = "default_publish_interval_secs")]
    pub publish_interval_secs: u64,

    /// Private key for publisher account (hex string without 0x prefix)
    pub private_key: String,

    /// Maximum fee per gas in gwei
    #[serde(default = "default_max_fee_per_gas_gwei")]
    pub max_fee_per_gas_gwei: u64,

    /// Maximum priority fee per gas in gwei
    #[serde(default = "default_max_priority_fee_per_gas_gwei")]
    pub max_priority_fee_per_gas_gwei: u64,

    /// Maximum gas price in gwei (0 = no limit)
    #[serde(default)]
    pub max_gas_price_gwei: u64,

    /// Number of confirmations to wait
    #[serde(default = "default_publisher_confirmations")]
    pub confirmations: u64,

    /// Maximum retry attempts for failed transactions
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Minimum interval between publishes in seconds
    #[serde(default = "default_min_publish_interval_secs")]
    pub min_interval_secs: u64,

    /// Filesystem directory where canonical manifest JSON files are written before anchoring.
    ///
    /// Must be configured together with `manifest_public_base_uri`.
    #[serde(default)]
    pub manifest_output_dir: Option<String>,

    /// Public base URI used to construct the anchored manifest URI.
    ///
    /// Example: `https://cdn.example.com/trustnet/manifests`
    /// Final URI: `{manifest_public_base_uri}/epoch-{epoch}-0x{manifest_hash}.json`
    ///
    /// Must be configured together with `manifest_output_dir`.
    #[serde(default)]
    pub manifest_public_base_uri: Option<String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format: json or pretty
    #[serde(default = "default_log_format")]
    pub format: String,
}

// Default value functions
fn default_confirmations() -> u64 {
    6
}

fn default_max_connections() -> u32 {
    5
}

fn default_min_connections() -> u32 {
    1
}

fn default_poll_interval_secs() -> u64 {
    12
}

fn default_batch_size() -> u64 {
    1000
}

fn default_rebuild_interval_secs() -> u64 {
    300 // 5 minutes
}

fn default_auto_publish() -> bool {
    true
}

fn default_publish_interval_secs() -> u64 {
    3600 // 1 hour
}

fn default_max_fee_per_gas_gwei() -> u64 {
    50
}

fn default_max_priority_fee_per_gas_gwei() -> u64 {
    2
}

fn default_publisher_confirmations() -> u64 {
    3 // Wait for 3 confirmations
}

fn default_max_retries() -> u32 {
    3 // Retry up to 3 times
}

fn default_min_publish_interval_secs() -> u64 {
    60 // Minimum 1 minute between publishes
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// Environment variables can be referenced using `${VAR_NAME}` syntax.
    /// For example: `private_key = "${PUBLISHER_PRIVATE_KEY}"`
    ///
    /// # Arguments
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Example
    /// ```no_run
    /// # use trustnet_indexer::config::Config;
    /// let config = Config::from_file("indexer.toml")?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        // Expand environment variables before parsing
        let expanded = Self::expand_env_vars(&contents)?;

        let config: Config = toml::from_str(&expanded)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        config.validate()?;

        Ok(config)
    }

    /// Load configuration from a TOML string.
    pub fn from_toml_str(toml: &str) -> Result<Self> {
        let config: Config = toml::from_str(toml).context("Failed to parse TOML configuration")?;

        config.validate()?;

        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate RPC URL
        if self.network.rpc_url.is_empty() {
            anyhow::bail!("Network RPC URL cannot be empty");
        }

        // Validate chain ID
        if self.network.chain_id == 0 {
            anyhow::bail!("Chain ID must be non-zero");
        }

        // Validate on-chain contract addresses
        if self.contracts.trust_graph.is_zero() {
            anyhow::bail!("Contracts trust_graph must be a non-zero address");
        }
        if self.contracts.root_registry.is_zero() {
            anyhow::bail!("Contracts root_registry must be a non-zero address");
        }
        if self.contracts.erc8004_reputation.is_zero() {
            anyhow::bail!("Contracts erc8004_reputation must be a non-zero address");
        }
        if let Some(identity) = self.contracts.erc8004_identity {
            if identity.is_zero() {
                anyhow::bail!(
                    "Contracts erc8004_identity must be a non-zero address when provided"
                );
            }
        }

        // Validate database URL
        if self.database.url.is_empty() {
            anyhow::bail!("Database URL cannot be empty");
        }

        // Validate connection pool settings
        if self.database.max_connections == 0 {
            anyhow::bail!("Database max_connections must be > 0");
        }
        if self.database.min_connections > self.database.max_connections {
            anyhow::bail!(
                "Database min_connections ({}) cannot exceed max_connections ({})",
                self.database.min_connections,
                self.database.max_connections
            );
        }

        // Validate sync settings
        if self.sync.poll_interval_secs == 0 {
            anyhow::bail!("Sync poll_interval_secs must be > 0");
        }
        if self.sync.batch_size == 0 {
            anyhow::bail!("Sync batch_size must be > 0");
        }

        // Validate builder settings
        if self.builder.rebuild_interval_secs == 0 {
            anyhow::bail!(
                "Builder rebuild_interval_secs must be > 0 (tokio interval cannot be zero)"
            );
        }

        // Validate publisher settings
        if self.publisher.private_key.is_empty() {
            anyhow::bail!("Publisher private_key cannot be empty");
        }

        // Validate private key format (hex string, optionally with 0x prefix)
        let key = self.publisher.private_key.trim_start_matches("0x");
        if key.len() != 64 {
            anyhow::bail!(
                "Publisher private_key must be 64 hex characters (got {})",
                key.len()
            );
        }
        if !key.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("Publisher private_key must be a valid hex string");
        }

        if self.publisher.publish_interval_secs == 0 {
            anyhow::bail!("Publisher publish_interval_secs must be > 0");
        }

        match (
            self.publisher.manifest_output_dir.as_deref(),
            self.publisher.manifest_public_base_uri.as_deref(),
        ) {
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!(
                    "Publisher manifest_output_dir and manifest_public_base_uri must be set together"
                );
            }
            (Some(dir), Some(base_uri)) => {
                if dir.trim().is_empty() {
                    anyhow::bail!("Publisher manifest_output_dir cannot be empty");
                }

                let base_uri = base_uri.trim();
                if base_uri.is_empty() {
                    anyhow::bail!("Publisher manifest_public_base_uri cannot be empty");
                }

                let valid_prefixes = ["https://", "http://", "ipfs://", "file://"];
                if !valid_prefixes
                    .iter()
                    .any(|prefix| base_uri.starts_with(prefix))
                {
                    anyhow::bail!(
                        "Publisher manifest_public_base_uri must start with one of: {}",
                        valid_prefixes.join(", ")
                    );
                }
            }
            (None, None) => {}
        }

        // Validate logging level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.as_str()) {
            anyhow::bail!(
                "Logging level must be one of: {} (got '{}')",
                valid_levels.join(", "),
                self.logging.level
            );
        }

        // Validate logging format
        let valid_formats = ["json", "pretty"];
        if !valid_formats.contains(&self.logging.format.as_str()) {
            anyhow::bail!(
                "Logging format must be one of: {} (got '{}')",
                valid_formats.join(", "),
                self.logging.format
            );
        }

        Ok(())
    }

    /// Get the publisher private key with 0x prefix.
    pub fn publisher_private_key_with_prefix(&self) -> String {
        let key = self.publisher.private_key.trim_start_matches("0x");
        format!("0x{}", key)
    }

    /// Expand environment variables in the format `${VAR_NAME}`.
    ///
    /// Environment variables inside TOML comments or strings are handled correctly:
    /// - Inside comments (after `#` outside strings): Not expanded
    /// - Inside strings (`"..."`, `'...'`, `"""..."""`, `'''...'''`): Expanded normally
    ///
    /// # Arguments
    /// * `input` - String containing environment variable placeholders
    ///
    /// # Returns
    /// String with all `${VAR_NAME}` placeholders replaced with their values
    ///
    /// # Errors
    /// Returns an error if a referenced environment variable is not set
    fn expand_env_vars(input: &str) -> Result<String> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut in_double_quote = false;
        let mut in_single_quote = false;
        let mut in_multiline_double = false;
        let mut in_multiline_single = false;
        let mut in_comment = false;
        let mut escape_next = false;
        let mut pos = 0;

        while let Some(ch) = chars.next() {
            pos += 1;

            // Handle escape sequences in double-quoted strings (basic and multiline)
            if escape_next {
                escape_next = false;
                result.push(ch);
                continue;
            }

            // Check for escape character in double-quoted strings
            if ch == '\\' && (in_double_quote || in_multiline_double) {
                escape_next = true;
                result.push(ch);
                continue;
            }

            // Check if we're in any string type
            let in_any_string =
                in_double_quote || in_single_quote || in_multiline_double || in_multiline_single;

            // Track string state
            if ch == '"' && !in_single_quote && !in_multiline_single && !in_comment {
                // Check if it's a triple-quote """
                if Self::is_triple_quote(&mut chars, '"') {
                    // Toggle multiline double-quote state
                    in_multiline_double = !in_multiline_double;
                    result.push(ch);
                    result.push(chars.next().unwrap());
                    result.push(chars.next().unwrap());
                    pos += 2;
                } else {
                    // Regular double quote (only toggle if not in multiline)
                    if !in_multiline_double {
                        in_double_quote = !in_double_quote;
                    }
                    result.push(ch);
                }
            } else if ch == '\'' && !in_double_quote && !in_multiline_double && !in_comment {
                // Check if it's a triple-quote '''
                if Self::is_triple_quote(&mut chars, '\'') {
                    // Toggle multiline single-quote state
                    in_multiline_single = !in_multiline_single;
                    result.push(ch);
                    result.push(chars.next().unwrap());
                    result.push(chars.next().unwrap());
                    pos += 2;
                } else {
                    // Regular single quote (only toggle if not in multiline)
                    if !in_multiline_single {
                        in_single_quote = !in_single_quote;
                    }
                    result.push(ch);
                }
            } else if ch == '#' && !in_any_string && !in_comment {
                // Only start comment if # is outside all string types
                in_comment = true;
                result.push(ch);
            } else if ch == '\n' {
                // End of line resets comment state (but not string state)
                in_comment = false;
                result.push(ch);
            } else if ch == '$' && !in_comment && chars.peek() == Some(&'{') {
                // Expand variables (works in strings and outside strings, but not in comments)
                chars.next(); // consume '{'
                pos += 1;

                // Extract variable name
                let mut var_name = String::new();
                let mut found_close = false;
                while let Some(&c) = chars.peek() {
                    pos += 1;
                    if c == '}' {
                        chars.next(); // consume '}'
                        found_close = true;
                        break;
                    }
                    var_name.push(chars.next().unwrap());
                }

                if !found_close {
                    anyhow::bail!(
                        "Unclosed environment variable placeholder at position {}",
                        pos
                    );
                }

                if var_name.is_empty() {
                    anyhow::bail!("Empty environment variable name at position {}", pos);
                }

                // Look up the environment variable
                match std::env::var(&var_name) {
                    Ok(value) => result.push_str(&value),
                    Err(_) => {
                        anyhow::bail!(
                            "Environment variable '{}' is not set (referenced at position {})",
                            var_name,
                            pos
                        );
                    }
                }
            } else {
                result.push(ch);
            }
        }

        Ok(result)
    }

    /// Check if the next two characters match the given quote character (for triple-quote detection).
    fn is_triple_quote(chars: &mut std::iter::Peekable<std::str::Chars>, quote_char: char) -> bool {
        let mut temp = chars.clone();
        temp.next() == Some(quote_char) && temp.next() == Some(quote_char)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_example_config() {
        let toml = r#"
[network]
rpc_url = "https://sepolia.infura.io/v3/YOUR_API_KEY"
chain_id = 11155111
confirmations = 6

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://trustnet.db"
max_connections = 5
min_connections = 1

[sync]
start_block = 0
poll_interval_secs = 12
batch_size = 1000

[publisher]
auto_publish = true
publish_interval_secs = 3600
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
max_fee_per_gas_gwei = 50
max_priority_fee_per_gas_gwei = 2

[logging]
level = "info"
format = "pretty"
        "#;

        let config = Config::from_toml_str(toml).unwrap();
        assert_eq!(config.network.chain_id, 11155111);
        assert_eq!(config.database.url, "sqlite://trustnet.db");
    }

    #[test]
    fn test_validation_empty_rpc_url() {
        let toml = r#"
[network]
rpc_url = ""
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "#;

        let result = Config::from_toml_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("RPC URL"));
    }

    #[test]
    fn test_validation_invalid_private_key() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "invalid"
        "#;

        let result = Config::from_toml_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private_key"));
    }

    #[test]
    fn test_validation_zero_root_registry_address() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x0000000000000000000000000000000000000000"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "#;

        let result = Config::from_toml_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("root_registry"));
    }

    #[test]
    fn test_validation_zero_optional_identity_address() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"
erc8004_identity = "0x0000000000000000000000000000000000000000"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "#;

        let result = Config::from_toml_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("erc8004_identity"));
    }

    #[test]
    fn test_private_key_with_prefix() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        "#;

        let config = Config::from_toml_str(toml).unwrap();
        assert_eq!(
            config.publisher_private_key_with_prefix(),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn test_validation_zero_rebuild_interval() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[builder]
rebuild_interval_secs = 0

[publisher]
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "#;

        let result = Config::from_toml_str(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("rebuild_interval_secs") && err.contains("must be > 0"),
            "Expected error about rebuild_interval_secs, got: {}",
            err
        );
    }

    #[test]
    fn test_default_values() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "#;

        let config = Config::from_toml_str(toml).unwrap();

        // Check defaults are applied
        assert_eq!(config.sync.confirmations, 6);
        assert_eq!(config.database.max_connections, 5);
        assert_eq!(config.database.min_connections, 1);
        assert_eq!(config.sync.poll_interval_secs, 12);
        assert_eq!(config.sync.batch_size, 1000);
        assert_eq!(config.builder.rebuild_interval_secs, 300);
        assert!(config.publisher.auto_publish);
        assert_eq!(config.publisher.publish_interval_secs, 3600);
        assert!(config.publisher.manifest_output_dir.is_none());
        assert!(config.publisher.manifest_public_base_uri.is_none());
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "pretty");
    }

    #[test]
    fn test_validation_manifest_publish_config_requires_both_fields() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
manifest_output_dir = "/tmp/trustnet-manifests"
        "#;

        let result = Config::from_toml_str(toml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be set together"));
    }

    #[test]
    fn test_validation_manifest_publish_config_rejects_invalid_uri_scheme() {
        let toml = r#"
[network]
rpc_url = "http://localhost:8545"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
manifest_output_dir = "/tmp/trustnet-manifests"
manifest_public_base_uri = "s3://bucket/path"
        "#;

        let result = Config::from_toml_str(toml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must start with one of"));
    }

    #[test]
    fn test_expand_env_vars() {
        // Simple replacement
        std::env::set_var("TEST_VAR", "hello");
        let result = Config::expand_env_vars("value is ${TEST_VAR}").unwrap();
        assert_eq!(result, "value is hello");

        // Multiple replacements
        std::env::set_var("VAR1", "foo");
        std::env::set_var("VAR2", "bar");
        let result = Config::expand_env_vars("${VAR1} and ${VAR2}").unwrap();
        assert_eq!(result, "foo and bar");

        // No variables
        let result = Config::expand_env_vars("no variables here").unwrap();
        assert_eq!(result, "no variables here");

        // Clean up
        std::env::remove_var("TEST_VAR");
        std::env::remove_var("VAR1");
        std::env::remove_var("VAR2");
    }

    #[test]
    fn test_expand_env_vars_undefined() {
        // Undefined variable should error
        let result = Config::expand_env_vars("value is ${UNDEFINED_VAR_12345}");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("UNDEFINED_VAR_12345"));
    }

    #[test]
    fn test_expand_env_vars_empty_name() {
        // Empty variable name should error
        let result = Config::expand_env_vars("value is ${}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty"));
    }

    #[test]
    fn test_expand_env_vars_unclosed() {
        // Unclosed placeholder should error
        let result = Config::expand_env_vars("value is ${UNCLOSED");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unclosed"));
    }

    #[test]
    fn test_config_with_env_vars() {
        // Set environment variable
        std::env::set_var(
            "TEST_PRIVATE_KEY",
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        );
        std::env::set_var("TEST_RPC_URL", "https://sepolia.example.com");

        let toml = r#"
[network]
rpc_url = "${TEST_RPC_URL}"
chain_id = 11155111

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
private_key = "${TEST_PRIVATE_KEY}"
        "#;

        // Expand env vars manually (simulating from_file behavior)
        let expanded = Config::expand_env_vars(toml).unwrap();
        let config = Config::from_toml_str(&expanded).unwrap();

        assert_eq!(config.network.rpc_url, "https://sepolia.example.com");
        assert_eq!(
            config.publisher.private_key,
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        );

        // Clean up
        std::env::remove_var("TEST_PRIVATE_KEY");
        std::env::remove_var("TEST_RPC_URL");
    }

    #[test]
    fn test_expand_env_vars_ignore_comments() {
        // Env var in a comment should be ignored
        let input = r#"
# This is a comment with ${UNDEFINED_VAR}
key = "value"
"#;
        let result = Config::expand_env_vars(input).unwrap();
        // The comment should remain unchanged
        assert!(result.contains("${UNDEFINED_VAR}"));
        assert!(result.contains("key = \"value\""));
    }

    #[test]
    fn test_expand_env_vars_comment_after_value() {
        std::env::set_var("TEST_KEY", "secret");

        // Env var before comment should expand, after comment should not
        let input = r#"key = "${TEST_KEY}"  # Example: use ${OTHER_VAR}"#;
        let result = Config::expand_env_vars(input).unwrap();

        // TEST_KEY should be expanded
        assert!(result.contains("secret"));
        // OTHER_VAR in comment should NOT be expanded
        assert!(result.contains("${OTHER_VAR}"));

        std::env::remove_var("TEST_KEY");
    }

    #[test]
    fn test_expand_env_vars_multiline_with_comments() {
        std::env::set_var("ACTUAL_VAR", "real_value");

        let input = r#"
# Example configuration
# You can use: key = "${EXAMPLE_VAR}"

[section]
key = "${ACTUAL_VAR}"  # Use env var here
"#;
        let result = Config::expand_env_vars(input).unwrap();

        // ACTUAL_VAR should be expanded
        assert!(result.contains("real_value"));
        // EXAMPLE_VAR in comment should NOT be expanded
        assert!(result.contains("${EXAMPLE_VAR}"));

        std::env::remove_var("ACTUAL_VAR");
    }

    #[test]
    fn test_config_from_file_with_comment_examples() {
        // This simulates the real-world case from indexer.toml.example
        std::env::set_var(
            "REAL_KEY",
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        );
        std::env::set_var("REAL_RPC", "https://eth.example.com");

        let toml = r#"
[network]
# Example: rpc_url = "${RPC_URL}"
rpc_url = "${REAL_RPC}"
chain_id = 1

[contracts]
trust_graph = "0x1111111111111111111111111111111111111111"
root_registry = "0x2222222222222222222222222222222222222222"
erc8004_reputation = "0x3333333333333333333333333333333333333333"

[database]
url = "sqlite://test.db"

[sync]
start_block = 0

[publisher]
# WARNING: Keep this secure! Use environment variable in production
# Example: Load from env with: private_key = "${PUBLISHER_PRIVATE_KEY}"
private_key = "${REAL_KEY}"
        "#;

        // This should succeed because comment examples are ignored
        let expanded = Config::expand_env_vars(toml).unwrap();
        let config = Config::from_toml_str(&expanded).unwrap();

        // Real variables should be expanded
        assert_eq!(config.network.rpc_url, "https://eth.example.com");
        assert_eq!(
            config.publisher.private_key,
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        );

        // Comment examples should remain in the expanded text
        assert!(expanded.contains("${RPC_URL}"));
        assert!(expanded.contains("${PUBLISHER_PRIVATE_KEY}"));

        std::env::remove_var("REAL_KEY");
        std::env::remove_var("REAL_RPC");
    }

    #[test]
    fn test_expand_env_vars_hash_in_string() {
        std::env::set_var("RPC_SUFFIX", "mytoken");

        // # inside a string should not be treated as a comment
        let input = r#"rpc_url = "https://example.com/#${RPC_SUFFIX}""#;
        let result = Config::expand_env_vars(input).unwrap();

        // Variable should be expanded even though # appears before it in the string
        assert!(result.contains("https://example.com/#mytoken"));
        assert!(!result.contains("${RPC_SUFFIX}"));

        std::env::remove_var("RPC_SUFFIX");
    }

    #[test]
    fn test_expand_env_vars_hash_in_single_quote_string() {
        std::env::set_var("MY_VAR", "value");

        // # inside a single-quoted string should not be treated as a comment
        let input = r#"key = 'text with # and ${MY_VAR}'"#;
        let result = Config::expand_env_vars(input).unwrap();

        // Variable should be expanded
        assert!(result.contains("value"));
        assert!(!result.contains("${MY_VAR}"));

        std::env::remove_var("MY_VAR");
    }

    #[test]
    fn test_expand_env_vars_escaped_quotes() {
        std::env::set_var("ESCAPE_TEST_VAR", "secret");

        // Escaped quotes should be handled correctly
        let input = r#"key = "She said \"hello\" with ${ESCAPE_TEST_VAR}""#;
        let result = Config::expand_env_vars(input).unwrap();

        // Variable should be expanded, escaped quotes preserved
        assert!(result.contains("secret"));
        assert!(result.contains(r#"She said \"hello\""#));

        std::env::remove_var("ESCAPE_TEST_VAR");
    }

    #[test]
    fn test_expand_env_vars_string_vs_comment() {
        std::env::set_var("IN_STRING", "string_value");

        // Variable in string should expand, variable in comment should not
        let input = r#"
key = "url/#${IN_STRING}"  # example: use ${IN_COMMENT}
"#;
        let result = Config::expand_env_vars(input).unwrap();

        // IN_STRING should be expanded
        assert!(result.contains("string_value"));
        assert!(!result.contains("${IN_STRING}"));

        // IN_COMMENT should NOT be expanded
        assert!(result.contains("${IN_COMMENT}"));

        std::env::remove_var("IN_STRING");
    }

    #[test]
    fn test_expand_env_vars_complex_scenario() {
        std::env::set_var("API_KEY", "abc123");
        std::env::set_var("DOMAIN", "example.com");

        let input = r#"
# Configuration file
# Example: url = "https://${YOUR_DOMAIN}/api"

[network]
# The RPC endpoint with fragment
rpc_url = "https://${DOMAIN}/#key=${API_KEY}"

[other]
description = 'This has a # character and ${API_KEY}'
"#;
        let result = Config::expand_env_vars(input).unwrap();

        // Real variables should be expanded
        assert!(result.contains("example.com"));
        assert!(result.contains("abc123"));
        assert!(!result.contains("${API_KEY}") || result.matches("${API_KEY}").count() == 1); // Only in comment
        assert!(!result.contains("${DOMAIN}"));

        // Comment example should NOT be expanded
        assert!(result.contains("${YOUR_DOMAIN}"));

        // Both strings should have variables expanded
        assert!(result.contains("https://example.com/#key=abc123"));
        assert!(result.contains("This has a # character and abc123"));

        std::env::remove_var("API_KEY");
        std::env::remove_var("DOMAIN");
    }

    #[test]
    fn test_expand_env_vars_private_key_with_hash() {
        std::env::set_var(
            "PUBLISHER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );

        // This tests the specific case mentioned in the issue
        let input = r##"
[publisher]
# Example: private_key = "${PUBLISHER_PRIVATE_KEY}"
private_key = "# ${PUBLISHER_KEY}"
"##;
        let result = Config::expand_env_vars(input).unwrap();

        // PUBLISHER_KEY should be expanded even with # before it in the string
        assert!(result.contains("# 0123456789abcdef"));
        assert!(
            !result.contains("${PUBLISHER_KEY}") || result.matches("${PUBLISHER_KEY}").count() == 0
        );

        // Comment example should NOT be expanded
        assert!(result.contains("${PUBLISHER_PRIVATE_KEY}"));

        std::env::remove_var("PUBLISHER_KEY");
    }

    #[test]
    fn test_expand_env_vars_multiline_literal_string() {
        // Test the specific case from the issue: multiline literal string with apostrophe
        let input = r###"
description = '''
It's fine
'''
# Comment with ${UNDEFINED_VAR}
"###;
        // This should succeed because ${UNDEFINED_VAR} is in a comment (not expanded)
        // Previously, the apostrophe in "It's" would leave in_single_quote=true,
        // causing the comment line to be treated as part of the string
        let result = Config::expand_env_vars(input);
        assert!(result.is_ok(), "Should not error on comment placeholders");
        let expanded = result.unwrap();

        // The comment placeholder should remain
        assert!(expanded.contains("${UNDEFINED_VAR}"));
        // The apostrophe should be preserved
        assert!(expanded.contains("It's fine"));
    }

    #[test]
    fn test_expand_env_vars_multiline_literal_with_expansion() {
        std::env::set_var("MULTILINE_VAR", "expanded_value");

        let input = r###"
description = '''
It's fine
and here is ${MULTILINE_VAR}
'''
# Comment ${NOT_EXPANDED}
"###;
        let result = Config::expand_env_vars(input).unwrap();

        // Variable inside multiline literal should be expanded
        assert!(result.contains("expanded_value"));
        assert!(!result.contains("${MULTILINE_VAR}"));

        // Apostrophe should be preserved
        assert!(result.contains("It's fine"));

        // Comment should NOT expand
        assert!(result.contains("${NOT_EXPANDED}"));

        std::env::remove_var("MULTILINE_VAR");
    }

    #[test]
    fn test_expand_env_vars_multiline_basic_string() {
        std::env::set_var("BASIC_VAR", "test_value");

        let input = r###"
text = """
Line 1
Line 2 with ${BASIC_VAR}
"""
# ${IN_COMMENT}
"###;
        let result = Config::expand_env_vars(input).unwrap();

        // Variable should be expanded
        assert!(result.contains("test_value"));
        assert!(!result.contains("${BASIC_VAR}"));

        // Comment should NOT expand
        assert!(result.contains("${IN_COMMENT}"));

        std::env::remove_var("BASIC_VAR");
    }

    #[test]
    fn test_expand_env_vars_mixed_string_types() {
        std::env::set_var("VAR1", "value1");
        std::env::set_var("VAR2", "value2");
        std::env::set_var("VAR3", "value3");

        let input = r###"
regular_double = "${VAR1}"
regular_single = '${VAR2}'
multiline_literal = '''
Text with ${VAR3}
'''
# Comment ${NOT_DEFINED}
"###;
        let result = Config::expand_env_vars(input).unwrap();

        // All variables in strings should be expanded
        assert!(result.contains("value1"));
        assert!(result.contains("value2"));
        assert!(result.contains("value3"));

        // Comment should NOT expand
        assert!(result.contains("${NOT_DEFINED}"));

        std::env::remove_var("VAR1");
        std::env::remove_var("VAR2");
        std::env::remove_var("VAR3");
    }

    #[test]
    fn test_expand_env_vars_apostrophe_after_multiline() {
        // This tests the regression described in the issue
        let input = r###"
value = '''
It's fine
'''
key = "normal"
# This comment should be recognized: ${UNDEF}
"###;

        // Should succeed because ${UNDEF} is in a comment (not expanded)
        // With the bug, the apostrophe in "It's" left us in single-quote mode,
        // so the comment wasn't recognized
        let result = Config::expand_env_vars(input);
        assert!(
            result.is_ok(),
            "Comment after multiline string should not cause expansion"
        );

        let expanded = result.unwrap();
        assert!(
            expanded.contains("${UNDEF}"),
            "Comment placeholder should remain"
        );
        assert!(
            expanded.contains("It's fine"),
            "Apostrophe should be preserved"
        );
    }

    #[test]
    fn test_expand_env_vars_nested_quotes_in_multiline() {
        std::env::set_var("NESTED_VAR", "nested");

        let input = r###"
text = """
She said "hello" with ${NESTED_VAR}
"""
"###;
        let result = Config::expand_env_vars(input).unwrap();

        // Variable should be expanded
        assert!(result.contains("nested"));

        // Inner quotes should be preserved
        assert!(result.contains(r#"She said "hello""#));

        std::env::remove_var("NESTED_VAR");
    }
}
