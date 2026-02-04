//! Verification helpers for ERC-8004 ResponseAppended stamps.

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use trustnet_core::hashing::keccak256;
use trustnet_core::B256;

const DEFAULT_MAX_BYTES: usize = 1_000_000; // 1 MB
const DEFAULT_IPFS_GATEWAY: &str = "https://ipfs.io/ipfs/";
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// HTTP verifier for `trustnet.verification.v1` response JSON.
#[derive(Clone)]
pub struct ResponseVerifier {
    client: Client,
    ipfs_gateway: String,
    max_bytes: usize,
}

impl ResponseVerifier {
    /// Build a verifier with explicit settings.
    pub fn new(ipfs_gateway: String, max_bytes: usize, timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("trustnet-indexer/verification")
            .build()
            .context("Failed to build response verifier HTTP client")?;

        Ok(Self {
            client,
            ipfs_gateway,
            max_bytes,
        })
    }

    /// Construct a verifier from environment variables.
    ///
    /// - `TRUSTNET_VERIFY_RESPONSES` (default: true)
    /// - `TRUSTNET_IPFS_GATEWAY` (default: https://ipfs.io/ipfs/)
    /// - `TRUSTNET_VERIFICATION_MAX_BYTES` (default: 1_000_000)
    /// - `TRUSTNET_VERIFICATION_TIMEOUT_SECS` (default: 10)
    pub fn from_env() -> Result<Option<Self>> {
        let enabled = std::env::var("TRUSTNET_VERIFY_RESPONSES")
            .ok()
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(true);

        if !enabled {
            return Ok(None);
        }

        let ipfs_gateway = std::env::var("TRUSTNET_IPFS_GATEWAY")
            .unwrap_or_else(|_| DEFAULT_IPFS_GATEWAY.to_string());

        let max_bytes = std::env::var("TRUSTNET_VERIFICATION_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_BYTES);

        let timeout_secs = std::env::var("TRUSTNET_VERIFICATION_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);

        Ok(Some(Self::new(ipfs_gateway, max_bytes, timeout_secs)?))
    }

    /// Verify a response URI against the expected response hash.
    ///
    /// Returns true only if:
    /// - the JSON hashes to `expected_hash` via JCS
    /// - `type == "trustnet.verification.v1"`
    /// - `status == "verified"`
    pub async fn verify_response_uri(&self, uri: &str, expected_hash: &B256) -> Result<bool> {
        let Some(resolved) = self.resolve_uri(uri) else {
            return Ok(false);
        };

        let response = self
            .client
            .get(resolved)
            .send()
            .await
            .context("Failed to fetch response URI")?;

        if !response.status().is_success() {
            return Ok(false);
        }

        if let Some(len) = response.content_length() {
            if len as usize > self.max_bytes {
                return Ok(false);
            }
        }

        let bytes = response.bytes().await.context("Failed to read response")?;
        if bytes.len() > self.max_bytes {
            return Ok(false);
        }

        let json: Value = serde_json::from_slice(&bytes).context("Invalid response JSON")?;
        self.verify_response_json(&json, expected_hash)
    }

    fn verify_response_json(&self, json: &Value, expected_hash: &B256) -> Result<bool> {
        let ty = json.get("type").and_then(|v| v.as_str());
        if ty != Some("trustnet.verification.v1") {
            return Ok(false);
        }

        let status = json.get("status").and_then(|v| v.as_str());
        if status != Some("verified") {
            return Ok(false);
        }

        let canonical = serde_jcs::to_vec(json).context("Failed to JCS-canonicalize response")?;
        let digest = keccak256(&canonical);
        Ok(&digest == expected_hash)
    }

    fn resolve_uri(&self, uri: &str) -> Option<String> {
        let trimmed = uri.trim();
        if trimmed.is_empty() {
            return None;
        }

        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return Some(trimmed.to_string());
        }

        if let Some(path) = trimmed.strip_prefix("ipfs://") {
            let path = path.strip_prefix("ipfs/").unwrap_or(path);
            let path = path.trim_start_matches('/');
            return Some(format!("{}{}", self.ipfs_gateway, path));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verification_accepts_valid_verified_payload() {
        let payload = json!({
            "type": "trustnet.verification.v1",
            "status": "verified",
            "context": "trustnet:ctx:payments:v1",
            "receipt": {"type": "escrowJob", "chainId": 1, "contract": "0xabc", "jobId": "1"},
            "createdAt": "2026-02-04T00:00:00Z"
        });

        let canonical = serde_jcs::to_vec(&payload).unwrap();
        let hash = keccak256(&canonical);

        let verifier = ResponseVerifier::new(DEFAULT_IPFS_GATEWAY.to_string(), 1024, 1).unwrap();
        assert!(verifier.verify_response_json(&payload, &hash).unwrap());
    }

    #[test]
    fn verification_rejects_wrong_status() {
        let payload = json!({
            "type": "trustnet.verification.v1",
            "status": "refunded"
        });

        let canonical = serde_jcs::to_vec(&payload).unwrap();
        let hash = keccak256(&canonical);

        let verifier = ResponseVerifier::new(DEFAULT_IPFS_GATEWAY.to_string(), 1024, 1).unwrap();
        assert!(!verifier.verify_response_json(&payload, &hash).unwrap());
    }

    #[test]
    fn verification_rejects_hash_mismatch() {
        let payload = json!({
            "type": "trustnet.verification.v1",
            "status": "verified"
        });

        let verifier = ResponseVerifier::new(DEFAULT_IPFS_GATEWAY.to_string(), 1024, 1).unwrap();
        assert!(!verifier
            .verify_response_json(&payload, &B256::repeat_byte(0x11))
            .unwrap());
    }
}
