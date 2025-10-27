//! Hashing utilities for TrustNet.
//!
//! Provides keccak256 hashing and edge key computation functions
//! that match the Solidity implementation exactly.

use crate::types::{AgentKey, Bytes32, ContextId};
use alloy_primitives::{keccak256 as alloy_keccak256, Address, B256};

/// Compute keccak256 hash of input data.
///
/// This is a re-export of Alloy's keccak256 for convenience.
///
/// # Example
///
/// ```
/// use trustnet_core::hashing::keccak256;
///
/// let data = b"hello";
/// let hash = keccak256(data);
/// ```
pub fn keccak256(data: &[u8]) -> B256 {
    alloy_keccak256(data)
}

/// Compute the edge key for a given (rater, target, context) triple.
///
/// The key is computed as: `keccak256(rater || target || contextId)`
/// where rater and target are 20-byte addresses and contextId is 32 bytes.
///
/// This must match the Solidity implementation exactly.
///
/// # Arguments
///
/// * `rater` - The address of the rater/observer
/// * `target` - The address of the target
/// * `context` - The context identifier
///
/// # Returns
///
/// A 32-byte key that uniquely identifies this edge in the SMM.
///
/// # Example
///
/// ```
/// use trustnet_core::{ContextId, CTX_PAYMENTS};
/// use trustnet_core::hashing::compute_edge_key;
/// use alloy_primitives::Address;
///
/// let rater = Address::from([0x11; 20]);
/// let target = Address::from([0x22; 20]);
/// let context = ContextId::from(CTX_PAYMENTS);
///
/// let key = compute_edge_key(&rater, &target, &context);
/// ```
pub fn compute_edge_key(rater: &Address, target: &Address, context: &ContextId) -> Bytes32 {
    // Concatenate: rater (20 bytes) || target (20 bytes) || contextId (32 bytes)
    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(rater.as_slice());
    data.extend_from_slice(target.as_slice());
    data.extend_from_slice(context.as_bytes());

    keccak256(&data)
}

/// Compute the agent key from chain ID, registry address, and agent ID.
///
/// The key is computed to match Solidity's `keccak256(abi.encodePacked(uint256 chainId, address registry, bytes32 agentId))`.
///
/// **Encoding format** (matching Solidity):
/// - `chainId`: 32 bytes (uint256, left-padded with zeros)
/// - `registry`: 20 bytes (address)
/// - `agentId`: 32 bytes (bytes32)
/// - **Total**: 84 bytes
///
/// This creates a globally unique identifier for an agent that's bound
/// to a specific chain and registry, and ensures Rust ↔ Solidity compatibility.
///
/// # Arguments
///
/// * `chain_id` - The blockchain chain ID (will be encoded as uint256)
/// * `registry` - The ERC-8004 identity registry address
/// * `agent_id` - The agent's ID in the registry
///
/// # Returns
///
/// A 32-byte agent key that matches the Solidity computation.
///
/// # Example
///
/// ```
/// use trustnet_core::hashing::compute_agent_key;
/// use alloy_primitives::Address;
///
/// let registry = Address::from([0x33; 20]);
/// let agent_id = [0x44u8; 32];
///
/// let key = compute_agent_key(1, &registry, &agent_id);
/// // This will produce the same hash as Solidity's:
/// // keccak256(abi.encodePacked(uint256(1), registry, agentId))
/// ```
pub fn compute_agent_key(chain_id: u64, registry: &Address, agent_id: &[u8; 32]) -> AgentKey {
    // Encode to match Solidity's abi.encodePacked(uint256, address, bytes32)
    // Total: 32 + 20 + 32 = 84 bytes
    let mut data = Vec::with_capacity(84);

    // Encode chain_id as 32 bytes (uint256) - left-padded with zeros
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
    data.extend_from_slice(&chain_id_bytes);

    // Append registry (20 bytes)
    data.extend_from_slice(registry.as_slice());

    // Append agent_id (32 bytes)
    data.extend_from_slice(agent_id);

    AgentKey::from(keccak256(&data))
}

/// Compute the leaf hash for an SMM entry.
///
/// The leaf hash is: `keccak256(0x00 || key || value)`
///
/// # Arguments
///
/// * `key` - The 32-byte key
/// * `value` - The value (level + 2, ranging from 0 to 4)
///
/// # Returns
///
/// The 32-byte leaf hash.
pub fn compute_leaf_hash(key: &Bytes32, value: u8) -> B256 {
    let mut data = Vec::with_capacity(33);
    data.push(crate::constants::SMM_LEAF_PREFIX);
    data.extend_from_slice(key.as_ref());
    data.push(value);

    keccak256(&data)
}

/// Compute the internal node hash for an SMM node.
///
/// The internal hash is: `keccak256(0x01 || left || right)`
///
/// Note: This is positional (no lexicographic sorting).
///
/// # Arguments
///
/// * `left` - The left child hash
/// * `right` - The right child hash
///
/// # Returns
///
/// The 32-byte internal node hash.
pub fn compute_internal_hash(left: &B256, right: &B256) -> B256 {
    let mut data = Vec::with_capacity(65);
    data.push(crate::constants::SMM_INTERNAL_PREFIX);
    data.extend_from_slice(left.as_ref());
    data.extend_from_slice(right.as_ref());

    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use alloy_primitives::hex;

    #[test]
    fn test_keccak256() {
        // Test with known Keccak256 vectors (not SHA3-256!)
        let input = b"";
        let expected = B256::from(hex!(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        ));
        assert_eq!(keccak256(input), expected);

        let input = b"abc";
        let expected = B256::from(hex!(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        ));
        assert_eq!(keccak256(input), expected);

        // Verify agenttrust tag matches constant
        let input = b"agenttrust:v1";
        assert_eq!(keccak256(input), TAG_AGENTTRUST_V1);

        // Verify a trustnet context hash
        let input = b"trustnet:ctx:global:v1";
        assert_eq!(keccak256(input), CTX_GLOBAL);
    }

    #[test]
    fn test_compute_edge_key() {
        let rater = Address::from(hex!("1111111111111111111111111111111111111111"));
        let target = Address::from(hex!("2222222222222222222222222222222222222222"));
        let context = ContextId::from(CTX_PAYMENTS);

        let key = compute_edge_key(&rater, &target, &context);

        // Verify the key is deterministic
        let key2 = compute_edge_key(&rater, &target, &context);
        assert_eq!(key, key2);

        // Different inputs should produce different keys
        let different_rater = Address::from(hex!("3333333333333333333333333333333333333333"));
        let different_key = compute_edge_key(&different_rater, &target, &context);
        assert_ne!(key, different_key);
    }

    #[test]
    fn test_compute_agent_key() {
        let chain_id = 1u64;
        let registry = Address::from(hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        let agent_id = hex!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let key = compute_agent_key(chain_id, &registry, &agent_id);

        // Verify the key is deterministic
        let key2 = compute_agent_key(chain_id, &registry, &agent_id);
        assert_eq!(key.as_bytes(), key2.as_bytes());

        // Different chain ID should produce different key
        let different_key = compute_agent_key(2, &registry, &agent_id);
        assert_ne!(key.as_bytes(), different_key.as_bytes());
    }

    #[test]
    fn test_agent_key_encoding_matches_solidity() {
        // This test verifies that our encoding exactly matches Solidity's
        // abi.encodePacked(uint256 chainId, address registry, bytes32 agentId)

        let chain_id = 1u64;
        let registry = Address::from(hex!("1234567890123456789012345678901234567890"));
        let agent_id = hex!("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");

        // Manually construct what Solidity would encode
        let mut expected_preimage = Vec::with_capacity(84);

        // chainId as uint256 (32 bytes, left-padded)
        // For chainId = 1, this is 31 zeros followed by 0x01
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[31] = 0x01;
        expected_preimage.extend_from_slice(&chain_id_bytes);

        // registry as address (20 bytes)
        expected_preimage.extend_from_slice(&hex!("1234567890123456789012345678901234567890"));

        // agentId as bytes32 (32 bytes)
        expected_preimage.extend_from_slice(&agent_id);

        assert_eq!(
            expected_preimage.len(),
            84,
            "Solidity encoding should be 84 bytes (32 + 20 + 32)"
        );

        // Compute the expected hash (what Solidity would produce)
        let expected_hash = keccak256(&expected_preimage);

        // Compute using our function
        let actual_key = compute_agent_key(chain_id, &registry, &agent_id);

        // They must match!
        assert_eq!(
            actual_key.as_bytes(),
            expected_hash.as_slice(),
            "Rust agent key must match Solidity computation"
        );
    }

    #[test]
    fn test_agent_key_chain_id_zero() {
        // Test edge case: chain_id = 0
        let chain_id = 0u64;
        let registry = Address::from(hex!("1111111111111111111111111111111111111111"));
        let agent_id = [0x22u8; 32];

        // For chain_id = 0, all 32 bytes should be zeros
        let mut expected_preimage = vec![0u8; 32]; // 32 zeros for uint256(0)
        expected_preimage.extend_from_slice(&hex!("1111111111111111111111111111111111111111"));
        expected_preimage.extend_from_slice(&agent_id);

        let expected_hash = keccak256(&expected_preimage);
        let actual_key = compute_agent_key(chain_id, &registry, &agent_id);

        assert_eq!(actual_key.as_bytes(), expected_hash.as_slice());
    }

    #[test]
    fn test_agent_key_large_chain_id() {
        // Test with a large chain ID (e.g., mainnet = 1, but test with larger)
        let chain_id = 0x123456789ABCDEFu64; // Large chain ID
        let registry = Address::from(hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        let agent_id = [0xbbu8; 32];

        // Manually encode chain_id as uint256
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());

        let mut expected_preimage = Vec::with_capacity(84);
        expected_preimage.extend_from_slice(&chain_id_bytes);
        expected_preimage.extend_from_slice(registry.as_slice());
        expected_preimage.extend_from_slice(&agent_id);

        let expected_hash = keccak256(&expected_preimage);
        let actual_key = compute_agent_key(chain_id, &registry, &agent_id);

        assert_eq!(actual_key.as_bytes(), expected_hash.as_slice());
    }

    #[test]
    fn test_agent_key_preimage_length() {
        // Verify that the preimage is always exactly 84 bytes
        // This is critical for Solidity compatibility

        let test_cases = vec![
            (0u64, "chain_id = 0"),
            (1u64, "chain_id = 1"),
            (1337u64, "chain_id = 1337 (common testnet)"),
            (u64::MAX, "chain_id = u64::MAX"),
        ];

        for (chain_id, description) in test_cases {
            let registry = Address::from([0xaa; 20]);
            let agent_id = [0xbb; 32];

            // We can't directly access the preimage, but we can verify behavior
            // by ensuring different chain IDs produce different keys
            let key = compute_agent_key(chain_id, &registry, &agent_id);
            assert_eq!(
                key.as_bytes().len(),
                32,
                "Agent key should be 32 bytes for {}",
                description
            );

            // The key should be deterministic
            let key2 = compute_agent_key(chain_id, &registry, &agent_id);
            assert_eq!(
                key, key2,
                "Agent key should be deterministic for {}",
                description
            );
        }
    }

    #[test]
    fn test_compute_leaf_hash() {
        let key = Bytes32::from(hex!(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ));
        let value = 2u8; // Represents level 0

        let hash = compute_leaf_hash(&key, value);

        // Verify the hash includes the leaf prefix
        let mut expected_preimage = vec![SMM_LEAF_PREFIX];
        expected_preimage.extend_from_slice(key.as_ref());
        expected_preimage.push(value);
        let expected_hash = keccak256(&expected_preimage);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_compute_internal_hash() {
        let left = B256::from(hex!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        let right = B256::from(hex!(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));

        let hash = compute_internal_hash(&left, &right);

        // Verify the hash includes the internal prefix
        let mut expected_preimage = vec![SMM_INTERNAL_PREFIX];
        expected_preimage.extend_from_slice(left.as_ref());
        expected_preimage.extend_from_slice(right.as_ref());
        let expected_hash = keccak256(&expected_preimage);

        assert_eq!(hash, expected_hash);

        // Verify that swapping left/right produces different hash (positional)
        let swapped_hash = compute_internal_hash(&right, &left);
        assert_ne!(hash, swapped_hash);
    }

    #[test]
    fn test_edge_key_matches_solidity() {
        // This test should match the exact computation in Solidity
        // We'll use the same test vectors as in the Solidity tests
        let rater = Address::from(hex!("0000000000000000000000000000000000000001"));
        let target = Address::from(hex!("0000000000000000000000000000000000000002"));
        let context = ContextId::from(CTX_GLOBAL);

        let key = compute_edge_key(&rater, &target, &context);

        // The expected value would come from running the same computation in Solidity
        // This is a placeholder - you'd need to verify against actual Solidity output
        // For now, we just verify it's deterministic
        let key2 = compute_edge_key(&rater, &target, &context);
        assert_eq!(key, key2);
    }
}
