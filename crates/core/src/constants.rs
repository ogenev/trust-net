//! Canonical constants for TrustNet.
//!
//! These constants MUST match the values in TrustNetContexts.sol exactly.

use alloy_primitives::{b256, B256};

/// Tag for ERC-8004 feedback that should be ingested by TrustNet.
/// Only feedback with tag2 == TAG_TRUSTNET_V1 will be processed.
/// keccak256("trustnet:v1")
pub const TAG_TRUSTNET_V1: B256 =
    b256!("3539b20dd2af81ad9c3c5953baeb60770eead262c1eee5a537a4b54c199e1215");

// Canonical context identifiers
// These MUST match TrustNetContexts.sol exactly

/// Global context - applies to all capabilities.
/// keccak256("trustnet:ctx:global:v1")
pub const CTX_GLOBAL: B256 =
    b256!("430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b");

/// Payments context - for payment-related operations.
/// keccak256("trustnet:ctx:payments:v1")
pub const CTX_PAYMENTS: B256 =
    b256!("195c31d552212fd148934033b94b89c00b603e2b73e757a2b7684b4cc9602147");

/// Code execution context - for code execution capabilities.
/// keccak256("trustnet:ctx:code-exec:v1")
pub const CTX_CODE_EXEC: B256 =
    b256!("5efe84ba1b51e4f09cf7666eca4d0685fcccf1ee1f5c051bfd1b40c537b4565b");

/// Writes context - for write/modification operations.
/// keccak256("trustnet:ctx:writes:v1")
pub const CTX_WRITES: B256 =
    b256!("a4d767d43a1aa6ce314b2c1df834966b812e18b0b99fcce9faf1591c0a6f2674");

/// DeFi execution context - for DeFi protocol interactions.
/// keccak256("trustnet:ctx:defi-exec:v1")
pub const CTX_DEFI_EXEC: B256 =
    b256!("3372ad16565f09e46bfdcd8668e8ddb764599c1e6088d92a088c17ecb464ad65");

// SMM (Sparse Merkle Map) constants

/// Prefix for SMM leaf nodes
pub const SMM_LEAF_PREFIX: u8 = 0x00;

/// Prefix for SMM internal nodes
pub const SMM_INTERNAL_PREFIX: u8 = 0x01;

/// Default value in SMM for non-membership (represents level 0)
pub const SMM_DEFAULT_VALUE: u8 = 2;

// Level constants

/// Minimum trust level
pub const MIN_LEVEL: i8 = -2;

/// Maximum trust level
pub const MAX_LEVEL: i8 = 2;

/// Neutral level (default)
pub const NEUTRAL_LEVEL: i8 = 0;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn test_tag_constant() {
        // Verify TAG_TRUSTNET_V1 matches keccak256("trustnet:v1")
        let result = keccak256(b"trustnet:v1");
        assert_eq!(result, TAG_TRUSTNET_V1);
    }

    #[test]
    fn test_context_constants() {
        // Verify each context constant matches its expected keccak256 hash
        // Note: These use "trustnet:ctx:" prefix to match Solidity TrustNetContexts.sol
        let test_cases = [
            ("trustnet:ctx:global:v1", CTX_GLOBAL),
            ("trustnet:ctx:payments:v1", CTX_PAYMENTS),
            ("trustnet:ctx:code-exec:v1", CTX_CODE_EXEC),
            ("trustnet:ctx:writes:v1", CTX_WRITES),
            ("trustnet:ctx:defi-exec:v1", CTX_DEFI_EXEC),
        ];

        for (input, expected) in test_cases {
            let result = keccak256(input.as_bytes());
            assert_eq!(result, expected, "Context constant mismatch for {}", input);
        }
    }

    #[test]
    fn test_level_bounds() {
        assert_eq!(MIN_LEVEL, -2);
        assert_eq!(MAX_LEVEL, 2);
        assert_eq!(NEUTRAL_LEVEL, 0);
    }

    #[test]
    fn test_smm_constants() {
        assert_eq!(SMM_LEAF_PREFIX, 0x00);
        assert_eq!(SMM_INTERNAL_PREFIX, 0x01);
        assert_eq!(SMM_DEFAULT_VALUE, 2); // Represents level 0
    }
}
