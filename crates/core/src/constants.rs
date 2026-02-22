//! Canonical constants for TrustNet.
//!
//! These constants MUST match the values in TrustNetContexts.sol exactly.

use alloy_primitives::{b256, B256};

/// Tag for ERC-8004 feedback that should be ingested by TrustNet.
/// Runtime ingestion must compare the literal `tag2` string (`"trustnet:v1"`).
/// This hash is exported for vectors/manifests: `keccak256("trustnet:v1")`.
pub const TAG_TRUSTNET_V1: B256 =
    b256!("3539b20dd2af81ad9c3c5953baeb60770eead262c1eee5a537a4b54c199e1215");

// Canonical context identifiers (TrustNet v1 registry)
// These MUST match TrustNetContexts.sol exactly.

/// Canonical global context.
/// keccak256("trustnet:ctx:global:v1")
pub const CTX_GLOBAL: B256 =
    b256!("430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b");

/// Canonical payments context.
/// keccak256("trustnet:ctx:payments:v1")
pub const CTX_PAYMENTS: B256 =
    b256!("195c31d552212fd148934033b94b89c00b603e2b73e757a2b7684b4cc9602147");

/// Canonical code-exec context.
/// keccak256("trustnet:ctx:code-exec:v1")
pub const CTX_CODE_EXEC: B256 =
    b256!("5efe84ba1b51e4f09cf7666eca4d0685fcccf1ee1f5c051bfd1b40c537b4565b");

/// Canonical writes context.
/// keccak256("trustnet:ctx:writes:v1")
pub const CTX_WRITES: B256 =
    b256!("a4d767d43a1aa6ce314b2c1df834966b812e18b0b99fcce9faf1591c0a6f2674");

/// Canonical defi-exec context.
/// keccak256("trustnet:ctx:defi-exec:v1")
pub const CTX_DEFI_EXEC: B256 =
    b256!("3372ad16565f09e46bfdcd8668e8ddb764599c1e6088d92a088c17ecb464ad65");

/// Canonical v1 context string: global.
pub const CTX_STR_GLOBAL: &str = "trustnet:ctx:global:v1";
/// Canonical v1 context string: payments.
pub const CTX_STR_PAYMENTS: &str = "trustnet:ctx:payments:v1";
/// Canonical v1 context string: code execution.
pub const CTX_STR_CODE_EXEC: &str = "trustnet:ctx:code-exec:v1";
/// Canonical v1 context string: writes.
pub const CTX_STR_WRITES: &str = "trustnet:ctx:writes:v1";
/// Canonical v1 context string: defi execution.
pub const CTX_STR_DEFI_EXEC: &str = "trustnet:ctx:defi-exec:v1";

/// Ordered canonical v1 context registry used for `contextRegistryHash`.
pub const CANONICAL_CONTEXTS_V1: [(&str, B256); 5] = [
    (CTX_STR_GLOBAL, CTX_GLOBAL),
    (CTX_STR_PAYMENTS, CTX_PAYMENTS),
    (CTX_STR_CODE_EXEC, CTX_CODE_EXEC),
    (CTX_STR_WRITES, CTX_WRITES),
    (CTX_STR_DEFI_EXEC, CTX_DEFI_EXEC),
];

/// Resolve a canonical v1 context id from a context string.
pub fn context_id_from_string_v1(context: &str) -> Option<B256> {
    CANONICAL_CONTEXTS_V1
        .iter()
        .find_map(|(name, id)| (*name == context).then_some(*id))
}

/// Check whether a context string is canonical in v1.
pub fn is_canonical_context_string_v1(context: &str) -> bool {
    context_id_from_string_v1(context).is_some()
}

/// Return the v1 canonical context id for a supplied context id.
pub fn normalize_context_id_v1(context_id: &B256) -> Option<B256> {
    let id = *context_id;
    if id == CTX_GLOBAL
        || id == CTX_PAYMENTS
        || id == CTX_CODE_EXEC
        || id == CTX_WRITES
        || id == CTX_DEFI_EXEC
    {
        return Some(id);
    }
    None
}

/// Whether a context id is accepted by TrustNet v1 defaults.
pub fn is_supported_context_id_v1(context_id: &B256) -> bool {
    normalize_context_id_v1(context_id).is_some()
}

/// Default TTL for a v1 context id.
///
/// Whitepaper v1 does not define per-context edge expiry, so pruning is disabled by default.
pub fn ttl_seconds_for_context_id_v1(context_id: &B256) -> Option<u64> {
    normalize_context_id_v1(context_id)?;
    Some(0)
}

// SMM (Sparse Merkle Map) constants

/// Prefix for SMM leaf nodes
pub const SMM_LEAF_PREFIX: u8 = 0x00;

/// Prefix for SMM internal nodes
pub const SMM_INTERNAL_PREFIX: u8 = 0x01;

/// Prefix for SMM empty-subtree base hash.
///
/// Whitepaper v1.1 defines:
/// - `H_empty = keccak256(0x02)`
pub const SMM_EMPTY_PREFIX: u8 = 0x02;

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
    fn test_v1_context_constants() {
        // Verify each canonical v1 context constant matches its expected keccak256 hash.
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
    fn test_context_string_lookup() {
        assert_eq!(
            context_id_from_string_v1(CTX_STR_CODE_EXEC),
            Some(CTX_CODE_EXEC)
        );
        assert!(is_canonical_context_string_v1(CTX_STR_PAYMENTS));
        assert!(!is_canonical_context_string_v1(
            "trustnet:ctx:agent-collab:code-exec:v1"
        ));
        assert!(!is_canonical_context_string_v1("trustnet:ctx:messaging:v1"));
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
        assert_eq!(SMM_EMPTY_PREFIX, 0x02);
        assert_eq!(SMM_DEFAULT_VALUE, 2); // Represents level 0
    }
}
