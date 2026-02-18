//! Canonical constants for TrustNet.
//!
//! These constants MUST match the values in TrustNetContexts.sol exactly.

use alloy_primitives::{b256, B256};

/// Tag for ERC-8004 feedback that should be ingested by TrustNet.
/// Only feedback with tag2 == TAG_TRUSTNET_V1 will be processed.
/// keccak256("trustnet:v1")
pub const TAG_TRUSTNET_V1: B256 =
    b256!("3539b20dd2af81ad9c3c5953baeb60770eead262c1eee5a537a4b54c199e1215");

// Canonical context identifiers (v0.7 agent-collab registry)
// These MUST match TrustNetContexts.sol exactly.

/// Canonical messaging context.
/// keccak256("trustnet:ctx:agent-collab:messaging:v1")
pub const CTX_AGENT_COLLAB_MESSAGING: B256 =
    b256!("04b03219e64c6472e5872ec762574f95cad7503f96392e00dae2bbbeaddd8158");

/// Canonical files-read context.
/// keccak256("trustnet:ctx:agent-collab:files:read:v1")
pub const CTX_AGENT_COLLAB_FILES_READ: B256 =
    b256!("c1fec36e15bcd80ff1f0c7d817e26b6a558c5f027fb0e2af1fcef6755e6c04aa");

/// Canonical files-write context.
/// keccak256("trustnet:ctx:agent-collab:files:write:v1")
pub const CTX_AGENT_COLLAB_FILES_WRITE: B256 =
    b256!("129283efa53ecd8ee862e64bbe6ca301c1f52167c643b55aafa8a668874769cf");

/// Canonical code-exec context.
/// keccak256("trustnet:ctx:agent-collab:code-exec:v1")
pub const CTX_AGENT_COLLAB_CODE_EXEC: B256 =
    b256!("88329f80681e8980157f3ce652efd4fd18edf3c55202d5fb4f4da8a23e2d6971");

/// Canonical delegation context.
/// keccak256("trustnet:ctx:agent-collab:delegation:v1")
pub const CTX_AGENT_COLLAB_DELEGATION: B256 =
    b256!("c6664c53c5aa763dbc7a4925c548e6600ce8d337698eb2faed7c9d348c3055d2");

/// Canonical data-share context.
/// keccak256("trustnet:ctx:agent-collab:data-share:v1")
pub const CTX_AGENT_COLLAB_DATA_SHARE: B256 =
    b256!("c217daac2c1b96669c55300178ca750feaf0eceffc89d9878cd3a5518d3ad33c");

/// Canonical v0.7 context string: messaging.
pub const CTX_STR_AGENT_COLLAB_MESSAGING: &str = "trustnet:ctx:agent-collab:messaging:v1";
/// Canonical v0.7 context string: files read.
pub const CTX_STR_AGENT_COLLAB_FILES_READ: &str = "trustnet:ctx:agent-collab:files:read:v1";
/// Canonical v0.7 context string: files write.
pub const CTX_STR_AGENT_COLLAB_FILES_WRITE: &str = "trustnet:ctx:agent-collab:files:write:v1";
/// Canonical v0.7 context string: code execution.
pub const CTX_STR_AGENT_COLLAB_CODE_EXEC: &str = "trustnet:ctx:agent-collab:code-exec:v1";
/// Canonical v0.7 context string: delegation.
pub const CTX_STR_AGENT_COLLAB_DELEGATION: &str = "trustnet:ctx:agent-collab:delegation:v1";
/// Canonical v0.7 context string: data share.
pub const CTX_STR_AGENT_COLLAB_DATA_SHARE: &str = "trustnet:ctx:agent-collab:data-share:v1";

/// Ordered canonical v0.7 context registry used for `contextRegistryHash`.
pub const CANONICAL_CONTEXTS_V0_7: [(&str, B256); 6] = [
    (CTX_STR_AGENT_COLLAB_MESSAGING, CTX_AGENT_COLLAB_MESSAGING),
    (CTX_STR_AGENT_COLLAB_FILES_READ, CTX_AGENT_COLLAB_FILES_READ),
    (
        CTX_STR_AGENT_COLLAB_FILES_WRITE,
        CTX_AGENT_COLLAB_FILES_WRITE,
    ),
    (CTX_STR_AGENT_COLLAB_CODE_EXEC, CTX_AGENT_COLLAB_CODE_EXEC),
    (CTX_STR_AGENT_COLLAB_DELEGATION, CTX_AGENT_COLLAB_DELEGATION),
    (CTX_STR_AGENT_COLLAB_DATA_SHARE, CTX_AGENT_COLLAB_DATA_SHARE),
];

/// Resolve a canonical v0.7 context id from a context string.
pub fn context_id_from_string_v0_7(context: &str) -> Option<B256> {
    CANONICAL_CONTEXTS_V0_7
        .iter()
        .find_map(|(name, id)| (*name == context).then_some(*id))
}

/// Check whether a context string is canonical in v0.7.
pub fn is_canonical_context_string_v0_7(context: &str) -> bool {
    context_id_from_string_v0_7(context).is_some()
}

/// Return the v0.7 canonical context id for a supplied context id.
pub fn normalize_context_id_v0_7(context_id: &B256) -> Option<B256> {
    let id = *context_id;
    if id == CTX_AGENT_COLLAB_MESSAGING
        || id == CTX_AGENT_COLLAB_FILES_READ
        || id == CTX_AGENT_COLLAB_FILES_WRITE
        || id == CTX_AGENT_COLLAB_CODE_EXEC
        || id == CTX_AGENT_COLLAB_DELEGATION
        || id == CTX_AGENT_COLLAB_DATA_SHARE
    {
        return Some(id);
    }
    None
}

/// Whether a context id is accepted by v0.7 local-first defaults.
pub fn is_supported_context_id_v0_7(context_id: &B256) -> bool {
    normalize_context_id_v0_7(context_id).is_some()
}

/// Default TTL for a v0.7 context id (after alias normalization).
pub fn ttl_seconds_for_context_id_v0_7(context_id: &B256) -> Option<u64> {
    let normalized = normalize_context_id_v0_7(context_id)?;

    if normalized == CTX_AGENT_COLLAB_FILES_READ || normalized == CTX_AGENT_COLLAB_DATA_SHARE {
        return Some(30 * 24 * 60 * 60);
    }

    if normalized == CTX_AGENT_COLLAB_MESSAGING
        || normalized == CTX_AGENT_COLLAB_FILES_WRITE
        || normalized == CTX_AGENT_COLLAB_CODE_EXEC
        || normalized == CTX_AGENT_COLLAB_DELEGATION
    {
        return Some(7 * 24 * 60 * 60);
    }

    Some(0)
}

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
    fn test_v0_7_context_constants() {
        // Verify each canonical v0.7 context constant matches its expected keccak256 hash.
        let test_cases = [
            (
                "trustnet:ctx:agent-collab:messaging:v1",
                CTX_AGENT_COLLAB_MESSAGING,
            ),
            (
                "trustnet:ctx:agent-collab:files:read:v1",
                CTX_AGENT_COLLAB_FILES_READ,
            ),
            (
                "trustnet:ctx:agent-collab:files:write:v1",
                CTX_AGENT_COLLAB_FILES_WRITE,
            ),
            (
                "trustnet:ctx:agent-collab:code-exec:v1",
                CTX_AGENT_COLLAB_CODE_EXEC,
            ),
            (
                "trustnet:ctx:agent-collab:delegation:v1",
                CTX_AGENT_COLLAB_DELEGATION,
            ),
            (
                "trustnet:ctx:agent-collab:data-share:v1",
                CTX_AGENT_COLLAB_DATA_SHARE,
            ),
        ];

        for (input, expected) in test_cases {
            let result = keccak256(input.as_bytes());
            assert_eq!(result, expected, "Context constant mismatch for {}", input);
        }
    }

    #[test]
    fn test_context_string_lookup() {
        assert_eq!(
            context_id_from_string_v0_7(CTX_STR_AGENT_COLLAB_CODE_EXEC),
            Some(CTX_AGENT_COLLAB_CODE_EXEC)
        );
        assert!(is_canonical_context_string_v0_7(
            CTX_STR_AGENT_COLLAB_DATA_SHARE
        ));
        assert!(!is_canonical_context_string_v0_7(
            "trustnet:ctx:code-exec:v1"
        ));
        assert!(!is_canonical_context_string_v0_7(
            "trustnet:ctx:payments:v1"
        ));
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
