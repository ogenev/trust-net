//! Proof generation and verification for Sparse Merkle Maps.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// A Sparse Merkle Map proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmmProof {
    /// The key being proven.
    pub key: B256,

    /// The leaf value bytes (membership proofs only).
    ///
    /// For non-membership proofs this MUST be empty and the verifier treats the leaf hash as the
    /// empty leaf hash (bytes32(0)).
    #[serde(with = "serde_bytes")]
    pub leaf_value: Vec<u8>,

    /// Sibling hashes along the path from leaf to root.
    ///
    /// For a 256-bit key space, this contains exactly 256 siblings.
    pub siblings: Vec<B256>,

    /// Whether this is a membership proof (true) or non-membership proof (false).
    pub is_membership: bool,
}

impl SmmProof {
    /// Construct a new proof.
    pub fn new(key: B256, leaf_value: Vec<u8>, siblings: Vec<B256>, is_membership: bool) -> Self {
        Self {
            key,
            leaf_value,
            siblings,
            is_membership,
        }
    }

    /// Verify this proof against a root hash.
    pub fn verify(&self, root: B256) -> bool {
        if self.siblings.len() != 256 {
            return false;
        }

        if !self.is_membership && !self.leaf_value.is_empty() {
            // Prevent callers from accidentally trusting forged leaf_value for non-membership.
            return false;
        }

        self.compute_root() == root
    }

    /// Compute the root implied by this proof.
    pub fn compute_root(&self) -> B256 {
        use trustnet_core::hashing::{compute_internal_hash, compute_leaf_hash};

        let mut hash = if self.is_membership {
            compute_leaf_hash(&self.key, &self.leaf_value)
        } else {
            B256::ZERO
        };

        // Walk from depth 255..0.
        for depth in (0..256).rev() {
            let sibling = &self.siblings[depth];
            let bit = get_bit(&self.key, depth);
            hash = if bit == 0 {
                compute_internal_hash(&hash, sibling)
            } else {
                compute_internal_hash(sibling, &hash)
            };
        }

        hash
    }
}

fn get_bit(key: &B256, index: usize) -> u8 {
    let byte_index = index / 8;
    let bit_index = 7 - (index % 8);
    (key[byte_index] >> bit_index) & 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn test_reject_non_membership_with_leaf_value() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let proof = SmmProof::new(key, vec![1u8], vec![B256::ZERO; 256], false);
        assert!(!proof.verify(B256::ZERO));
    }
}
