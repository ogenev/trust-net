//! Proof generation and verification for Sparse Merkle Maps.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// A Sparse Merkle Map proof.
///
/// Proves that a key-value pair exists in the tree (membership proof)
/// or that a key maps to the default value (non-membership proof).
///
/// # Examples
///
/// ```
/// use trustnet_smm::{SmmBuilder, SmmProof};
/// use alloy_primitives::B256;
///
/// let mut builder = SmmBuilder::new();
/// let key = B256::from([0x01; 32]);
/// builder.insert(key, 2).unwrap();
/// let smm = builder.build();
///
/// // Generate proof
/// let proof = smm.prove(key).unwrap();
///
/// // Verify proof
/// assert!(proof.verify(smm.root()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmmProof {
    /// The key being proven.
    pub key: B256,

    /// The value at this key.
    /// - For membership proofs: the actual value stored
    /// - For non-membership proofs: 2 (default, representing level 0)
    pub value: u8,

    /// Sibling hashes along the path from leaf to root.
    ///
    /// siblings[i] is the sibling at depth i:
    /// - If key bit i is 0, siblings[i] is the right sibling
    /// - If key bit i is 1, siblings[i] is the left sibling
    ///
    /// For a 256-bit key space, this contains 256 siblings.
    pub siblings: Vec<B256>,

    /// Whether this is a membership proof (true) or non-membership proof (false).
    ///
    /// Membership: the key exists in the tree with the specified value
    /// Non-membership: the key doesn't exist, value is the default (2)
    pub is_membership: bool,
}

impl SmmProof {
    /// Create a new proof.
    pub fn new(key: B256, value: u8, siblings: Vec<B256>, is_membership: bool) -> Self {
        Self {
            key,
            value,
            siblings,
            is_membership,
        }
    }

    /// Verify this proof against a root hash.
    ///
    /// Returns `true` if the proof is valid, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use trustnet_smm::SmmBuilder;
    /// use alloy_primitives::B256;
    ///
    /// let mut builder = SmmBuilder::new();
    /// let key = B256::from([0x01; 32]);
    /// builder.insert(key, 2).unwrap();
    /// let smm = builder.build();
    ///
    /// let proof = smm.prove(key).unwrap();
    /// assert!(proof.verify(smm.root()));
    /// ```
    pub fn verify(&self, root: B256) -> bool {
        // Validate value is in range
        if self.value > 4 {
            return false;
        }

        // Validate siblings length
        if self.siblings.len() != 256 {
            return false;
        }

        // Non-membership proofs must have the default value (2)
        // Since compute_root() ignores the value field for non-membership proofs,
        // an attacker could forge a different value and still pass verification.
        // This would trick callers that trust proof.value() into accepting a forged trust level.
        if !self.is_membership && self.value != 2 {
            return false;
        }

        // Special case: empty tree (root is zero)
        // For empty tree, only non-membership proofs are valid (no leaves exist)
        // Membership proofs must be rejected to prevent forgery
        if root == B256::ZERO {
            let all_siblings_zero = self.siblings.iter().all(|s| *s == B256::ZERO);
            return all_siblings_zero && self.value == 2 && !self.is_membership;
        }

        // Compute the root hash by walking up the tree
        let computed_root = self.compute_root();
        computed_root == root
    }

    /// Compute the root hash from this proof.
    ///
    /// For a full 256-level Sparse Merkle Tree, this:
    /// 1. Starts with either a leaf hash (membership) or zero (non-membership)
    /// 2. Combines with all 256 siblings walking up the tree
    /// 3. Returns the final hash (which should equal the root)
    ///
    /// Special handling for empty subtrees: If both current hash and sibling are ZERO,
    /// the parent hash is also ZERO (no need to compute H(ZERO, ZERO)).
    pub fn compute_root(&self) -> B256 {
        use crate::node::Node;
        use trustnet_core::hashing::compute_internal_hash;

        // Start hash at depth 256:
        // - For membership proof: start with leaf hash
        // - For non-membership proof: start with ZERO (empty)
        let mut hash = if self.is_membership {
            Node::leaf(self.key, self.value).hash()
        } else {
            B256::ZERO
        };

        // Walk UP the tree from depth 256 to root, combining with siblings
        for depth in (0..256).rev() {
            let sibling = &self.siblings[depth];
            let bit = get_bit(&self.key, depth);

            // Special case: if both current hash and sibling are ZERO,
            // we're in an empty subtree, so parent hash is also ZERO
            if hash == B256::ZERO && *sibling == B256::ZERO {
                hash = B256::ZERO;
                continue;
            }

            // Combine current hash with sibling
            hash = if bit == 0 {
                // We are the left child at this depth
                compute_internal_hash(&hash, sibling)
            } else {
                // We are the right child at this depth
                compute_internal_hash(sibling, &hash)
            };
        }

        hash
    }

    /// Get the key this proof is for.
    pub fn key(&self) -> B256 {
        self.key
    }

    /// Get the value being proven.
    pub fn value(&self) -> u8 {
        self.value
    }

    /// Get the siblings.
    pub fn siblings(&self) -> &[B256] {
        &self.siblings
    }
}

/// Get the bit at the given index in the key.
///
/// Bits are numbered 0-255, with 0 being the MSB.
fn get_bit(key: &B256, index: usize) -> u8 {
    let byte_index = index / 8;
    let bit_index = 7 - (index % 8); // MSB first within each byte
    (key[byte_index] >> bit_index) & 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn test_get_bit() {
        let key = b256!("8000000000000000000000000000000000000000000000000000000000000000");
        // 0x80 = 10000000, so first bit is 1
        assert_eq!(get_bit(&key, 0), 1);
        assert_eq!(get_bit(&key, 1), 0);

        let key = b256!("4000000000000000000000000000000000000000000000000000000000000000");
        // 0x40 = 01000000, so first bit is 0, second is 1
        assert_eq!(get_bit(&key, 0), 0);
        assert_eq!(get_bit(&key, 1), 1);
    }

    #[test]
    fn test_proof_creation() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 2u8;
        let siblings = vec![B256::ZERO; 256];

        let proof = SmmProof::new(key, value, siblings, false);

        assert_eq!(proof.key(), key);
        assert_eq!(proof.value(), value);
        assert_eq!(proof.siblings().len(), 256);
    }

    #[test]
    fn test_proof_invalid_value() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 5u8; // Invalid
        let siblings = vec![B256::ZERO; 256];

        let proof = SmmProof::new(key, value, siblings, false);
        let root = B256::ZERO;

        // Should fail verification due to invalid value
        assert!(!proof.verify(root));
    }

    #[test]
    fn test_proof_invalid_siblings_length() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 2u8;
        let siblings = vec![B256::ZERO; 10]; // Wrong length

        let proof = SmmProof::new(key, value, siblings, false);
        let root = B256::ZERO;

        // Should fail verification due to wrong siblings length
        assert!(!proof.verify(root));
    }

    #[test]
    fn test_reject_forged_membership_proof_for_empty_tree() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 2u8; // Default value
        let siblings = vec![B256::ZERO; 256]; // All zeros

        // Create a forged membership proof
        let forged_proof = SmmProof::new(key, value, siblings, true); // is_membership=true!

        // Empty tree root
        let empty_root = B256::ZERO;

        // MUST reject this forged membership proof
        assert!(
            !forged_proof.verify(empty_root),
            "Empty tree must reject membership proofs to prevent forgery"
        );

        // But a valid non-membership proof should still work
        let valid_proof = SmmProof::new(key, value, vec![B256::ZERO; 256], false);
        assert!(
            valid_proof.verify(empty_root),
            "Empty tree should accept valid non-membership proofs"
        );
    }

    #[test]
    fn test_reject_forged_value_in_non_membership_proof() {
        use crate::SmmBuilder;

        // Attacker takes a valid non-membership proof
        // and tampers with the value field to forge a different trust level
        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key_absent = b256!("9999999999999999999999999999999999999999999999999999999999999999");

        // Build a tree with one key
        let mut builder = SmmBuilder::new();
        builder.insert(key1, 3).unwrap();
        let smm = builder.build();

        // Generate a legitimate non-membership proof for key_absent
        let valid_proof = smm.prove(key_absent).unwrap();
        assert!(!valid_proof.is_membership);
        assert_eq!(valid_proof.value(), 2); // Default value
        assert!(valid_proof.verify(smm.root()));

        // Attacker tampers with the value (e.g., claims trust level +2 instead of 0)
        let forged_proof = SmmProof::new(
            key_absent,
            4, // Forged value! (should be 2 for non-membership)
            valid_proof.siblings().to_vec(),
            false, // Still claims non-membership
        );

        // MUST reject this tampered proof
        assert!(
            !forged_proof.verify(smm.root()),
            "Non-membership proofs with forged values must be rejected"
        );

        // Original proof should still work
        assert!(
            valid_proof.verify(smm.root()),
            "Original non-membership proof should still be valid"
        );
    }
}
